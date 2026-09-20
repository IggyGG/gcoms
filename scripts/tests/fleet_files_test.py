import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

SCRIPTS=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(SCRIPTS))
from fleet_files import analyze, Campaign, qualified_transport
from fleet_files_remote import Host, IPS

class EvidenceTests(unittest.TestCase):
    def transport(self):
        return {'protocol':'gchat', 'profile_id':22, 'bootstrap_version':2,
                'routing_ready':True, 'ready_entries':2, 'usable_terminal_routes':1,
                'interactive_subscriptions':2, 'bulk_subscriptions':2}

    def test_ipc_or_entry_readiness_cannot_substitute_for_usable_protocol(self):
        status = self.transport()
        self.assertTrue(qualified_transport(status))
        for key, value in [('profile_id',10), ('bootstrap_version',1), ('routing_ready',False),
                           ('ready_entries',0), ('usable_terminal_routes',0), ('bulk_subscriptions',0)]:
            self.assertFalse(qualified_transport(dict(status, **{key:value})))
    def transfer(self):
        return [{'event':'transfer','transfer':'a','elapsed':0,'size':4,'sha256':'abcd','expected_receivers':[1]},
                {'event':'accepted','transfer':'a','client':1,'elapsed':1}]

    def test_complete_without_export_fails(self):
        events=self.transfer()+[{'event':'progress','transfer':'a','client':1,'state':'complete','elapsed':2}]
        report=analyze({'phase':'canary'},events)
        self.assertEqual(report['verdict'],'fail')
        self.assertIn('expected export missing',[e['error'] for e in report['failures']])

    def test_scope_reports_observed_clients_and_distinguishes_offers_from_exports(self):
        manifest={'phase':'canary','clients':16,'large_sizes':[1024**3]}
        events=self.transfer()+[{'event':'client_ready','client':i} for i in (0,8)]
        report=analyze(manifest,events)
        self.assertEqual(report['observed_clients'],2)
        self.assertIn('2 Linux clients observed',report['scope'])
        self.assertEqual(report['largest_offered_file_bytes'],4)
        self.assertEqual(report['largest_verified_file_bytes'],0)
        events.append({'event':'export_verified','transfer':'a','client':1,'elapsed':3,
                       'verified':True,'size':4,'sha256':'abcd'})
        self.assertEqual(analyze(manifest,events)['largest_verified_file_bytes'],4)

    def test_wrong_hash_or_size_fails(self):
        for size,digest in ((3,'abcd'),(4,'other')):
            events=self.transfer()+[{'event':'export_verified','transfer':'a','client':1,'elapsed':3,'verified':True,'size':size,'sha256':digest}]
            self.assertEqual(analyze({'phase':'canary'},events)['verdict'],'fail')

    def test_export_requires_recorded_acceptance_and_reports_measured_goodput(self):
        exported={'event':'export_verified','transfer':'a','client':1,'elapsed':3,'verified':True,'size':4,'sha256':'abcd'}
        report=analyze({'phase':'canary'},[self.transfer()[0],exported])
        self.assertEqual(report['verdict'],'fail')
        self.assertEqual(report['file_metrics_by_size'],{})
        report=analyze({'phase':'canary'},self.transfer()+[exported])
        self.assertEqual(report['file_metrics_by_size']['4'],{
            'exports':1,'completion_p50_seconds':2,'completion_p95_seconds':2,
            'goodput_p50_bytes_per_second':2})

    def test_cleanup_requires_every_distinct_host_and_uses_recovery_observations(self):
        cleanup=[{'event':'cleanup','host':0,'passed':True} for _ in range(8)]
        self.assertFalse(analyze({'phase':'canary'},cleanup)['cleanup_complete'])
        cleanup=[{'event':'cleanup','host':i,'passed':True} for i in range(8)]
        cleanup.append({'event':'cleanup','host':3,'passed':False})
        self.assertFalse(analyze({'phase':'canary'},cleanup)['cleanup_complete'])
        cleanup.append({'event':'cleanup','host':3,'passed':True})
        self.assertTrue(analyze({'phase':'canary'},cleanup)['cleanup_complete'])

    def test_cancel_must_be_explicit(self):
        events=self.transfer()
        events[0]['expected_receivers']=[]
        self.assertEqual(analyze({'phase':'canary'},events)['verdict'],'fail')
        events.append({'event':'cancelled','transfer':'a','client':1,'elapsed':2})
        self.assertEqual(analyze({'phase':'canary'},events)['verdict'],'incomplete')

    def test_removed_isolation_does_not_excuse_changed_production(self):
        events=[dict(event='cleanup',host=i,passed=i!=3,errors=[],
            namespace_removed=True,veth_removed=True,rules_removed=True,volume_unmounted=True)
            for i in range(8)]
        report=analyze({'phase':'canary'},events)
        self.assertTrue(report['isolated_resources_removed'])
        self.assertFalse(report['cleanup_complete'])
        self.assertFalse(report['phase_passed'])
        events[0]['namespace_removed']=False
        self.assertFalse(analyze({'phase':'canary'},events)['isolated_resources_removed'])

    def test_missing_or_short_runtime_never_passes(self):
        for duration in (0,1,14399):
            report=analyze({'phase':'campaign'},[{'event':'window_end','name':'mixed','duration':duration,'elapsed':duration}])
            self.assertEqual(report['verdict'],'incomplete')
            self.assertFalse(report['phase_passed'])

    def test_missing_ack_fails(self):
        report=analyze({'phase':'campaign'},[{'event':'chat_sent','message':'ping','elapsed':1}])
        self.assertEqual(report['verdict'],'fail')

    def test_canary_is_not_fleet_qualification(self):
        events=self.transfer()+[{'event':'export_verified','transfer':'a','client':1,'elapsed':3,'verified':True,'size':65536,'sha256':'abcd'}]
        events[0]['size']=65536
        events[0]['sender']=2
        events += [{'event':'cleanup','host':i,'passed':True} for i in range(8)]
        events += [{'event':'client_ready','client':i,'transport':self.transport()} for i in (2,1)]
        self.assertFalse(analyze({'phase':'canary'},events)['phase_passed'])
        events += [{'event':'canary_reopen','transfer':'a','client':1,'elapsed':4,'verified':True,
                    'size':65536,'sha256':'abcd','same_instance':True}]
        report=analyze({'phase':'canary'},events)
        self.assertEqual(report['verdict'],'incomplete'); self.assertTrue(report['phase_passed'])
        for event in events:
            event.pop('transport', None)
        self.assertFalse(analyze({'phase':'canary'}, events)['phase_passed'])

    def test_case_labels_cannot_replace_directed_pair_evidence(self):
        events=[{'event':'case','name':name,'result':'pass'} for name in ('coverage','boundaries')]
        events += [{'event':'cleanup','host':i,'passed':True} for i in range(8)]
        events += [{'event':'client_ready','client':i} for i in range(16)]
        report=analyze({'phase':'coverage'},events)
        self.assertFalse(report['phase_passed'])
        self.assertEqual(report['verified_directed_host_pairs'],0)

    def test_fault_requires_partial_progress_before_verified_export(self):
        transfer=self.transfer()
        transfer[0]['label']='pause_resume'
        exported={'event':'export_verified','transfer':'a','client':1,'elapsed':3,
                  'verified':True,'size':4,'sha256':'abcd'}
        partial={'event':'fault_precondition','name':'pause_resume','transfer':'a',
                 'client':1,'elapsed':2,'state':'downloading','verified_bytes':2,'size':4}
        for change,expected in (({},True),({'verified_bytes':0},False),
                                ({'verified_bytes':4},False),({'elapsed':4},False),
                                ({'state':'complete'},False),({'size':5},False)):
            report=analyze({'phase':'campaign'},transfer+[dict(partial,**change),exported])
            self.assertEqual(report['fault_evidence']['pause_resume'],expected)

    def test_sources_advertised_are_not_proof_of_multisource_completion(self):
        transfer=self.transfer()
        transfer[0]['label']='complementary'
        first={'event':'source_contribution','transfer':'a','client':1,'source':4,
               'verified_before':0,'verified_after':2,'exclusive_source':True,'elapsed':2}
        second=dict(first,source=8,verified_before=2,verified_after=4,elapsed=4)
        exported={'event':'export_verified','transfer':'a','client':1,'elapsed':3,
                  'verified':True,'size':4,'sha256':'abcd','sources':2}
        for parts,expected in (([],False),([first],False),([first,second],True),
                               ([first,dict(second,source=4)],False),
                               ([first,dict(second,verified_before=1)],False),
                               ([first,dict(second,exclusive_source=False)],False)):
            report=analyze({'phase':'campaign'},transfer+[exported]+parts)
            self.assertEqual(report['fault_evidence']['multisource_late_join'],expected)

    def test_recovery_requires_timed_progress_and_matching_export(self):
        transfer=self.transfer(); transfer[0]['label']='pause_resume'
        partial={'event':'fault_precondition','name':'pause_resume','transfer':'a',
                 'client':1,'elapsed':2,'state':'downloading','verified_bytes':1,'size':4}
        resumed={'event':'recovery_progress','name':'pause_resume','transfer':'a','client':1,
                 'elapsed':10,'started_elapsed':3,'seconds':7,'verified_before':1,
                 'verified_after':2,'state':'downloading'}
        exported={'event':'export_verified','transfer':'a','client':1,'elapsed':11,
                  'verified':True,'size':4,'sha256':'abcd'}
        for change,expected in (({},True),({'seconds':301},False),({'seconds':0},False),
                                ({'client':2},False),({'verified_after':1},False),
                                ({'verified_before':3},False),({'verified_after':5},False),
                                ({'started_elapsed':1},False),
                                ({'verified_before':4,'verified_after':4,'state':'complete'},True)):
            with self.subTest(change=change):
                result=analyze({'phase':'campaign'},transfer+[partial,dict(resumed,**change),exported])
                self.assertEqual(result['recovery_progress_evidence']['pause_resume'],expected)
        for missing in (partial,exported):
            events=transfer+[e for e in (partial,resumed,exported) if e is not missing]
            self.assertFalse(analyze({'phase':'campaign'},events)['recovery_progress_evidence']['pause_resume'])

    def test_generic_partial_progress_cannot_replace_specialized_source_evidence(self):
        for name in ('missing_source','multisource_late_join','multisource_simultaneous'):
            transfer=self.transfer()
            transfer[0]['label']=name
            partial={'event':'fault_precondition','name':name,'transfer':'a','client':1,
                     'elapsed':2,'state':'downloading','verified_bytes':2,'size':4}
            exported={'event':'export_verified','transfer':'a','client':1,'elapsed':3,
                      'verified':True,'size':4,'sha256':'abcd'}
            report=analyze({'phase':'campaign'},transfer+[partial,exported])
            self.assertFalse(report['fault_evidence'][name])

    def test_simultaneous_sources_require_verified_contributors(self):
        transfer=self.transfer(); transfer[0]['label']='simultaneous'
        export={'event':'export_verified','transfer':'a','client':1,'elapsed':3,
                'verified':True,'size':4,'sha256':'abcd'}
        event={'event':'simultaneous_sources','transfer':'a','client':1,'elapsed':4,
               'both_enabled_before_acceptance':True,'verified_sources':2}
        for changed, expected in (({},True),({'verified_sources':1},False),
                                   ({'both_enabled_before_acceptance':False},False),({'elapsed':2},False)):
            self.assertEqual(analyze({'phase':'campaign'},transfer+[export,dict(event,**changed)])
                             ['fault_evidence']['multisource_simultaneous'],expected)

    def test_one_gib_deadline_is_an_export_gate(self):
        transfer=self.transfer(); transfer[0]['size']=1024**3
        for elapsed,expected in ((14401,False),(14402,True)):
            export={'event':'export_verified','transfer':'a','client':1,'elapsed':elapsed,
                    'verified':True,'size':1024**3,'sha256':'abcd'}
            errors=analyze({'phase':'campaign'},transfer+[export])['failures']
            self.assertEqual(any(e['error']=='1 GiB file exceeded four hours' for e in errors),expected)

class ScenarioTests(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory()
        self.campaign=Campaign(Path(self.folder.name),{'run_id':'ff-test','phase':'campaign'})
        self.campaign.channels['fleet']={'id':'channel'}

    def tearDown(self):
        self.campaign.jobs.shutdown()
        self.campaign.chat_jobs.shutdown()
        self.folder.cleanup()

    def test_monitor_stop_is_distinct_from_a_readiness_deadline(self):
        c=self.campaign
        with self.assertRaisesRegex(RuntimeError,'readiness: deadline exceeded'):
            c.until(lambda:False,0,'readiness')
        def monitor_stopped():
            c.stop.set()
            return False
        with self.assertRaisesRegex(RuntimeError,'readiness: campaign stopped'):
            c.until(monitor_stopped,120,'readiness')

    def test_monitor_stop_is_distinct_from_a_transfer_deadline(self):
        c=self.campaign
        with self.assertRaisesRegex(RuntimeError,'did not complete by deadline'):
            c.finish_transfer({'id':'test'},0,0)
        c.stop.set()
        with self.assertRaisesRegex(RuntimeError,'transfer test: campaign stopped'):
            c.finish_transfer({'id':'test'},0,float('inf'))

    def test_admission_waits_for_real_slot_before_acceptance(self):
        c=self.campaign
        active=[{'id':'a','state':'downloading'},{'id':'b','state':'waiting_for_peers'}]
        calls=[]
        def files(client,action='list',**values):
            calls.append(action)
            if action=='list': return {'files':[dict(f) for f in active]}
            self.assertEqual(action,'accept')
            self.assertEqual(sum(f['state']=='downloading' for f in active),1)
        def wait(_): active[1]['state']='complete'
        with patch.object(c,'files',side_effect=files), patch.object(c.stop,'wait',side_effect=wait):
            c.activate({'id':'new'},3)
        self.assertEqual(calls,['list','list','accept'])
        self.assertEqual([e['event'] for e in c.events],['admission','accepted'])

    def test_missing_source_stops_seed_before_acceptance_and_restores_on_failure(self):
        c=self.campaign; calls=[]; t={'id':'file'}
        with patch.object(c,'prepare_transfer',return_value=t), \
             patch.object(c,'offer',side_effect=lambda *a:calls.append('offer')), \
             patch.object(c,'accept',side_effect=lambda *a:calls.append('accept')), \
             patch.object(c,'remote',side_effect=lambda h,a,**v:calls.append(v.get('kind',a))), \
             patch.object(c,'until',side_effect=RuntimeError('missing waiting state')):
            with self.assertRaisesRegex(RuntimeError,'missing waiting state'): c.missing_source()
        self.assertEqual(calls,['offer','stop_client','accept','client'])

    def test_already_complete_transfer_cannot_supply_fault_precondition(self):
        c=self.campaign
        t={'id':'file','size':256*1024*1024}
        def until(predicate,*args,**kwargs):
            self.assertIsNone(predicate())
            raise RuntimeError('partial progress missing')
        with patch.object(c,'prepare_transfer',return_value=t),patch.object(c,'accept'), \
             patch.object(c,'info',return_value={'state':'complete','verified_bytes':str(t['size'])}), \
             patch.object(c,'until',side_effect=until):
            with self.assertRaisesRegex(RuntimeError,'partial progress missing'):
                c.active_transfer(0,8,'pause_resume')
        self.assertFalse(any(e['event']=='fault_precondition' for e in c.events))

    def test_recovery_progress_includes_reopen_time_and_has_separate_capacity_budget(self):
        c=self.campaign; c.start=1000; clock=[1120.]
        t={'id':'file','size':256*1024*1024}
        before={'state':'downloading','verified_bytes':'262144'}
        after=dict(before,verified_bytes='524288')
        def until(predicate,timeout,label,**kwargs):
            self.assertEqual(timeout,180)
            self.assertEqual(kwargs['deadline'],1300)
            clock[0]+=2
            return predicate()
        with patch('fleet_files.time.monotonic',side_effect=lambda:clock[0]), \
             patch.object(c,'info',side_effect=[before,after]),patch.object(c,'until',side_effect=until), \
             patch.object(c,'finish_transfer') as finish:
            c.finish_recovery(t,9,'receiver_restart',started=1000)
        finish.assert_called_once_with(t,9,4600)
        event=c.events[-1]
        self.assertEqual(event['seconds'],122)
        self.assertEqual(event['started_elapsed'],0)
        self.assertEqual(event['verified_after'],524288)

    def test_recovery_cannot_use_late_or_regressed_progress(self):
        for observed,after,message in ((1301,'524288','deadline exceeded'),
                                       (1002,'0','lost verified pieces')):
            c=self.campaign; clock=[1000.]
            def until(predicate,*args,**kwargs):
                clock[0]=observed
                return predicate()
            with self.subTest(message=message), \
                 patch('fleet_files.time.monotonic',side_effect=lambda:clock[0]), \
                 patch.object(c,'info',side_effect=[{'state':'downloading','verified_bytes':'262144'},
                                                   {'state':'downloading','verified_bytes':after}]), \
                 patch.object(c,'until',side_effect=until),patch.object(c,'finish_transfer') as finish:
                with self.assertRaisesRegex(RuntimeError,message):
                    c.finish_recovery({'id':'file','size':256*1024*1024},8,'pause_resume',started=1000)
            finish.assert_not_called()
        self.assertFalse(any(e['event']=='recovery_progress' for e in c.events))

    def test_recovery_does_not_extend_the_progress_deadline_while_waiting(self):
        c=self.campaign; clock=[1000.]
        def wait(seconds): clock[0]+=seconds
        with patch('fleet_files.time.monotonic',side_effect=lambda:clock[0]), \
             patch.object(c.stop,'wait',side_effect=wait), \
             patch.object(c,'info',return_value={'state':'waiting_for_peers','verified_bytes':'262144'}), \
             patch.object(c,'finish_transfer') as finish:
            with self.assertRaisesRegex(RuntimeError,'recovery progress: deadline exceeded'):
                c.finish_recovery({'id':'file','size':256*1024*1024},8,'pause_resume',started=1000)
        self.assertEqual(clock[0],1300)
        finish.assert_not_called()

    def resume_scenario(self, name, delays, fails=False):
        # Run the real scenario, admission, RPC wrappers, polling and recovery.
        # Only the SSH boundary, clock and final capacity transfer are replaced.
        c=self.campaign; c.start=1000; clock=[1000.]; calls=[]
        client=8 if name=='pause_resume' else 13
        started=1010. if name=='pause_resume' else 1000.
        transfer={'id':'file','size':256*1024*1024}
        state={'admitting':False,'resumed':False,'progress_reads':0}
        lock=Mock()
        def acquire(timeout):
            calls.append(('lock',clock[0],timeout))
            state['admitting']=True
            clock[0]+=delays.get('lock',0)
            return True
        lock.acquire.side_effect=acquire
        c.admission_locks[client]=lock
        c.nodes=[{'base':'/var/tmp','root':'/var/tmp/fixture'} for _ in range(8)]
        def ssh(host,argv,payload=None,timeout=1000):
            request=json.loads(payload)['payload']['request']['request']
            self.assertNotIn('deadline',request)
            action=request['action']; stage=None
            if action=='configure' and request['quota_bytes']==str(8*1024**3): stage='restore'
            elif action=='resume': stage='resume'
            elif action=='list' and state['admitting'] and not state['resumed']: stage='slot'
            elif action=='list' and state['resumed']: stage='progress'
            calls.append((stage or action,clock[0],timeout))
            clock[0]+=delays.get(stage,0)
            if action=='prepare':
                return json.dumps({'ok':True,'value':{'ok':False,'error':'quota exceeded'}})
            if action=='resume': state['resumed']=True
            info={'id':'file','state':'paused','verified_bytes':'262144'}
            if state['resumed']:
                info['state']='downloading'
                if action=='list': state['progress_reads']+=1
                if state['progress_reads']>=2: info['verified_bytes']='524288'
            files=[info]
            if stage=='slot' and delays.get('occupied'):
                files.extend({'id':str(i),'state':'downloading'} for i in range(2))
            return json.dumps({'ok':True,'value':{'ok':True,'value':{'snapshot':{'files':files}}}})
        def wait(seconds): clock[0]+=seconds
        with patch('fleet_files.time.monotonic',side_effect=lambda:clock[0]), \
             patch.object(c.stop,'wait',side_effect=wait),patch.object(c,'active_transfer',return_value=transfer), \
             patch.object(c,'ssh',side_effect=ssh),patch.object(c,'finish_transfer') as finish:
            if fails:
                with self.assertRaisesRegex(RuntimeError,'deadline'):
                    getattr(c,name)()
                finish.assert_not_called()
                self.assertFalse(any(e['event']=='recovery_progress' for e in c.events))
            else:
                getattr(c,name)()
                finish.assert_called_once_with(transfer,client,started+3600)
                event=next(e for e in c.events if e['event']=='recovery_progress')
                self.assertEqual(event['started_elapsed'],started-c.start)
                self.assertEqual(event['seconds'],clock[0]-started)
                self.assertEqual(event['verified_after'],524288)
        return calls,clock[0],lock

    def test_resume_scenarios_include_restore_admission_and_rpc_time(self):
        for name in ('pause_resume','quota'):
            with self.subTest(name=name):
                self.campaign.events.clear()
                calls,_,lock=self.resume_scenario(name,{'restore':35,'lock':20,'slot':25,'resume':40,'progress':2})
                started=1010 if name=='pause_resume' else 1000
                for stage,when,timeout in calls:
                    if stage in ('restore','lock','slot','resume','progress'):
                        self.assertEqual(timeout,started+300-when,(stage,calls))
                lock.release.assert_called_once()

    def test_resume_scenarios_reject_late_activation_and_progress_responses(self):
        for name in ('pause_resume','quota'):
            for stage in ('lock','slot','resume','progress'):
                with self.subTest(name=name,stage=stage):
                    self.campaign.events.clear()
                    calls,_,lock=self.resume_scenario(name,{stage:301},fails=True)
                    self.assertIn(stage,[row[0] for row in calls])
                    lock.release.assert_called_once()

    def test_quota_restoration_must_finish_before_resume_deadline(self):
        calls,_,lock=self.resume_scenario('quota',{'restore':301},fails=True)
        self.assertNotIn('resume',[row[0] for row in calls])
        lock.acquire.assert_not_called()

    def test_resume_scenarios_cannot_reset_deadline_waiting_for_admission(self):
        for name in ('pause_resume','quota'):
            with self.subTest(name=name):
                self.campaign.events.clear()
                calls,finished,lock=self.resume_scenario(name,{'occupied':True},fails=True)
                self.assertEqual(finished,1310 if name=='pause_resume' else 1300)
                self.assertNotIn('resume',[row[0] for row in calls])
                lock.release.assert_called_once()

    def test_resume_scenarios_share_one_deadline_across_short_actions(self):
        for name in ('pause_resume','quota'):
            with self.subTest(name=name):
                self.campaign.events.clear()
                calls,finished,_=self.resume_scenario(name,{'lock':100,'slot':100,'resume':101},fails=True)
                self.assertEqual(finished,1311 if name=='pause_resume' else 1301)
                self.assertEqual([timeout for stage,_,timeout in calls if stage in ('lock','slot','resume')],
                                 [300,200,100])

    def test_resume_scenarios_accept_progress_observed_at_exactly_300_seconds(self):
        for name in ('pause_resume','quota'):
            with self.subTest(name=name):
                self.campaign.events.clear()
                self.resume_scenario(name,{'lock':100,'slot':100,'resume':98,'progress':1})
                self.assertEqual(self.campaign.events[-1]['seconds'],300)

    def test_receiver_reopen_readiness_uses_the_remaining_recovery_budget(self):
        for ready_delay in (20,61):
            with self.subTest(ready_delay=ready_delay):
                c=self.campaign; c.events.clear(); c.start=1000; clock=[1000.]; timeouts=[]
                c.nodes=[{'base':'/var/tmp','root':'/var/tmp/fixture'} for _ in range(8)]
                t={'id':'file','size':256*1024*1024}
                before={'state':'downloading','verified_bytes':'262144'}
                after=dict(before,verified_bytes='524288')
                def ssh(host,argv,payload=None,timeout=1000):
                    request=json.loads(payload); action=request['action']; timeouts.append(timeout)
                    self.assertNotIn('deadline',request)
                    clock[0]+={'fault':190,'client':10,'probe':40,'traffic':ready_delay}[action]
                    if action=='probe': value={'ok':True,'value':{'ready':True}}
                    elif action=='traffic':
                        value={'file_diagnostics':{'1':{'latest':{'unix_seconds':clock[0],
                            'protocol':{'transport':EvidenceTests().transport()}}}}}
                    else: value=True
                    return json.dumps({'ok':True,'value':value})
                with patch('fleet_files.time.monotonic',side_effect=lambda:clock[0]), \
                     patch('fleet_files.time.time',side_effect=lambda:clock[0]), \
                     patch.object(c,'active_transfer',return_value=t),patch.object(c,'ssh',side_effect=ssh), \
                     patch.object(c,'info',side_effect=[before,before,before,after]), \
                     patch.object(c,'finish_transfer') as finish:
                    if ready_delay==20:
                        c.receiver_restart()
                        finish.assert_called_once_with(t,9,4600)
                        self.assertEqual(c.events[-1]['seconds'],260)
                    else:
                        with self.assertRaisesRegex(RuntimeError,'readiness: deadline exceeded'):
                            c.receiver_restart()
                        finish.assert_not_called()
                        self.assertFalse(any(e['event']=='recovery_progress' for e in c.events))
                self.assertEqual(timeouts,[300,110,100,60])

    def test_late_join_precedes_seeding_and_complementary_sources_never_overlap(self):
        c=self.campaign; states={4:'complete',8:'complete'}; seed_stopped=False
        t={'id':'file','size':4*1024*1024}
        def remote(host,action,**values):
            nonlocal seed_stopped
            if host==0: seed_stopped=action=='fault'
            if action=='cache_fault':
                client=host*2; states[client]='paused'
                parity=0 if values['mode']=='even' else 1
                return {'pieces':{f'{n}.piece':'hash' for n in range(parity,16,2)}}
        def activate(transfer,client,action):
            self.assertTrue(seed_stopped)
            self.assertEqual(states[8 if client==4 else 4],'paused')
            states[client]='downloading'
        def accept(transfer,client):
            if client==12:
                self.assertTrue(seed_stopped)
                self.assertEqual(states,{4:'paused',8:'paused'})
        def info(client,ident):
            return {'state':states.get(client,'downloading'),
                    'verified_bytes':str(2*1024*1024 if client==12 else 0)}
        def finish(transfer,client,deadline):
            if client==12:
                self.assertEqual(states,{4:'paused',8:'downloading'})
                self.assertEqual([e['source'] for e in c.events if e['event']=='source_contribution'],[4])
        def files(client,action,**values):
            self.assertEqual(action,'pause'); states[client]='paused'
        with patch.object(c,'channel',return_value='channel'),patch.object(c,'prepare_transfer',return_value=t), \
             patch.object(c,'accept',side_effect=accept),patch.object(c,'finish_transfer',side_effect=finish), \
             patch.object(c,'remote',side_effect=remote),patch.object(c,'request',return_value=True), \
             patch.object(c,'info',side_effect=info),patch.object(c,'files',side_effect=files), \
             patch.object(c,'activate',side_effect=activate),patch.object(c,'invitation',return_value='invite'), \
             patch.object(c,'submit'),patch.object(c,'wait_transport'):
            c.multisource()
        self.assertFalse(seed_stopped)
        self.assertEqual([e['source'] for e in c.events if e['event']=='source_contribution'],[4,8])

class DeploymentTests(unittest.TestCase):
    def host(self): return Host({'run_id':'ff-test','host':0,'base':'/var/tmp'})

    def test_diagnostic_counters_include_restarts_without_counting_samples_twice(self):
        with tempfile.TemporaryDirectory() as folder:
            host=self.host(); host.root=Path(folder); host.data=host.root/'data'; host.data.mkdir()
            (host.root/'owner.json').write_text(json.dumps({'run_id':host.id,'host':host.index}))
            samples=[dict(event='file_diagnostics',pid=pid,retries=retries,
                buffered_bytes=12,pending_pulls=1,pending_actions=0)
                for pid,retries in ((10,1),(10,3),(10,3),(20,2))]
            (host.data/'client0.log').write_text(''.join(json.dumps(x)+'\n' for x in samples))
            stats=host.traffic()['file_diagnostics']['0']
            self.assertEqual(stats['samples'],4)
            self.assertEqual(stats['counters']['retries'],5)

    def test_selection_rejects_external_paths_and_units(self):
        for bad in ('../live','ff-../live','ghost-relay'):
            with self.assertRaises(ValueError): Host({'run_id':bad,'host':0,'base':'/var/tmp'})
        with self.assertRaises(ValueError): Host({'run_id':'ff-test','host':0,'base':'/etc'})
        with self.assertRaises(ValueError): self.host().unit('ghost-relay')

    def test_firewall_changes_are_narrow_and_reversible(self):
        host=self.host()
        for table, args in host.rules():
            self.assertNotIn('-F',args); self.assertNotIn('-P',args)
            self.assertNotIn('4433',args); self.assertNotIn('19443',args)
            if args[0]=='-I': self.assertTrue(host.chain in args or host.inside in args)
            else: self.assertEqual(args[1],host.chain)
        inbound=[args for table,args in host.rules() if 'DNAT' in args]
        self.assertEqual(len(inbound),9)
        self.assertEqual({args[args.index('-s')+1] for args in inbound},set(IPS)|{host.inside})
        self.assertTrue(all(args[args.index('-p')+1]=='tcp' for args in inbound))

    def test_collection_failure_does_not_skip_cleanup(self):
        with tempfile.TemporaryDirectory() as folder:
            campaign=Campaign(Path(folder),{'run_id':'ff-test','phase':'canary'})
            campaign.nodes=[{'root':'/var/tmp/gcoms-fleet/ff-test','before':{'production':'unchanged'}} for _ in IPS]
            calls=[]
            def remote(host, action):
                calls.append((host,action))
                self.assertEqual(action,'cleanup')
                return {'errors':[], 'production':'unchanged',
                        'namespace_removed':True, 'veth_removed':True,
                        'rules_removed':True, 'volume_unmounted':True}
            try:
                with patch('fleet_files.subprocess.run',side_effect=OSError('collection unavailable')), patch.object(campaign,'remote',side_effect=remote):
                    campaign.cleanup()
                self.assertEqual(calls,[(i,'cleanup') for i in range(8)])
                self.assertEqual(len([e for e in campaign.events if e['event']=='collection_error']),8)
                self.assertTrue(all(e['passed'] for e in campaign.events if e['event']=='cleanup'))
            finally:
                campaign.jobs.shutdown()
                campaign.chat_jobs.shutdown()

if __name__=='__main__': unittest.main()
