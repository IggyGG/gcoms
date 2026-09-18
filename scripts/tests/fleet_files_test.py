import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(SCRIPTS))
from fleet_files import analyze, Campaign
from fleet_files_remote import Host, IPS

class EvidenceTests(unittest.TestCase):
    def transfer(self):
        return [{'event':'transfer','transfer':'a','elapsed':0,'size':4,'sha256':'abcd','expected_receivers':[1]},
                {'event':'accepted','transfer':'a','client':1,'elapsed':1}]

    def test_complete_without_export_fails(self):
        events=self.transfer()+[{'event':'progress','transfer':'a','client':1,'state':'complete','elapsed':2}]
        report=analyze({'phase':'canary'},events)
        self.assertEqual(report['verdict'],'fail')
        self.assertIn('expected export missing',[e['error'] for e in report['failures']])

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

    def test_missing_or_short_runtime_never_passes(self):
        for duration in (0,1,14399):
            report=analyze({'phase':'campaign'},[{'event':'window_end','name':'mixed','duration':duration,'elapsed':duration}])
            self.assertEqual(report['verdict'],'incomplete')
            self.assertFalse(report['phase_passed'])

    def test_missing_ack_fails(self):
        report=analyze({'phase':'campaign'},[{'event':'chat_sent','message':'ping','elapsed':1}])
        self.assertEqual(report['verdict'],'fail')

    def test_canary_is_not_fleet_qualification(self):
        events=self.transfer()+[{'event':'export_verified','transfer':'a','client':1,'elapsed':3,'verified':True,'size':4,'sha256':'abcd'}]
        events[0]['sender']=2
        events += [{'event':'cleanup','host':i,'passed':True} for i in range(8)]
        events += [{'event':'client_ready','client':i} for i in (2,1)]
        report=analyze({'phase':'canary'},events)
        self.assertEqual(report['verdict'],'incomplete'); self.assertTrue(report['phase_passed'])

    def test_case_labels_cannot_replace_directed_pair_evidence(self):
        events=[{'event':'case','name':name,'result':'pass'} for name in ('coverage','boundaries')]
        events += [{'event':'cleanup','host':i,'passed':True} for i in range(8)]
        events += [{'event':'client_ready','client':i} for i in range(16)]
        report=analyze({'phase':'coverage'},events)
        self.assertFalse(report['phase_passed'])
        self.assertEqual(report['verified_directed_host_pairs'],0)

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
