"""Controller regressions from the real-daemon startup/reopen attempts."""
import importlib.util
import json
import base64
import copy
import concurrent.futures
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("gchat_turnover", Path(__file__).resolve().parents[1] / "gchat-turnover.py")
turnover = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(turnover)


@unittest.skipUnless(os.name == "posix", "Linux namespace controller")
class ControllerTests(unittest.TestCase):
    def test_pending_evidence_distinguishes_missing_recipient_from_missing_ack(self):
        accepted=concurrent.futures.Future();accepted.set_result(True)
        waiting=concurrent.futures.Future()
        failed=concurrent.futures.Future();failed.set_exception(RuntimeError('private error'))
        base={'index':1,'sender':0,'members':[0,4,8],'token':'private message',
            'channel':'private channel','started':20,'submission':accepted}
        records=[dict(base,seen={0:{},4:{}},sender_delivery='pending'),
            dict(base,seen={0:{},4:{},8:{}},sender_delivery='pending'),
            dict(base,seen={},submission=waiting),dict(base,seen={},submission=failed)]
        summary=turnover.incomplete_load_commands(records,30)
        self.assertEqual(summary['pending_commands'],4)
        self.assertEqual(summary['commands'][0]['missing_clients'],[8])
        self.assertEqual(summary['commands'][1]['missing_clients'],[])
        self.assertEqual(summary['commands'][1]['sender_delivery'],'pending')
        self.assertEqual([row['submission'] for row in summary['commands']],
                         ['accepted','accepted','pending','failed'])
        self.assertTrue(all(row['age_seconds']==10 for row in summary['commands']))
        self.assertNotIn('private',json.dumps(summary))
        bounded=turnover.incomplete_load_commands(records*17,30)
        self.assertEqual(bounded['pending_commands'],68)
        self.assertEqual(len(bounded['commands']),64)

    def test_restart_readiness_waits_for_bind_and_keeps_absolute_deadline(self):
        now=[10.0];calls=[]
        process=mock.Mock();process.poll.return_value=None
        bundle=base64.urlsafe_b64encode(turnover.bootstrap_bytes([self.introduction(1)])).decode()
        def control(relay,command,deadline):
            calls.append((relay,command,deadline,now[0]))
            if len(calls)<3:raise ConnectionRefusedError('not bound yet')
            return {'routing_bundle_b64':bundle}
        with mock.patch.object(turnover.time,'monotonic',side_effect=lambda:now[0]), \
                mock.patch.object(turnover.time,'sleep',side_effect=lambda seconds:now.__setitem__(0,now[0]+seconds)):
            ready=turnover.wait_restarted_relay(process,0,40,control)
        self.assertAlmostEqual(ready,10.2)
        self.assertEqual([row[:3] for row in calls],[(0,'routing_bootstrap',40)]*3)
        self.assertGreater(calls[-1][3],calls[0][3])

    def test_restart_readiness_does_not_hide_exit_bad_receipt_or_wedge(self):
        process=mock.Mock();process.poll.return_value=1
        control=mock.Mock()
        with self.assertRaisesRegex(RuntimeError,'exited before readiness'):
            turnover.wait_restarted_relay(process,0,turnover.time.monotonic()+30,control)
        control.assert_not_called()
        process.poll.return_value=None
        control.return_value={'routing_bundle_b64':base64.urlsafe_b64encode(b'bad').decode()}
        with self.assertRaisesRegex(ValueError,'invalid bounded'):
            turnover.wait_restarted_relay(process,0,turnover.time.monotonic()+30,control)
        self.assertEqual(control.call_count,1)
        control.reset_mock();control.side_effect=ConnectionRefusedError('not bound')
        now=[0.0]
        with mock.patch.object(turnover.time,'monotonic',side_effect=lambda:now[0]), \
                mock.patch.object(turnover.time,'sleep',side_effect=lambda seconds:now.__setitem__(0,now[0]+seconds)):
            with self.assertRaisesRegex(TimeoutError,'within 30 seconds'):
                turnover.wait_restarted_relay(process,0,30,control)
        self.assertEqual(now[0],30)
        self.assertTrue(all(call.args[2]==30 for call in control.call_args_list))

    def test_control_deadline_includes_partial_response_bytes(self):
        now=[0.0];stream=mock.MagicMock()
        stream.__enter__.return_value=stream
        def receive(_):
            now[0]+=1
            return b' '
        stream.recv.side_effect=receive
        with mock.patch.object(turnover.time,'monotonic',side_effect=lambda:now[0]), \
                mock.patch.object(turnover.socket,'create_connection',return_value=stream):
            with self.assertRaisesRegex(TimeoutError,'relay control deadline'):
                turnover.bounded_control(0,'routing_bootstrap',3)
        self.assertEqual(stream.recv.call_count,3)
        self.assertEqual([call.args[0] for call in stream.settimeout.call_args_list],[3,3,2,1])

    def test_restart_records_real_downtime_without_changing_delivery_deadline(self):
        now=[10.0];old=mock.Mock();old.poll.return_value=None;new=mock.Mock()
        self.worker.children=[('relay0-configured',old)];self.worker.rpc_deadline=1800
        def stop(process):
            self.assertIs(process,old);now[0]+=2
        def spawn(*args):now[0]+=1;return new
        def ready(process,relay,deadline):
            self.assertIs(process,new);self.assertEqual(deadline,43)
            now[0]+=4;return now[0]
        with mock.patch.object(turnover.time,'monotonic',side_effect=lambda:now[0]), \
                mock.patch.object(self.worker,'stop',side_effect=stop), \
                mock.patch.object(self.worker,'relay',side_effect=spawn), \
                mock.patch.object(turnover,'wait_restarted_relay',side_effect=ready):
            receipt=self.worker.restart_load_relay(0)
        self.assertEqual(receipt['stop_and_spawn_seconds'],3)
        self.assertEqual(receipt['control_ready_seconds'],4)
        self.assertEqual(receipt['observed_downtime_seconds'],7)
        self.assertTrue(receipt['ready'])
        self.assertEqual(self.worker.rpc_deadline,1800)

    def test_directory_sampling_skips_only_the_known_pending_restart(self):
        bundle=base64.urlsafe_b64encode(turnover.bootstrap_bytes([self.introduction(1)])).decode()
        with mock.patch.object(self.worker,'status',return_value=None), \
                mock.patch.object(self.worker,'control',return_value={'routing_bundle_b64':bundle}) as control:
            self.worker.sample(restarting=(0,))
        self.assertEqual([call.args[0] for call in control.call_args_list],list(range(1,6)))
        row=self.worker.events[-1]
        self.assertEqual(row['relays'][0],{'relay':0,'restart_pending':True})
        self.worker.directory_sample=None
        with mock.patch.object(self.worker,'status',return_value=None), \
                mock.patch.object(self.worker,'control',side_effect=ConnectionRefusedError('unexpected relay failure')):
            with self.assertRaises(ConnectionRefusedError):self.worker.sample()

    def test_campaign_observes_commands_while_relay_readiness_is_pending(self):
        class Observed(Exception):pass
        now=[0.0];entered=threading.Event();release=threading.Event();observed=[];pending_samples=[]
        worker=self.worker
        worker.spec['config'].update(load_topology='fleet-four-channels',load_seconds=2,file_bytes=5235248)
        process=mock.Mock();process.poll.return_value=None
        worker.children=[(f'client{i}',process) for i in range(64)]
        groups=[dict(index=0,channel='channel',members=list(range(64)))]
        def history(client,channel,token):
            if not entered.is_set():return []
            observed.append(client)
            return [dict(id=token,mine=client==0,delivery='delivered')]
        def restart(relay):
            self.assertEqual(relay,0);entered.set()
            if not release.wait(5):raise TimeoutError('test did not release relay readiness')
            return {'ready':True}
        def sample(restarting=()):
            if restarting:
                self.assertTrue(entered.wait(5))
                pending_samples.append(now[0])
                if len(pending_samples)==1:return
                try:
                    self.assertFalse(release.is_set())
                    self.assertEqual(restarting,(0,))
                    self.assertEqual(set(observed),set(range(64)))
                    self.assertTrue(any(row['event']=='load_command_delivered' for row in worker.events))
                    raise Observed
                finally:release.set()
        with mock.patch.object(turnover.time,'monotonic',side_effect=lambda:now[0]), \
                mock.patch.object(turnover.time,'sleep',side_effect=lambda seconds:now.__setitem__(0,now[0]+seconds)), \
                mock.patch.object(worker,'start_client'),mock.patch.object(worker,'request',return_value=True), \
                mock.patch.object(worker,'readiness',return_value=True),mock.patch.object(worker,'files'), \
                mock.patch.object(worker,'prepare_load_channels',return_value=groups), \
                mock.patch.object(worker,'start_file',return_value='original-file'), \
                mock.patch.object(worker,'submit'),mock.patch.object(worker,'history',side_effect=history), \
                mock.patch.object(worker,'restart_load_relay',side_effect=restart), \
                mock.patch.object(worker,'sample',side_effect=sample):
            with self.assertRaises(Observed):worker.relay_load()
        self.assertGreater(pending_samples[1],pending_samples[0])
        self.assertAlmostEqual(worker.rpc_deadline,12.8+2+120)

    def test_parallel_setup_bounds_all_64_clients_and_preserves_results(self):
        barrier=threading.Barrier(4);lock=threading.Lock();active=0;peak=0;seen=[]
        def prepare(client):
            nonlocal active,peak
            with lock:active+=1;peak=max(peak,active);seen.append(client)
            try:
                if client<4:barrier.wait(timeout=5)
                return client*2
            finally:
                with lock:active-=1
        result=turnover.parallel_setup(prepare,range(64))
        self.assertEqual(peak,4)
        self.assertEqual(sorted(seen),list(range(64)))
        self.assertEqual(result,[i*2 for i in range(64)])
        with self.assertRaisesRegex(RuntimeError,'prepare failed'):
            turnover.parallel_setup(lambda _:(_ for _ in ()).throw(RuntimeError('prepare failed')),range(4))

    def test_failed_join_retains_member_and_owner_transport_without_invitation(self):
        self.worker.spec['config']['load_topology']='fleet-four-channels'
        self.worker.rpc_deadline=turnover.time.monotonic()+60
        with mock.patch.object(turnover,'load_channel_members',return_value=[[0,1,2]]), \
                mock.patch.object(self.worker,'submit',return_value={'conversation':'channel'}), \
                mock.patch.object(self.worker,'remote_invitation',return_value='private-invitation') as invitation, \
                mock.patch.object(self.worker,'join_invitation',side_effect=RuntimeError('owner timeout')) as join, \
                mock.patch.object(self.worker,'status',side_effect=lambda i:{'routing_ready':i==0}):
            with self.assertRaisesRegex(RuntimeError,'owner timeout'):
                self.worker.prepare_load_channels(self.worker.rpc_deadline)
        failure=next(row for row in self.worker.events if row['event']=='load_member_join_failed')
        self.assertEqual((failure['client'],failure['channel_index']),(1,0))
        self.assertTrue(failure['owner_transport']['routing_ready'])
        self.assertFalse(failure['member_transport']['routing_ready'])
        self.assertGreaterEqual(failure['seconds'],0)
        self.assertNotIn('private-invitation',json.dumps(failure))
        invitation.assert_called_once()
        join.assert_called_once_with(1,'private-invitation','participant1')

    def test_shared_owner_enrollment_is_serial_round_robin_for_all_63_members(self):
        self.worker.spec['config']['load_topology']='fleet-four-channels'
        self.worker.rpc_deadline=turnover.time.monotonic()+60
        owner_thread=threading.get_ident();joined={i:[] for i in range(4)};created=[];order=[]
        def create(client,text):
            self.assertEqual(client,0);index=len(created);created.append(text)
            return {'conversation':f'channel{index}'}
        def invitation(channel):
            self.assertEqual(threading.get_ident(),owner_thread)
            self.assertEqual(channel,f'channel{len(order)%4}')
            return channel
        def join(client,code,nickname):
            index=int(code[-1])
            self.assertEqual(threading.get_ident(),owner_thread)
            joined[index].append(client);order.append(client)
            self.assertEqual(nickname,f'participant{client}')
            return {'conversation':code}
        with mock.patch.object(self.worker,'submit',side_effect=create), \
                mock.patch.object(self.worker,'remote_invitation',side_effect=invitation), \
                mock.patch.object(self.worker,'join_invitation',side_effect=join):
            groups=self.worker.prepare_load_channels(self.worker.rpc_deadline)
        self.assertEqual(len(created),4)
        self.assertEqual([g['members'] for g in groups],turnover.load_channel_members())
        self.assertEqual([joined[i] for i in range(4)],[g[1:] for g in turnover.load_channel_members()])
        self.assertEqual(order,list(range(1,64)))
        events=[row for row in self.worker.events if row['event']=='load_member_joined']
        self.assertEqual(sorted(row['client'] for row in events),list(range(1,64)))
        # Every admitted member retains one complete event record.
        self.assertEqual(len((self.root/'events.jsonl').read_text().splitlines()),63)

    @staticmethod
    def introduction(identity, expiry=3600, epoch=1):
        return bytes([identity])*83+bytes([epoch])*64+expiry.to_bytes(8,'big')

    def test_routing_renewal_preserves_identity_and_hourly_authority(self):
        old=[self.introduction(1),self.introduction(2)]
        fresh=[self.introduction(1,7200,2),self.introduction(2,7200,2)]
        self.assertEqual(turnover.renewed_records(old,old,3599),old)
        with self.assertRaises(TimeoutError):turnover.renewed_records(old,old,3600)
        self.assertEqual(turnover.renewed_records(old,fresh,3601),fresh)
        for offset in (0,19,51):
            changed=bytearray(fresh[0]);changed[offset]^=1
            with self.subTest(offset=offset),self.assertRaisesRegex(ValueError,'identity'):
                turnover.renewed_records(old,[bytes(changed),fresh[1]],3601)
        with self.assertRaisesRegex(ValueError,'within one epoch'):
            turnover.renewed_records(old,[self.introduction(1,3600,2),old[1]],3599)
        with self.assertRaisesRegex(ValueError,'lifetime or rollback'):
            turnover.renewed_records(fresh,old,3599)
        with self.assertRaisesRegex(ValueError,'lifetime or rollback'):
            turnover.renewed_records(old,fresh,3599)

    def test_routing_bundles_are_bounded_and_unambiguous(self):
        raw=turnover.bootstrap_bytes([self.introduction(1)])
        self.assertEqual(turnover.bootstrap_records(raw),[self.introduction(1)])
        for invalid in (raw[:-1],raw+b'x',b'',b'GCRB\x02\x00',
                        b'GCRB\x02\x09'+raw[6:]*9):
            with self.subTest(length=len(invalid)),self.assertRaises(ValueError):
                turnover.bootstrap_records(invalid)
        with self.assertRaisesRegex(ValueError,'duplicate'):
            turnover.bootstrap_bytes([self.introduction(1)]*2)

    def test_routing_refresh_replaces_every_bundle_without_changing_client_routes(self):
        old=[self.introduction(i) for i in range(1,7)]
        fresh=[self.introduction(i,7200,2) for i in range(1,7)]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'bootstrap').write_bytes(turnover.bootstrap_bytes(old))
            for client in range(2):
                (root/f'c{client}').mkdir()
                (root/f'c{client}/bootstrap').write_bytes(turnover.bootstrap_bytes(old[:client+1]))
            def control(i,command):
                self.assertEqual(command,'routing_bootstrap')
                return {'routing_bundle_b64':base64.urlsafe_b64encode(turnover.bootstrap_bytes([fresh[i]])).decode().rstrip('=')}
            renewal=turnover.FixtureRoutingRenewal(root,2,0,control,os.getuid(),os.getgid())
            renewal.refresh(now=3601)
            for path,expected in [(root/'bootstrap',fresh),(root/'c0/bootstrap',fresh[:1]),
                                  (root/'c1/bootstrap',fresh[:2])]:
                self.assertEqual(turnover.bootstrap_records(path.read_bytes()),expected)
                self.assertEqual(path.stat().st_mode&0o777,0o600)
            self.assertEqual(renewal.receipt['changed_bundles'],3)
            renewal.refresh(now=3602)
            self.assertEqual(renewal.receipt['changed_bundles'],3)
            renewal.close();self.assertTrue(renewal.receipt['stopped'])
            renewal.error='producer failed'
            with self.assertRaisesRegex(RuntimeError,'producer failed'):renewal.check()

    def test_failed_atomic_refresh_retains_the_complete_original(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'bootstrap';path.write_bytes(b'old')
            with mock.patch.object(turnover.os,'replace',side_effect=OSError('disk failure')):
                with self.assertRaises(OSError):turnover.replace_private(path,b'new',os.getuid(),os.getgid())
            self.assertEqual(path.read_bytes(),b'old')
            self.assertEqual(list(path.parent.iterdir()),[path])

    def test_routing_worker_surfaces_rejected_authority_and_stops(self):
        renewal=turnover.FixtureRoutingRenewal.__new__(turnover.FixtureRoutingRenewal)
        renewal.stop=threading.Event();renewal.thread=None;renewal.error=None;renewal.receipt={}
        renewal.refresh=mock.Mock(side_effect=[None,ValueError('changed identity')])
        with mock.patch.object(renewal.stop,'wait',return_value=False):
            renewal.start();renewal.thread.join(timeout=2)
        self.assertFalse(renewal.thread.is_alive())
        with self.assertRaisesRegex(RuntimeError,'changed identity'):renewal.close()
        self.assertTrue(renewal.receipt['stopped'])

    def test_load_receipt_counts_only_campaign_events_across_rotations(self):
        with tempfile.TemporaryDirectory() as directory:
            paths=[Path(directory)/name for name in ('metrics.jsonl','metrics.jsonl.1')]
            rows=[dict(ts=999,event='gc2_forward_refused'),dict(ts=1000,event='gc2_forward_accepted'),
                  dict(ts=1500,event='gchat_push_accepted',kind='data'),
                  dict(ts=1700,event='gchat_push_accepted',kind='duplicate'),
                  dict(ts=1900,event='gchat_queue_refused',reason='queue_full'),
                  dict(ts=2000,event='gc2_forward_refused'),dict(ts=2001,event='gc2_forward_refused')]
            for path,subset in zip(paths,(rows[:3],rows[3:])):
                path.write_text(''.join(json.dumps(row)+'\n' for row in subset))
            self.assertEqual(turnover.relay_load_counts(paths,1,2),(2,1,2))

    def test_load_retains_rotated_metrics_and_final_contribution_after_cleanup(self):
        journey=turnover.Journey.__new__(turnover.Journey)
        journey.spec={'config':{'mode':'relay-load'}};journey.result={'evidence':{}}
        with tempfile.TemporaryDirectory() as directory:
            journey.original_root=Path(directory)
            expected=['r0/metrics.jsonl','r0/metrics.jsonl.1','c0/metrics.jsonl',
                      'c53/metrics.jsonl.1','c2/contribution.json']
            for name in expected+['c2/card']:
                path=journey.original_root/name;path.parent.mkdir(exist_ok=True);path.write_bytes(b'evidence')
            with mock.patch.object(turnover.base.Worker,'execute',return_value=0) as execute:
                self.assertEqual(journey.execute(),0)
            execute.assert_called_once()
            receipt=json.loads((journey.original_root/'worker.json').read_text())
            self.assertEqual(set(receipt['evidence']),set(expected))
            self.assertTrue(all(len(digest)==64 for digest in receipt['evidence'].values()))

    def test_receiver_observation_precedes_collection_of_unrelated_slow_work(self):
        release=threading.Event(); held=threading.Event()
        item=dict(channel='channel',token='command',started=10)
        def history(client,channel,token):
            if client==1:
                held.set()
                if not release.wait(5): raise TimeoutError('held receiver')
            return [dict(id='exact',mine=False)]
        with mock.patch.object(turnover.time,'monotonic',return_value=12) as clock, \
                turnover.concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            slow=pool.submit(turnover.observe_load_recipient,item,1,history)
            try:
                self.assertTrue(held.wait(5))
                fast=pool.submit(turnover.observe_load_recipient,item,2,history)
                self.assertEqual(fast.result(timeout=5)[1]['seconds'],2)
                clock.return_value=100
                self.assertEqual(fast.result()[1]['seconds'],2)
            finally:
                release.set()
            self.assertEqual(slow.result(timeout=5)[1]['seconds'],90)
        with self.assertRaisesRegex(RuntimeError,'duplicated'):
            turnover.observe_load_recipient(item,2,lambda *args:[dict(id='a'),dict(id='b')])

    def test_fleet_load_keeps_every_client_and_the_original_recipient_rate(self):
        groups=turnover.load_channel_members()
        self.assertEqual([len(g) for g in groups],[17,17,17,16])
        self.assertEqual(sorted(i for g in groups for i in g[1:]),list(range(1,64)))
        self.assertTrue(all(g[0]==0 for g in groups))
        self.assertEqual(sum(len(g)-1 for g in groups),63)
        self.assertEqual(turnover.load_channel_members('single-channel'),[list(range(64))])
        with self.assertRaises(ValueError):turnover.load_channel_members('unknown')

    def test_load_delivery_needs_every_member_correct_authorship_and_all_acks(self):
        for members in turnover.load_channel_members()+turnover.load_channel_members('single-channel'):
            sender=members[-1]
            seen={i:dict(id='exact',mine=i==sender,seconds=1) for i in members}
            sent=[dict(id='exact',mine=True,delivery='delivered')]
            self.assertEqual(turnover.validated_load_delivery(seen,members,sender,sent),sent[0])
            for i in members:
                changed=copy.deepcopy(seen);del changed[i]
                self.assertIsNone(turnover.validated_load_delivery(changed,members,sender,sent))
                for mutation in [dict(id='different'),dict(mine=i!=sender)]:
                    changed=copy.deepcopy(seen);changed[i].update(mutation)
                    with self.assertRaisesRegex(RuntimeError,'identity or authorship'):
                        turnover.validated_load_delivery(changed,members,sender,sent)
            self.assertIsNone(turnover.validated_load_delivery(seen,members,sender,[{**sent[0],'delivery':'accepted'}]))
            with self.assertRaisesRegex(RuntimeError,'duplicated'):
                turnover.validated_load_delivery(seen,members,sender,sent+sent)
            with self.assertRaises(ValueError):turnover.validated_load_delivery(seen,members,-1,sent)
            with self.assertRaises(ValueError):turnover.validated_load_delivery(seen,members+members[:1],sender,sent)

    def test_load_capacity_matches_node_bounds_and_keeps_other_modes_unchanged(self):
        self.assertEqual(turnover.load_relay_capacity({'mode':'smoke'}), [])
        self.assertEqual(turnover.load_relay_capacity({'mode':'relay-load',
            'relay_circuits':2048, 'relay_connections':4096}),
            ['--relay-circuits','2048','--relay-connections','4096'])
        for circuits, connections in [(0,4096),(4097,8192),(2048,4095),(1,8193),(True,4096)]:
            with self.subTest(circuits=circuits, connections=connections), self.assertRaises(ValueError):
                turnover.load_relay_capacity({'mode':'relay-load',
                    'relay_circuits':circuits, 'relay_connections':connections})

    def test_load_capacity_rejects_invalid_cli_overrides_before_fixture_creation(self):
        for extra in (['--mode','smoke','--load-relay-circuits','2048'],
                      ['--mode','relay-load','--fixture-host','/unused','--load-relay-circuits','4097'],
                      ['--mode','relay-load','--fixture-host','/unused','--load-relay-connections','4095']):
            with self.subTest(extra=extra), mock.patch.object(os,'geteuid',return_value=1000), \
                    mock.patch.object(sys,'argv',['gchat-turnover','--build','/unused','--out','/unused',*extra]), \
                    mock.patch.object(sys,'stderr'):
                with self.assertRaises(SystemExit) as caught: turnover.main()
                self.assertEqual(caught.exception.code,2)

    def test_group_delivery_requires_every_recipient_exact_identity_and_sender_ack(self):
        rows = [[dict(id='original', mine=i == 3, delivery='delivered')] for i in range(10)]
        self.assertEqual(turnover.validated_group_delivery(rows, 3)['id'], 'original')
        for i in range(10):
            changed = copy.deepcopy(rows); changed[i] = []
            self.assertIsNone(turnover.validated_group_delivery(changed, 3))
            for mutation in [dict(id='other'), dict(mine=i != 3)]:
                changed = copy.deepcopy(rows); changed[i][0].update(mutation)
                with self.assertRaisesRegex(RuntimeError, 'identity or authorship'):
                    turnover.validated_group_delivery(changed, 3)
            changed = copy.deepcopy(rows); changed[i].append(changed[i][0].copy())
            with self.assertRaisesRegex(RuntimeError, 'duplicate'):
                turnover.validated_group_delivery(changed, 3)
        rows[3][0]['delivery'] = 'accepted'
        self.assertIsNone(turnover.validated_group_delivery(rows, 3))
        with self.assertRaises(ValueError):
            turnover.validated_group_delivery(rows[:9], 3)

    def test_entry_replacement_requires_both_actual_transport_ends_and_new_ready_drivers(self):
        old=[{'id':1},{'id':2}]
        ends=[dict(id=i,phase='transport_ended',unix_ms=101) for i in (1,2)]
        fresh=[dict(id=i,phase='class_muxes_ready',unix_ms=102) for i in (3,4)]
        self.assertIsNone(turnover.validated_replacements(old, fresh, 100))
        self.assertIsNone(turnover.validated_replacements(old, ends+fresh[:1], 100))
        self.assertEqual(turnover.validated_replacements(old, ends+fresh, 100),
                         {'ended':ends,'ready':fresh})
        for change in [dict(phase='deadline_elapsed'),dict(unix_ms=99)]:
            changed=copy.deepcopy(ends);changed[0].update(change)
            with self.subTest(change=change), self.assertRaisesRegex(RuntimeError, 'declared transport loss'):
                turnover.validated_replacements(old, changed+fresh, 100)
        self.assertIsNone(turnover.validated_replacements(old, ends+fresh+
            [dict(id=3,phase='transport_ended',unix_ms=103)],100))
        with self.assertRaisesRegex(RuntimeError, 'two distinct'):
            turnover.validated_replacements([{'id':1},{'id':1}],ends+fresh,100)
        with self.assertRaisesRegex(RuntimeError, 'declared transport loss'):
            turnover.validated_replacements(old,[ends[0],ends[0]]+fresh,100)

    def test_namespace_accepts_only_unaddressed_down_unrouted_kernel_fallback(self):
        tunnel = dict(ifname='tunl0', link_type='ipip', operstate='DOWN', flags=['NOARP'],
                      addr_info=[], address='0.0.0.0', broadcast='0.0.0.0', link=None)
        inventory = {}
        for scope, device in [('observer', 'client0'), ('fixture', 'fixture0')]:
            inventory[scope + '_links'] = [dict(ifname='lo'), dict(ifname=device), tunnel]
            inventory[scope + '_routes'] = {'-4': [], '-6': []}
        original = copy.deepcopy(inventory)
        turnover.Journey.assert_topology(inventory)
        self.assertEqual(inventory, original)  # Receipt retains every raw link.
        for scope in ('observer', 'fixture'):
            for change in [dict(flags=['NOARP', 'UP']), dict(operstate='UNKNOWN'),
                           dict(addr_info=[{'local': '10.0.0.1'}]), dict(link_type='ether'),
                           dict(address='10.0.0.1'), dict(link='eth0'), dict(master='br0'),
                           dict(ifname='unrecognized0')]:
                with self.subTest(scope=scope, change=change):
                    changed = copy.deepcopy(inventory)
                    changed[scope + '_links'][-1].update(change)
                    with self.assertRaises(RuntimeError):
                        turnover.Journey.assert_topology(changed)
            for route in [dict(dev='tunl0', dst='10.0.0.0/24'),
                          dict(dev='client0', dst='default'),
                          dict(dev='client0', gateway='10.0.0.1')]:
                changed = copy.deepcopy(inventory)
                changed[scope + '_routes']['-4'].append(route)
                with self.assertRaises(RuntimeError):
                    turnover.Journey.assert_topology(changed)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "c0").mkdir()
        self.worker = turnover.Journey(dict(out=str(self.root), uid=os.getuid(), gid=os.getgid(),
            workload="turnover", seed=1, config={}, build={"path": str(self.root / "build")}))
        self.worker.root = self.root
        self.worker.roles["client0"] = 1

    def test_custom_file_budget_rejects_unbounded_or_wrong_mode(self):
        for mode, seconds in [('file-recovery', '59'), ('file-recovery', '3601'), ('smoke', '2400')]:
            with self.subTest(mode=mode, seconds=seconds), \
                    mock.patch.object(os, 'geteuid', return_value=1000), \
                    mock.patch.object(sys, 'argv', ['gchat-turnover', '--build', '/unused', '--out', '/unused',
                                                   '--mode', mode, '--file-completion-seconds', seconds]), \
                    mock.patch.object(sys, 'stderr'):
                with self.assertRaises(SystemExit) as caught:
                    turnover.main()
                self.assertEqual(caught.exception.code, 2)

    def test_release_preset_cannot_silently_change_mode_size_or_deadline(self):
        for extra in (['--mode','smoke'], ['--mode','file-recovery','--file-bytes','1073741824'],
                      ['--mode','file-recovery','--file-completion-seconds','1200']):
            with self.subTest(extra=extra), mock.patch.object(os,'geteuid',return_value=1000), \
                    mock.patch.object(sys,'argv',['gchat-turnover','--build','/unused','--out','/unused',
                                                  '--release-check',*extra]), mock.patch.object(sys,'stderr'):
                with self.assertRaises(SystemExit) as caught: turnover.main()
                self.assertEqual(caught.exception.code,2)

    def test_file_completion_uses_one_deadline_and_rejects_late_completion(self):
        transfer = {'id': 'fixture', 'name': 'fixture.bin', 'size': 10, 'sha256': '0'*64}
        with mock.patch.object(self.worker, 'file_info', return_value={'state':'downloading','verified_bytes':'9'}), \
                mock.patch.object(self.worker, 'sample'), mock.patch.object(self.worker, 'event') as event, \
                mock.patch.object(self.worker, 'probe') as export, \
                mock.patch.object(turnover.time, 'sleep'), \
                mock.patch.object(turnover.time, 'monotonic', side_effect=[100, 101, 102, 159, 159.5, 160]):
            with self.assertRaisesRegex(RuntimeError, 'independent file completion deadline'):
                self.worker.finish_file(transfer, 60)
            export.assert_not_called()
            self.assertEqual(event.call_args_list[0].args[0], 'file_completion_deadline')
            self.assertEqual(event.call_args_list[0].kwargs['seconds'], 60)

    def test_file_completion_observed_after_deadline_is_not_exported(self):
        transfer = {'id': 'fixture', 'name': 'fixture.bin', 'size': 10, 'sha256': '0'*64}
        with mock.patch.object(self.worker, 'file_info', return_value={'state':'complete','verified_bytes':'10'}), \
                mock.patch.object(self.worker, 'event'), mock.patch.object(self.worker, 'probe') as export, \
                mock.patch.object(turnover.time, 'monotonic', side_effect=[100, 101, 160]):
            with self.assertRaisesRegex(RuntimeError, 'independent file completion deadline'):
                self.worker.finish_file(transfer, 60)
            export.assert_not_called()

    def test_reopen_removes_only_dead_owned_probe_socket_and_preserves_profile(self):
        endpoint = self.root / "c0/probe.sock"
        with socket.socket(socket.AF_UNIX) as stream:
            stream.bind(str(endpoint))
        profile = self.root / "c0/profile"
        profile.write_bytes(b"retained encrypted fixture bytes")
        self.worker.children.append(("probe0", mock.Mock(poll=lambda: -15)))
        with mock.patch.object(self.worker, "spawn") as spawn:
            self.worker.start_client(0)
        self.assertFalse(endpoint.exists())
        self.assertEqual(profile.read_bytes(), b"retained encrypted fixture bytes")
        _, command = spawn.call_args_list[0].args
        self.assertNotIn("--create", command)
        self.assertNotIn("--inbox-relay-file", command)
        self.assertNotIn("GC_ROUTING_BOOTSTRAP", spawn.call_args_list[0].kwargs["env"])
        self.assertIn("--gc2-carrier", command)

    def test_live_probe_or_unexpected_file_is_never_removed(self):
        endpoint = self.root / "c0/probe.sock"
        endpoint.write_text("preserve")
        self.worker.children.append(("probe0", mock.Mock(poll=lambda: None)))
        with self.assertRaisesRegex(RuntimeError, "still running"):
            self.worker.start_client(0)
        self.assertEqual(endpoint.read_text(), "preserve")

        self.worker.children.clear()
        with self.assertRaisesRegex(RuntimeError, "unexpected file"):
            self.worker.start_client(0)
        self.assertEqual(endpoint.read_text(), "preserve")

    def test_archive_fault_restores_owned_file_if_send_fails(self):
        self.worker.spec['fixture_host']={'path':'/bound/turnover_daemon'}
        (self.root/'c1').mkdir()
        archive=self.root/'c1/archive'
        archive.write_bytes(b'encrypted retained archive')
        with mock.patch.object(self.worker,'request',return_value={'snapshot':{'instance':{'id':'same'}}}), \
                mock.patch.object(self.worker,'submit',side_effect=RuntimeError('send failed')):
            with self.assertRaisesRegex(RuntimeError,'send failed'):
                self.worker.archive_failure('channel')
        self.assertEqual(archive.read_bytes(),b'encrypted retained archive')
        self.assertFalse((self.root/'c1/archive.before-failure').exists())

    def test_signed_fixture_host_reopen_keeps_network_and_profile_without_reprovisioning(self):
        self.worker.spec['host_netns']='net:[host]'
        self.worker.spec['fixture_host']={'path':'/bound/turnover_daemon'}
        self.worker.result['boundary']={'observer_netns':'net:[observer]','fixture_netns':'net:[fixture]'}
        with mock.patch.object(self.worker,'spawn') as spawn:
            self.worker.start_client(0)
        command=spawn.call_args_list[0].args[1]
        environment=spawn.call_args_list[0].kwargs['env']
        self.assertEqual(command[:2],['/bound/turnover_daemon','serve'])
        self.assertIn(self.root/'network.json',command)
        self.assertNotIn('--create',command)
        self.assertNotIn('--inbox-card',command)
        self.assertNotIn('GC_ROUTING_BOOTSTRAP',environment)
        self.assertEqual(environment['GCHAT_FIXTURE_NETNS'],'net:[observer]')
        self.assertEqual(environment['GCHAT_FIXTURE_HOST_NETNS'],'net:[host]')

    def test_received_reply_cannot_substitute_for_sender_delivery_receipt(self):
        self.worker.rpc_deadline = None
        def history(i, channel, token):
            return [dict(id='message-id', body=token, mine=i == 0,
                         delivery='local_accepted')]
        with mock.patch.object(self.worker, 'submit'), \
                mock.patch.object(self.worker, 'history', side_effect=history):
            with self.assertRaisesRegex(RuntimeError, 'deadline'):
                self.worker.chat('channel', 'pending', seconds=.02)
        self.assertEqual(self.worker.chat_count, 0)
        self.assertIsNone(self.worker.rpc_deadline)

    def test_delivery_receipt_requires_matching_received_id(self):
        self.worker.rpc_deadline = None
        def history(i, channel, token):
            return [dict(id=f'wrong-{i}', body=token, mine=i == 0,
                         delivery='delivered')]
        with mock.patch.object(self.worker, 'submit'), \
                mock.patch.object(self.worker, 'history', side_effect=history):
            with self.assertRaisesRegex(RuntimeError, 'deadline|identity'):
                self.worker.chat('channel', 'mismatch', seconds=.02)
        self.assertEqual(self.worker.chat_count, 0)
        self.assertIsNone(self.worker.rpc_deadline)

    def test_both_directions_require_matching_id_and_delivered_receipt(self):
        self.worker.rpc_deadline = None
        def history(i, channel, token):
            sender = 1 if token.startswith('reply:') else 0
            return [dict(id='id:'+token, body=token, mine=i == sender,
                         delivery='delivered' if i == sender else None)]
        with mock.patch.object(self.worker, 'submit') as submit, \
                mock.patch.object(self.worker, 'history', side_effect=history):
            self.worker.chat('channel', 'success', seconds=1)
        self.assertEqual(submit.call_count, 2)
        self.assertEqual(self.worker.chat_count, 1)
        self.assertIsNone(self.worker.rpc_deadline)

    def test_remote_join_uses_remaining_setup_budget_not_default_rpc_timeout(self):
        class SetupComplete(Exception):
            pass

        class Setup(turnover.Journey):
            def start_client(self, i):
                pass

            def request(self, *args, **kwargs):
                return {"ready": True}

            def files(self, *args, **kwargs):
                return {}

            def readiness(self, i):
                return True

            def submit(self, i, text, conversation=None):
                if text.startswith("/create"):
                    return {"conversation": "fixture"}
                if text.startswith("/invite"):
                    return {"output": {"link": "fixture", "localOnly": False}}
                return {}

            def join_invitation(self, *args):
                remaining = self.rpc_deadline - turnover.time.monotonic() if self.rpc_deadline else 30
                if remaining < 40:
                    raise TimeoutError("controller abandoned join before setup deadline")

            def chat(self, *args, **kwargs):
                raise SetupComplete

        worker = Setup(self.worker.spec)
        worker.root = self.root
        worker.ns = []
        with mock.patch.object(turnover.subprocess, "Popen"):
            with self.assertRaises(SetupComplete):
                worker.exercise()

    def test_combined_invitation_uses_typed_join_and_exact_inspected_network(self):
        code = 'private-fixture-' + 'x' * 16000
        preview = {'response': {'kind':'preview', 'preview': {
            'newNetwork':False, 'network':{'id':'fixture-network'}}}}
        result = {'response': {'kind':'result', 'network':'fixture-network',
                              'response':{'kind':'applied','conversation':'channel'}}}
        with mock.patch.object(self.worker, 'request', side_effect=[preview,result]) as request:
            self.assertEqual(self.worker.join_invitation(1,code,'receiver')['conversation'],'channel')
        self.assertEqual(request.call_args_list[0].kwargs['request'], {'kind':'inspect','code':code})
        join=request.call_args_list[1].kwargs['request']
        self.assertEqual(join['accepted_network'],'fixture-network')
        self.assertEqual(join['code'],code)
        self.assertEqual(join['nickname'],'receiver')
        self.assertTrue(join['operation_id'])
        self.assertNotIn(code,(self.root/'events.jsonl').read_text())

    def test_invitation_options_fail_setup_immediately_instead_of_polling(self):
        self.worker.spec.pop('fixture_host', None)
        with mock.patch.object(self.worker, 'submit', return_value={
                'output': {'kind': 'invitation_options'}}) as submit:
            with self.assertRaisesRegex(AssertionError, 'routable invitation'):
                turnover.until(lambda:self.worker.remote_invitation('channel'),
                               turnover.time.monotonic()+1, 'invitation')
        submit.assert_called_once_with(0, '/invite person', 'channel')

    def test_fixture_invitation_runs_as_the_profile_owner(self):
        self.worker.spec['fixture_host']={'path':'fixture'}
        answer=turnover.subprocess.CompletedProcess([],0,b'{"link":"private-link","localOnly":false}',b'')
        with mock.patch.object(self.worker,'request',return_value={'snapshot':{'conversations':[
                {'id':'channel','name':'#fixture'}]}}), mock.patch.object(turnover.subprocess,'run',return_value=answer) as run:
            self.assertEqual(self.worker.remote_invitation('channel'),'private-link')
        argv=run.call_args.args[0]
        self.assertIn('setpriv',argv)
        self.assertEqual(argv[argv.index('--reuid')+1],str(self.worker.uid))
        self.assertEqual(json.loads(run.call_args.kwargs['input']),{'channel':'fixture'})
        self.assertNotIn('private-link',str(self.worker.events))

    def test_fixture_never_silently_accepts_another_network(self):
        preview={'response':{'kind':'preview','preview':{'newNetwork':True,'network':{'id':'other'}}}}
        with mock.patch.object(self.worker,'request',return_value=preview) as request:
            with self.assertRaisesRegex(RuntimeError,'existing network'):
                self.worker.join_invitation(1,'fixture','receiver')
        self.assertEqual(request.call_count,1)

    def test_file_recovery_requires_retained_verified_bytes_before_export(self):
        self.worker.spec['config']['file_bytes']=123000000
        transfer={'id':'file','name':'fixture.bin','size':123000000,'sha256':'bound-hash'}
        before={'state':'downloading','verified_bytes':'13000000'}
        after={'state':'downloading','verified_bytes':'12999999'}
        with mock.patch.object(self.worker,'start_file',return_value=transfer), \
                mock.patch.object(self.worker,'file_info',side_effect=[before,after]), \
                mock.patch.object(self.worker,'reopen') as reopen, \
                mock.patch.object(self.worker,'finish_file') as finish:
            with self.assertRaisesRegex(RuntimeError,'verified pieces regressed'):
                self.worker.file_recovery('channel')
        reopen.assert_called_once_with(1,abrupt=True)
        finish.assert_not_called()

    def test_file_recovery_binds_final_and_reopened_export_to_original_hash(self):
        self.worker.spec['config']['file_bytes']=123000000
        self.worker.spec['config']['file_completion_seconds']=2400
        transfer={'id':'file','name':'fixture.bin','size':123000000,'sha256':'bound-hash'}
        info={'state':'downloading','verified_bytes':'13000000'}
        with mock.patch.object(self.worker,'start_file',return_value=transfer), \
                mock.patch.object(self.worker,'file_info',return_value=info), \
                mock.patch.object(self.worker,'reopen') as reopen, \
                mock.patch.object(self.worker,'chat'), \
                mock.patch.object(self.worker,'finish_file') as finish, \
                mock.patch.object(self.worker,'probe') as probe:
            self.worker.file_recovery('channel')
        self.assertEqual(reopen.call_args_list,[mock.call(1,abrupt=True),mock.call(1)])
        finish.assert_called_once_with(transfer, 2400)
        probe.assert_called_once_with(1,{'action':'export','id':'file','name':'reopened-fixture.bin',
                                         'size':123000000,'sha256':'bound-hash'})


class TopologyTests(unittest.TestCase):
    def test_bootstrap_can_supply_five_distinct_hops_for_either_inbox(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for i in (0, 1):
                (root / f'c{i}').mkdir()
            # This checks generated topology, not Unix ownership or namespaces.
            worker = turnover.Journey(dict(out=str(root), uid=1000, gid=1000,
                workload='turnover', seed=1, config={}, build={'path': str(root / 'build')}))
            worker.root = root
            (root / 'resolver').write_text('fixture')
            (root / 'nsswitch').write_text('fixture')
            def control(i, command):
                if command == 'routing_bootstrap':
                    return {'routing_bundle_b64': base64.urlsafe_b64encode(
                        b'GCRB\x02\x01' + bytes([i + 1]) * 155).decode()}
                if command == 'provision_client_relay':
                    return {'private_card_b64': 'private-fixture'}
                return {'ready': True}
            with mock.patch.object(worker, 'relay'), mock.patch.object(worker, 'stop'), \
                    mock.patch.object(os, 'chown', create=True), \
                    mock.patch.object(worker, 'control', side_effect=control):
                worker.prepare()
            for client, inbox in ((0, 2), (1, 3)):
                bundle = (root / f'c{client}/bootstrap').read_bytes()
                self.assertEqual(len(bundle), 6 + bundle[5] * 155)
                candidates = {bundle[offset] for offset in range(6, len(bundle), 155)}
                self.assertNotIn(inbox + 1, candidates)
                for entry in candidates:
                    self.assertGreaterEqual(len(candidates - {entry}), 3,
                        'five-hop route needs three independent middles after entry and terminal exclusion')
            self.assertEqual(len(set(worker.relay_addresses)), 6)


class CapEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.start = dict(id=1, role="client", phase="started", unix_ms=1000000,
            authority_expires_at=4600, max_lifetime_ms=1800000,
            deadline_after_start_ms=1799999, elapsed_ms=0)
        self.end = self.start | dict(phase="deadline_elapsed", unix_ms=2800001, elapsed_ms=1800001)

    def test_requires_actual_deadline_and_fresh_authority(self):
        self.assertEqual(turnover.validated_cap_ends([self.start], [self.end]), [self.end])
        for change in ({"phase": "transport_ended"}, {"phase": "dropped"},
                       {"elapsed_ms": 1790000}, {"unix_ms": 4600000}):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                turnover.validated_cap_ends([self.start], [self.end | change])
        with self.assertRaises(RuntimeError):
            turnover.validated_cap_ends([self.start | dict(authority_expires_at=2700)], [self.end])

    def test_missing_or_duplicate_completion_cannot_pass(self):
        self.assertIsNone(turnover.validated_cap_ends([self.start], []))
        with self.assertRaises(RuntimeError):
            turnover.validated_cap_ends([self.start], [self.end, self.end])


if __name__ == "__main__":
    unittest.main()
