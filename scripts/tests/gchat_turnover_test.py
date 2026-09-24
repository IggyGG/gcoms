"""Controller regressions from the real-daemon startup/reopen attempts."""
import importlib.util
import base64
import copy
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("gchat_turnover", Path(__file__).resolve().parents[1] / "gchat-turnover.py")
turnover = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(turnover)


@unittest.skipUnless(os.name == "posix", "Linux namespace controller")
class ControllerTests(unittest.TestCase):
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

    def test_file_completion_uses_one_deadline_and_rejects_late_completion(self):
        transfer = {'id': 'fixture', 'size': 10, 'sha256': '0'*64}
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
        transfer = {'id': 'fixture', 'size': 10, 'sha256': '0'*64}
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
            worker = turnover.Journey(dict(out=str(root), uid=os.getuid(), gid=os.getgid(),
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
