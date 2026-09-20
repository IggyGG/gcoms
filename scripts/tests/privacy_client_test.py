"""Client-boundary regressions: accounting loss, flow lifecycle and scope confusion."""
from dataclasses import replace
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
from privacy_client_packets import FIELDS, Frame, capture_counts, connections, parse_fields, pcap_counts
from privacy_client_manifest import SCOPE, intervals, topology, validate_capture, validate_quartet

CLIENT = '02:00:00:00:00:01'
PEER = '02:00:00:00:00:02'
A = ('11.231.97.2', 40000)
B = ('11.231.97.10', 24500)


def row(number=1, **values):
    fields = dict.fromkeys(FIELDS, '')
    fields.update({'frame.number': str(number), 'frame.time_epoch': str(number),
                   'frame.len': '60', 'frame.cap_len': '60', 'eth.src': CLIENT,
                   'eth.dst': PEER, 'eth.type': '0x0800', 'ip.src': A[0], 'ip.dst': B[0]})
    fields.update(values)
    return '\t'.join(fields[name] for name in FIELDS)


def frame(t, source=A, destination=B, stream='0', **flags):
    return Frame(int(t * 10), t, 60, 'up' if source == A else 'down', 'tcp',
                 source, destination, stream, flags.get('syn', False), flags.get('ack', False),
                 flags.get('rst', False), flags.get('fin', False), flags.get('sequence', '1'),
                 flags.get('retransmission', False))


class ClientPacketsTest(unittest.TestCase):
    def test_multicast_and_non_ip_frames_are_never_dropped(self):
        rows = [row(), row(2, **{'eth.src': PEER, 'eth.dst': '33:33:00:00:00:01',
                 'ip.src': '', 'ip.dst': '', 'ipv6.src': 'fe80::1', 'ipv6.dst': 'ff02::1'}),
                row(3, **{'ip.src': '', 'ip.dst': '', 'eth.dst': 'ff:ff:ff:ff:ff:ff', 'eth.type': '0x0806'})]
        frames = parse_fields('\n'.join(rows), CLIENT, PEER)
        self.assertEqual(len(frames), 3)
        self.assertEqual([f.direction for f in frames], ['up', 'down', 'up'])
        self.assertEqual(frames[-1].protocol, 'non_ip')

    def test_unattributed_malformed_truncated_and_omitted_frames_fail(self):
        for text in [row(**{'eth.src': '02:00:00:00:00:03'}), row(**{'_ws.malformed': '1'}),
                     row(**{'frame.cap_len': '20'}), row(2), row(**{'frame.time_epoch': 'nan'}),
                     row(**{'tcp.srcport': '40', 'tcp.dstport': '50'})]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_fields(text, CLIENT, PEER)

    def test_syn_retransmission_bidirectional_fin_and_tuple_reuse(self):
        rows = [frame(1, syn=True), frame(2, syn=True, retransmission=True),
                frame(3, B, A, syn=True, ack=True), frame(4, ack=True),
                frame(5, fin=True, ack=True), frame(6, B, A, fin=True, ack=True),
                frame(7, ack=True), frame(8, stream='1', syn=True, sequence='22'),
                frame(9, B, A, stream='1', rst=True)]
        flows = connections(rows, 0, 10)
        self.assertEqual(len(flows), 2)
        self.assertEqual(flows[0]['syn_retransmissions'], 1)
        self.assertEqual(flows[0]['fin_packets'], 2)
        self.assertTrue(flows[0]['handshake_observed'])
        self.assertFalse(flows[0]['right_censored'])
        self.assertEqual(flows[0]['observed_seconds'], 6)
        self.assertTrue(flows[1]['setup_refused'])
        self.assertFalse(flows[1]['handshake_observed'])

    def test_missing_open_and_half_close_are_censored(self):
        flows = connections([frame(2, ack=True), frame(3, fin=True)], 0, 10)
        self.assertTrue(flows[0]['left_censored'])
        self.assertTrue(flows[0]['right_censored'])
        self.assertEqual(flows[0]['observed_seconds'], 1)
        self.assertFalse(flows[0]['setup_refused'])

    def test_missing_final_handshake_ack_is_not_established(self):
        flows = connections([frame(1, syn=True), frame(2, B, A, syn=True, ack=True)], 0, 10)
        self.assertFalse(flows[0]['handshake_observed'])
        self.assertTrue(flows[0]['right_censored'])

    def test_ambiguous_tuple_generation_is_rejected(self):
        for rows in ([frame(1, syn=True), frame(2, syn=True, sequence='different')],
                     [frame(1), replace(frame(2), destination=('11.231.97.11', 24501))]):
            with self.assertRaises(ValueError):
                connections(rows, 0, 10)

    def test_pcap_counts_independently_reject_partial_and_truncated_records(self):
        header = b'\xd4\xc3\xb2\xa1' + struct.pack('<HHIIII', 2, 4, 0, 0, 262144, 1)
        valid = header + struct.pack('<IIII', 1, 1, 60, 60) + bytes(60)
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / 'wire.pcap'
            p.write_bytes(valid)
            self.assertEqual(pcap_counts(p)['frames'], 1)
            for bad in (valid[:-1], header[:-1], header + b'one',
                        header + struct.pack('<IIII', 1, 1, 20, 60) + bytes(20),
                        header[:20] + struct.pack('<I', 113)):
                p.write_bytes(bad)
                with self.subTest(size=len(bad)), self.assertRaises(ValueError):
                    pcap_counts(p)

    def test_buffered_zero_capture_is_visible_even_with_zero_drops(self):
        values = capture_counts('0 packets captured\n26 packets received by filter\n0 packets dropped by kernel\n')
        self.assertEqual(values, {'captured': 0, 'received': 26, 'dropped': 0})
        for bad in ('0 packets dropped by kernel\n', '1 packets captured\n1 packets captured\n1 packets received by filter\n0 packets dropped by kernel\n'):
            with self.assertRaises(ValueError):
                capture_counts(bad)


class ClientIpcDeadlineTest(unittest.TestCase):
    def test_long_setup_response_uses_phase_budget_and_expired_budget_refuses_io(self):
        spec = importlib.util.spec_from_file_location('client_capture_driver', SCRIPTS / 'privacy-client-capture.py')
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
        worker = object.__new__(driver.Worker)
        worker.root = Path('/unused-fixture')
        worker.rpc_deadline = 190.0
        raw = json.dumps({'ok': True, 'value': {'joined': True}}).encode()

        class Socket:
            def __init__(self):
                self.data = struct.pack('!I', len(raw)) + raw
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def settimeout(self, timeout): self.timeout = timeout
            def connect(self, path): pass
            def sendall(self, data): pass
            def recv(self, n):
                # A completed response at 40 seconds used to be lost to the
                # unrelated 35-second controller timeout despite setup budget.
                if self.timeout < 40:
                    raise TimeoutError('response exceeded socket timeout')
                result, self.data = self.data[:n], self.data[n:]
                return result
        with patch.object(driver.time, 'monotonic', return_value=100.0), \
                patch.object(driver.socket, 'socket', side_effect=lambda *_: Socket()):
            self.assertEqual(worker.probe(0, {}), {'joined': True})
            worker.rpc_deadline = 99.0
            with self.assertRaisesRegex(TimeoutError, 'phase deadline'):
                worker.probe(0, {})


class ClientManifestTest(unittest.TestCase):
    def test_pooled_capture_is_rejected_before_analysis(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)
            (p / 'worker.json').write_text(json.dumps({'schema': 1, 'scope': 'pooled_loopback_fixture', 'workload': 'idle'}))
            for n in ('outer', 'spec'):
                (p / (n + '.json')).write_text('{}')
            result = validate_capture(p, {'scope': SCOPE})
            self.assertFalse(result['measurement_valid'])
            self.assertIn('pooled', result['error'])
            self.assertFalse(result['release_qualified'])

    def test_lifecycle_must_include_startup_shutdown_and_equal_window(self):
        names = ['capture_started_epoch', 'application_started_epoch', 'measurement_started_epoch',
                 'measurement_finished_epoch', 'application_stop_requested_epoch',
                 'application_finished_epoch', 'capture_finished_epoch']
        good = dict(zip(names, [1, 2, 122, 182, 182, 183, 185]))
        config = {'warmup_seconds': 120, 'seconds': 60}
        intervals(good, config)
        for field, value in [('capture_started_epoch', 3), ('capture_finished_epoch', 181),
                             ('measurement_finished_epoch', 184), ('application_stop_requested_epoch', 185)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                intervals(good | {field: value}, config)

    def test_valid_calibration_still_cannot_pass_a_privacy_component(self):
        file = {'id': 'same', 'size': 1024, 'sha256': 'a' * 64, 'verified': True}
        reports = [{'workload': w, 'measurement_valid': True, 'process_lifetime_seconds': 180,
                    'crossed_credential_epoch': False, **({'file': file} if w in ('bulk', 'mixed') else {})}
                   for w in ('idle', 'chat', 'bulk', 'mixed')]
        plan = {'order': ['idle', 'chat', 'bulk', 'mixed']}
        result = validate_quartet(reports, plan)
        self.assertTrue(result['measurement_valid'])
        self.assertFalse(result['release_qualified'])
        self.assertFalse(result['component_gate_passed'])
        self.assertTrue(result['reference_threshold_is_release_veto'])
        self.assertEqual(result['reference_threshold'], .55)
        for changed in (reports[:-1], reports + [reports[0]],
                        [reports[0] | {'measurement_valid': False}, *reports[1:]],
                        [reports[0] | {'process_lifetime_seconds': 184}, *reports[1:]],
                        [reports[0] | {'crossed_credential_epoch': True}, *reports[1:]],
                        [*reports[:3], reports[3] | {'file': file | {'sha256': 'b' * 64}}]):
            self.assertFalse(validate_quartet(changed, plan)['measurement_valid'])


if __name__ == '__main__':
    unittest.main()
