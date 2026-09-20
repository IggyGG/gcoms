"""Fail-closed validity for disconnected, single-client GChat calibration.

A passing quartet is instrumentation/application evidence, never a statistical
privacy gate. Accepted file-profile separability requirements remain unchanged.
"""
import json
import math
from pathlib import Path
import re
import subprocess

from privacy_packets import sha256
from privacy_client_packets import capture_counts, observer_features, read_frames

SCOPE = 'isolated_gchat_daemon_explicit_bootstrap_v1'
WORKLOADS = {'idle', 'chat', 'bulk', 'mixed'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def bound_path(root, name):
    path = root / name
    require(not Path(name).is_absolute() and path.resolve().is_relative_to(root.resolve()), 'evidence escapes capture directory')
    return path


def topology(boundary):
    require(len({boundary[k] for k in ('host_netns', 'observer_netns', 'fixture_netns')}) == 3,
            'observer/fixture/host namespaces must be distinct')
    require(boundary['private_mount_namespace'] is True, 'private resolver/mount boundary missing')
    for key in ('resolver_sha256', 'nsswitch_sha256'):
        require(bool(re.fullmatch('[0-9a-f]{64}', boundary[key])), 'resolver binding missing')
    identities = []
    for when in ('before', 'after'):
        inventory = boundary[when]
        for prefix, device in (('observer', 'client0'), ('fixture', 'fixture0')):
            links = inventory[prefix + '_links']
            require({link['ifname'] for link in links} == {'lo', device}, 'undeclared interface')
            require(next(x for x in links if x['ifname'] == device)['link_type'] == 'ether', 'Ethernet boundary required')
            for rows in inventory[prefix + '_routes'].values():
                require(all(r.get('dst') != 'default' and not r.get('gateway') and r.get('dev') in ('lo', device) for r in rows), 'external route')
        identities.append(sorted((prefix, x['ifindex'], x['ifname'], x['address'])
            for prefix in ('observer', 'fixture') for x in inventory[prefix + '_links']))
    require(identities[0] == identities[1], 'interface identity changed')
    for members in (boundary['members'], boundary['members_at_shutdown']):
        roles = [m['role'] for m in members]
        require(len(roles) == len(set(roles)) and set(roles) == {'client0', 'namespace_holder', 'observer_capture', 'loopback_capture'},
                'undeclared or missing observer namespace member')
        require(next(m for m in members if m['role'] == 'client0')['effective_uid'] != 0, 'application ran privileged')
    for value in boundary['offloads'].values():
        for feature in ('tcp-segmentation-offload', 'generic-segmentation-offload', 'generic-receive-offload'):
            require(re.search(r'(?m)^' + feature + r': off(?:\s|$)', value) is not None, 'capture offload not disabled')
    return tuple(next(x['address'] for x in boundary['before'][prefix + '_links'] if x['ifname'] == device)
                 for prefix, device in (('observer', 'client0'), ('fixture', 'fixture0')))


def intervals(meta, config):
    names = ('capture_started_epoch', 'application_started_epoch', 'measurement_started_epoch',
             'measurement_finished_epoch', 'application_stop_requested_epoch',
             'application_finished_epoch', 'capture_finished_epoch')
    times = [meta[n] for n in names]
    require(all(isinstance(t, (int, float)) and math.isfinite(t) for t in times), 'invalid lifecycle timestamp')
    require(times == sorted(times), 'capture must cover application startup through shutdown and drain')
    require(abs(times[2] - times[1] - config['warmup_seconds']) < 1, 'unmatched startup allowance')
    require(abs(times[3] - times[2] - config['seconds']) < 1, 'unmatched measurement lifetime')
    require(abs(times[4] - times[1] - config['warmup_seconds'] - config['seconds']) < 1, 'unmatched process stop schedule')
    require(times[5] - times[4] < 15, 'application shutdown deadline')
    return times


def validate_capture(root, plan):
    root = Path(root)
    report = {'schema': 1, 'scope': SCOPE, 'measurement_valid': False, 'diagnostic_only': True,
              'release_qualified': False, 'component_gate_passed': False,
              'reference_threshold': .55, 'reference_threshold_is_release_veto': True,
              'statistical_evaluation_performed': False}
    try:
        meta = json.loads((root / 'worker.json').read_text())
        outer = json.loads((root / 'outer.json').read_text())
        spec = json.loads((root / 'spec.json').read_text())
        report['workload'] = meta['workload']
        require(meta['scope'] == plan['scope'] == SCOPE and meta['schema'] == 1,
                'pooled or unsupported capture scope')
        require(meta['diagnostic_only'] is True and meta['release_qualified'] is False, 'calibration cannot qualify release')
        require(meta['workload'] in WORKLOADS and meta['seed'] == plan['seed'], 'undeclared workload or seed')
        require(meta['config'] == plan['config'] and meta['build'] == plan['build'], 'configuration/build mismatch')
        for name, digest in plan['tooling'].items():
            require(sha256(Path(__file__).with_name(name)) == digest, 'capture tooling changed during run')
        config = meta['config']
        require(config['profile_id'] == 22 and config['bootstrap_version'] == 2 and config['entries'] == 2
                and config['cadence'] == 'production' and config['local_fixture'] is False
                and config['network_bootstrap'] is False and config['state'] == 'fresh'
                and config['observed_role'] == 'sender', 'unsupported client calibration settings')
        require(meta['completed'] is True and 'failure' not in meta and not meta.get('forced_kills'), 'incomplete or failed application run')
        require(meta['children_stopped'] is True and all(p['returncode'] is not None for p in meta['children']), 'child cleanup incomplete')
        require(meta['application_returncodes'] == [0, 0], 'daemon shutdown did not complete normally')
        require(outer['worker_returncode'] == 0 and outer['host_links_unchanged'] is True and outer['build_unchanged'] is True,
                'worker, host boundary or frozen build changed')
        require(meta['capture_returncode'] == 0 and meta['loopback_capture_returncode'] == 0, 'capture did not stop cleanly')
        require(meta['boundary']['host_netns'] == spec['host_netns'], 'host namespace binding mismatch')
        client_mac, fixture_mac = topology(meta['boundary'])
        times = intervals(meta, config)
        for name, digest in meta['evidence'].items():
            require(sha256(bound_path(root, name)) == digest, 'changed retained evidence: ' + name)
        for name in ('observer.pcap', 'observer.capture.log', 'loopback.pcap', 'loopback.capture.log', 'events.jsonl', 'client0.log', 'client1.log', *[f'r{i}/metrics.jsonl' for i in range(4)]):
            require(name in meta['evidence'], 'missing evidence binding: ' + name)
        frames, accounting = read_frames(root / 'observer.pcap', client_mac, fixture_mac)
        counters = capture_counts((root / 'observer.capture.log').read_text())
        require(counters['dropped'] == 0 and counters['captured'] == counters['received'] == accounting['frames'] > 0,
                'incomplete capture drain, lost or unaccounted frames')
        raw = (root / 'observer.pcap').read_bytes()
        require(len(meta['sentinels']) == 4 and len(set(meta['sentinels'])) == 4
                and all(s.encode() in raw for s in meta['sentinels']), 'IPv4/IPv6 startup/shutdown drain sentinel missing')
        require(meta['backend_sentinel'].encode() not in raw, 'backend-only traffic leaked into observed link')
        events = [json.loads(line) for line in (root / 'events.jsonl').read_text().splitlines()]
        attempted = [e['id'] for e in events if e['event'] == 'chat_attempted']
        sent = [e['id'] for e in events if e['event'] == 'chat_submitted']
        acked = [e['id'] for e in events if e['event'] == 'chat_acknowledged']
        count = config['chat_count'] if meta['workload'] in ('chat', 'mixed') else 0
        require(len(attempted) == len(set(attempted)) == count and sorted(attempted) == sorted(sent) == sorted(acked), 'incomplete/duplicate chat receipt ledger')
        require(sorted(meta['chat_acknowledged']) == sorted(acked), 'chat summary differs from receipt ledger')
        app_roles = {e['role']: e for e in events if e['event'] == 'process_start'}
        for role in ('client0', 'client1'):
            command = app_roles[role]['argv']
            require('--gc2-carrier' in command and '--no-network-bootstrap' in command
                    and '--local-fixture' not in command and '--allow-frwd-private-cidr' not in command
                    and app_roles[role]['owner_uid'] == spec['uid'], 'daemon launch does not match production carrier scope')
        for status in meta['readiness']:
            require(status['protocol'] == 'gchat' and status['profile_id'] == 22 and status['bootstrap_version'] == 2
                    and status['routing_ready'] is True and status['usable_terminal_routes'] > 0
                    and status['interactive_subscriptions'] >= 2 and status['bulk_subscriptions'] >= 2, 'unqualified transport readiness')
        require(len(meta['readiness']) == 2, 'both client readiness observations required')
        for e in events:
            if e['event'].startswith(('chat_', 'file_')):
                require(times[2] <= e['unix_seconds'] <= times[3], 'workload escaped matched measurement window')
        bulk = meta['workload'] in ('bulk', 'mixed')
        if bulk:
            file = meta['file']
            require(file['verified'] is True and file['size'] == config['file_bytes'], 'incomplete file export')
            for relative in ('c0/fixtures/matched-file.bin', 'c1/fixtures/received.bin'):
                path = bound_path(root, relative)
                require(path.stat().st_size == file['size'] and sha256(path) == file['sha256'], 'independent file hash mismatch')
            selected = [e for e in events if e['event'] in ('file_import', 'file_offered', 'file_accepted', 'file_export_verified')]
            require([e['event'] for e in selected] == ['file_import', 'file_offered', 'file_accepted', 'file_export_verified']
                    and all(e['id'] == file['id'] for e in selected), 'file receipt sequence mismatch')
            accepted = []
            for i in range(4):
                metric = root / f'r{i}/metrics.jsonl'
                for line in metric.read_text().splitlines():
                    e = json.loads(line)
                    if e['event'] == 'gchat_push_accepted' and e.get('class') == 'Bulk' and times[2] <= e['ts'] / 1000 <= times[3]:
                        accepted.append(e)
            require(bool(accepted), 'authenticated terminal Bulk acceptance missing')
            report['file'] = file
            report['terminal_acceptance_diagnostic_count'] = len(accepted)
        else:
            require(meta['file'] is None and not any(e['event'].startswith('file_') for e in events), 'unexpected bulk workload')
        report.update(measurement_valid=True, accounting=accounting, capture_counts=counters,
                      chat_acknowledged=count, process_lifetime_seconds=times[5] - times[1],
                      epoch_phase_seconds=times[1] % 3600,
                      crossed_credential_epoch=int(times[1] // 3600) != int(times[5] // 3600),
                      features=observer_features(frames, times[2], config['seconds'], times[1], times[6]),
                      manifest_sha256=sha256(root / 'worker.json'), pcap_sha256=sha256(root / 'observer.pcap'))
    except (OSError, ValueError, TypeError, KeyError, IndexError, subprocess.SubprocessError) as error:
        report['error'] = str(error)
    return report


def validate_quartet(reports, plan):
    result = {'schema': 1, 'scope': SCOPE, 'measurement_valid': False, 'diagnostic_only': True,
              'release_qualified': False, 'component_gate_passed': False,
              'reference_threshold': .55, 'reference_threshold_is_release_veto': True,
              'statistical_evaluation_performed': False,
              'next_gate': 'independent training/held-out window and connection comparisons; installed-client coverage remains separate',
              'workloads': [{k: v for k, v in r.items() if k != 'features'} for r in reports]}
    try:
        require(len(reports) == 4 and {r.get('workload') for r in reports} == WORKLOADS, 'one complete four-workload quartet required')
        require(all(r['measurement_valid'] for r in reports), 'one or more captures failed validity')
        files = [r['file'] for r in reports if r['workload'] in ('bulk', 'mixed')]
        require(files[0] == files[1], 'bulk/mixed file identity, size, hash or verification differ')
        lifetimes = [r['process_lifetime_seconds'] for r in reports]
        require(max(lifetimes) - min(lifetimes) < 2, 'unmatched process lifetimes')
        require(not any(r['crossed_credential_epoch'] for r in reports), 'credential rollover during validity calibration; retain phase evidence')
        result['measurement_valid'] = True
        result['order'] = plan['order']
        result['limits'] = ['One quartet has no training/held-out privacy bound.',
                            'Explicit-bootstrap daemon only; not installed-default desktop.',
                            'Process phases relative to hourly expiry are retained; no matched statistical phase claim.']
    except (ValueError, TypeError, KeyError) as error:
        result['error'] = str(error)
    return result
