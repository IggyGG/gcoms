#!/usr/bin/env python3
"""Bounded, synthetic cost/queueing models; no sockets, captures or deployment output.

These models do not implement GC/1, cryptography, a mixnet or an anonymity test.
All traffic is generated from sizes and virtual times. Candidate aggregation is
hypothetical, not a compatible production wire-format change.
"""
import argparse
from collections import Counter, defaultdict, deque
import hashlib
import heapq
import json
import math
import os
from pathlib import Path
import random
import statistics
import tempfile
from typing import NamedTuple

DAY_MS = 86_400_000
MONTH_DAYS = 30
BUDGETS = {"mobile": 250_000_000, "desktop": 1_000_000_000}
CHAT_DELAY_MS = 3000
BATCH_MS = CHAT_DELAY_MS // 2
MIX_MS = CHAT_DELAY_MS - BATCH_MS
RECORD_BYTES = 4096
HEADER_BYTES = 64  # Illustrative ordinary overhead, NOT GC/1 crypto/TLS sizing.
CHUNK_BYTES = 16_128
QUEUE_BYTES = 8 * 1024 * 1024
QUEUE_JOBS = 4096
MAX_MESSAGES = 20_000
MAX_EVENTS = 250_000
POLICIES = ("fixed_serial_model", "unpadded_control", "budgeted_padding", "chat_batching")


class Message(NamedTuple):
    number: int
    client: int
    kind: str
    at_ms: float
    size: int


class Job(NamedTuple):
    messages: tuple
    ready_ms: float

    @property
    def client(self):
        return self.messages[0].client

    @property
    def kind(self):
        return self.messages[0].kind

    @property
    def size(self):
        return sum(message.size for message in self.messages)


class Scenario(NamedTuple):
    name: str
    clients: int = 1
    link_bytes_s: int = 262_144
    loss_every: int = 0
    outage_ms: tuple = ()
    exhausted: bool = False


SCENARIOS = (
    Scenario("idle"), Scenario("sparse_chat"), Scenario("conversation"),
    Scenario("burst_chat"), Scenario("small_population", clients=2),
    Scenario("shared_population", clients=8), Scenario("bulk"),
    Scenario("chat_bulk"), Scenario("congestion", link_bytes_s=4096),
    Scenario("reconnect", outage_ms=(3_610_000, 3_640_000)),
    Scenario("loss", loss_every=7), Scenario("budget_exhaustion", exhausted=True),
    Scenario("overload"),
)


def seeded(seed, label):
    digest = hashlib.sha256(f"{seed}:{label}".encode()).digest()
    return random.Random(int.from_bytes(digest, "big"))


def workload(scenario, seed):
    rng = seeded(seed, "workload:" + scenario.name)
    messages = []

    def add(client, kind, at_ms, size):
        messages.append(Message(len(messages), client, kind, at_ms, size))

    for client in range(scenario.clients):
        if scenario.name in ("sparse_chat", "budget_exhaustion"):
            for hour in range(24):
                add(client, "chat", hour * 3_600_000 + 15_000, 128)
        if scenario.name in ("conversation", "small_population", "shared_population"):
            count = 300 if scenario.name == "conversation" else 120
            for _ in range(count):
                add(client, "chat", rng.uniform(3_600_000, 7_200_000), rng.choice((128, 256, 768)))
        if scenario.name == "burst_chat":
            for burst in range(30):
                for index in range(20):
                    add(client, "chat", 3_601_000 + burst * 120_000 + index * 20, 128)
        if scenario.name in ("chat_bulk", "congestion", "reconnect", "loss"):
            count = 300 if scenario.name == "chat_bulk" else 60
            for index in range(count):
                add(client, "chat", 3_600_100 + index * 2000, 128)
        if scenario.name in ("bulk", "chat_bulk", "congestion", "loss", "overload"):
            size = (32 if scenario.name == "overload" else
                    1 if scenario.name in ("congestion", "loss") else 4) * 1024 * 1024
            while size:
                amount = min(size, CHUNK_BYTES)
                add(client, "bulk", 3_600_000, amount)
                size -= amount
    return tuple(sorted(messages, key=lambda message: (message.at_ms, message.number)))


def jobs_for(messages, policy):
    if policy != "chat_batching":
        return [Job((message,), message.at_ms) for message in messages]
    groups = defaultdict(list)
    result = []
    for message in messages:
        if message.kind == "bulk":
            result.append(Job((message,), message.at_ms))
        else:
            # One aggregate end-to-end delay allowance, never three seconds per hop.
            release = (math.floor(message.at_ms / BATCH_MS) + 1) * BATCH_MS
            groups[message.client, release].append(message)
    for (_, release), group in sorted(groups.items()):
        current, size = [], 0
        for message in group:
            amount = message.size + HEADER_BYTES
            if current and size + amount > CHUNK_BYTES:
                result.append(Job(tuple(current), release))
                current, size = [], 0
            current.append(message)
            size += amount
        result.append(Job(tuple(current), release))
    return sorted(result, key=lambda job: (job.ready_ms, job.messages[0].number))


def encoding(job, policy):
    request = job.size + HEADER_BYTES * len(job.messages)
    reply = HEADER_BYTES
    protocol = request + reply - job.size
    if policy != "unpadded_control":
        request = math.ceil(request / RECORD_BYTES) * RECORD_BYTES
        reply = RECORD_BYTES
    return request, reply, protocol, request + reply - job.size - protocol


class Budget:
    def __init__(self, available):
        self.available = available
        self.spent = 0
        self.denials = 0
        self.first_denial_ms = None

    def charge(self, amount, now):
        if amount < 0:
            raise ValueError("negative privacy charge")
        if self.spent + amount > self.available:
            self.denials += 1
            if self.first_denial_ms is None:
                self.first_denial_ms = now
            return False
        self.spent += amount
        return True


def describe(values):
    if not values:
        return {"count": 0, "median": None, "p95": None, "max": None}
    ordered = sorted(values)
    return {"count": len(values), "median": statistics.median(ordered),
            "p95": ordered[math.ceil(len(ordered) * .95) - 1], "max": ordered[-1]}


class Model:
    def __init__(self, scenario, policy, profile, seed, messages):
        self.scenario, self.policy, self.profile = scenario, policy, profile
        self.messages = messages
        self.window = 1 if policy == "fixed_serial_model" else 4
        available = 0 if scenario.exhausted else BUDGETS[profile] // MONTH_DAYS
        self.budgets = [Budget(available) for _ in range(scenario.clients)]
        self.bytes = [Counter() for _ in range(scenario.clients)]
        self.queues = [{"chat": deque(), "bulk": deque()} for _ in range(scenario.clients)]
        self.queued_bytes = [0] * scenario.clients
        self.held_bytes = [0] * scenario.clients
        self.held_jobs = [0] * scenario.clients
        self.inflight = [0] * scenario.clients
        self.inflight_bytes = [0] * scenario.clients
        self.peaks = [0] * scenario.clients
        self.chat_turns = [0] * scenario.clients
        self.ticks = set()
        self.events, self.sequence = [], 0
        self.link_free = defaultdict(float)
        self.link_bytes = [0, 0, 0]
        self.active_seconds = [set(), set(), set()]
        self.schedule_rng = seeded(seed, "schedule")
        self.mix_rng = seeded(seed, "mix")
        self.mix_groups = defaultdict(list)
        self.intentional_positions = {}
        self.latency = {"chat": [], "bulk": []}
        self.intentional, self.queue_wait = [], []
        self.bulk_finish = []
        self.delivered = Counter()
        self.failures = Counter()
        self.counters = Counter()
        self.release_clients = defaultdict(set)
        self.processed_events = 0
        for job in jobs_for(messages, policy):
            if policy == "chat_batching" and job.kind == "chat":
                # Conservatively reserve the entire aggregate at its first arrival.
                self.push(min(message.at_ms for message in job.messages), "hold", job)
            else:
                self.push(job.ready_ms, "arrival", job)
        if policy in ("budgeted_padding", "chat_batching"):
            # Illustrative candidate: half the daily allowance is the EXPECTED
            # cover allocation. The shared per-device ledger still caps all padding.
            mean_gap = DAY_MS * RECORD_BYTES / (BUDGETS[profile] / MONTH_DAYS / 2)
            for client in range(scenario.clients):
                rng = seeded(seed, f"cover:{client}")
                time_ms = rng.expovariate(1 / mean_gap)
                while time_ms < DAY_MS:
                    self.push(time_ms, "cover", (client, rng.randrange(2)))
                    time_ms += rng.expovariate(1 / mean_gap)

    def push(self, at, kind, value):
        self.sequence += 1
        if self.sequence > MAX_EVENTS:
            raise ValueError("synthetic event bound exceeded")
        heapq.heappush(self.events, (at, self.sequence, kind, value))

    def track_memory(self, client):
        self.peaks[client] = max(self.peaks[client],
                                 self.held_bytes[client] + self.queued_bytes[client] + self.inflight_bytes[client])

    def hop(self, now, transfer):
        job, client, size, direction, link, retry, mixed = transfer
        if (job is not None and job.kind == "chat" and self.policy == "chat_batching"
                and link == 1 and direction == 0 and not mixed and not retry):
            release = (math.floor(now / MIX_MS) + 1) * MIX_MS
            group = self.mix_groups[release]
            if not group:
                self.push(release, "mix_release", release)
            group.append((job, client, size, direction, link, retry, True))
            for position in self.intentional_positions[job.messages[0].number]:
                self.intentional[position] += release - now
            return
        key = (link, direction, client if link == 0 else -1)
        start = max(now, self.link_free[key])
        outage = self.scenario.outage_ms
        if link == 0 and outage and outage[0] <= start < outage[1]:
            start = outage[1]
            self.counters["outage_deferrals"] += 1
        rate = self.scenario.link_bytes_s
        if self.policy == "fixed_serial_model" and link == 0:
            rate = min(rate, 40 * 1024)
        finish = start + size * 1000 / rate
        self.link_free[key] = finish
        self.link_bytes[link] += size
        self.active_seconds[link].add(int(start // 1000))
        arrival = finish + 20  # Assumed propagation per link, not calibrated RTT.
        if job is None:  # Dummy terminates on the client link.
            return
        if direction == 0 and link == 2:
            reply = encoding(job, self.policy)[1]
            self.push(arrival, "hop", (job, client, reply, 1, 2, retry, mixed))
        elif direction == 1 and link == 0:
            self.push(arrival, "completion", (job, retry))
        else:
            next_link = link + (1 if direction == 0 else -1)
            self.push(arrival, "hop", (job, client, size, direction, next_link, retry, mixed))

    def reject(self, job, reason):
        self.failures[reason] += len(job.messages)

    def take_job(self, client):
        queue = self.queues[client]
        if queue["chat"] and (self.chat_turns[client] < 3 or not queue["bulk"]):
            self.chat_turns[client] += 1
            return queue["chat"].popleft()
        self.chat_turns[client] = 0
        return queue["bulk"].popleft()

    def transmit(self, job, now, retry=False):
        request, reply, protocol, padding = encoding(job, self.policy)
        client = job.client
        if self.policy in ("budgeted_padding", "chat_batching"):
            if not self.budgets[client].charge(padding, now):
                self.reject(job, "privacy_budget")
                return False
        amounts = self.bytes[client]
        amounts["payload_transmission"] += job.size
        amounts["ordinary_protocol"] += protocol
        amounts["privacy_padding"] += padding
        if retry:
            amounts["retransmitted_payload"] += job.size  # Subset, not a fifth wire category.
        self.push(now, "hop", (job, client, request, 0, 0, retry, False))
        return True

    def dispatch(self, client, now, tick_delay=None):
        queue = self.queues[client]
        while self.inflight[client] < self.window and (queue["chat"] or queue["bulk"]):
            if self.policy == "fixed_serial_model" and tick_delay is None:
                if client not in self.ticks:
                    delay = 3000
                    while self.schedule_rng.random() >= .5:
                        delay += 3000
                    self.ticks.add(client)
                    self.push(now + delay, "tick", (client, delay))
                return
            job = self.take_job(client)
            self.queued_bytes[client] -= job.size
            delay = tick_delay or 0
            if self.transmit(job, now):
                positions = []
                for message in job.messages:
                    if message.kind == "chat":
                        positions.append(len(self.intentional))
                        self.intentional.append(job.ready_ms - message.at_ms + delay)
                    self.queue_wait.append(max(0, now - job.ready_ms - delay))
                self.intentional_positions[job.messages[0].number] = positions
                self.inflight[client] += 1
                self.inflight_bytes[client] += job.size
                self.track_memory(client)
            tick_delay = None

    def run(self):
        while self.events:
            now, _, kind, value = heapq.heappop(self.events)
            self.processed_events += 1
            if now > DAY_MS + 3_600_000:
                raise ValueError("model failed to drain within the explicit bound")
            if kind == "hold":
                job = value
                client = job.client
                queue = self.queues[client]
                count = len(queue["chat"]) + len(queue["bulk"]) + self.held_jobs[client]
                if (self.held_bytes[client] + self.queued_bytes[client] + job.size > QUEUE_BYTES
                        or count >= QUEUE_JOBS):
                    self.reject(job, "queue_capacity")
                else:
                    self.held_bytes[client] += job.size
                    self.held_jobs[client] += 1
                    self.track_memory(client)
                    self.push(job.ready_ms, "arrival", job)
            elif kind == "arrival":
                job = value
                client = job.client
                if self.policy == "chat_batching" and job.kind == "chat":
                    self.held_bytes[client] -= job.size
                    self.held_jobs[client] -= 1
                queue = self.queues[client]
                count = len(queue["chat"]) + len(queue["bulk"]) + self.held_jobs[client]
                if self.held_bytes[client] + self.queued_bytes[client] + job.size > QUEUE_BYTES or count >= QUEUE_JOBS:
                    self.reject(job, "queue_capacity")
                else:
                    queue[job.kind].append(job)
                    self.queued_bytes[client] += job.size
                    self.track_memory(client)
                    self.dispatch(client, now)
            elif kind == "tick":
                client, delay = value
                self.ticks.remove(client)
                self.dispatch(client, now, delay)
            elif kind == "hop":
                self.hop(now, value)
            elif kind == "mix_release":
                group = self.mix_groups.pop(value)
                self.mix_rng.shuffle(group)
                self.release_clients[value].update(transfer[1] for transfer in group)
                for transfer in group:
                    self.push(now, "hop", transfer)
            elif kind == "completion":
                job, retry = value
                client = job.client
                lost = (not retry and self.scenario.loss_every and
                        job.messages[0].number % self.scenario.loss_every == 0)
                if lost:
                    self.counters["modeled_reply_losses"] += 1
                    self.push(now + 500, "retry", job)
                    continue
                for message in job.messages:
                    self.delivered[message.kind + "_messages"] += 1
                    self.delivered[message.kind + "_bytes"] += message.size
                    self.latency[message.kind].append(now - message.at_ms)
                if job.kind == "bulk":
                    self.bulk_finish.append(now)
                self.inflight[client] -= 1
                self.inflight_bytes[client] -= job.size
                self.dispatch(client, now)
            elif kind == "retry":
                job = value
                if not self.transmit(job, now, retry=True):
                    self.inflight[job.client] -= 1
                    self.inflight_bytes[job.client] -= job.size
                    self.dispatch(job.client, now)
            elif kind == "cover":
                client, direction = value
                self.counters["cover_opportunities"] += 1
                queue = self.queues[client]
                if self.inflight[client] or self.held_jobs[client] or queue["chat"] or queue["bulk"]:
                    self.counters["cover_suppressed_busy"] += 1
                elif self.budgets[client].charge(RECORD_BYTES, now):
                    self.bytes[client]["dummy"] += RECORD_BYTES
                    self.push(now, "hop", (None, client, RECORD_BYTES, direction, 0, False, False))
                else:
                    self.counters["cover_suppressed_budget"] += 1
            else:
                raise AssertionError("unknown model event")
        return self.result()

    def result(self):
        nominal_daily = 2 * RECORD_BYTES * DAY_MS // 100
        if self.policy == "fixed_serial_model":
            # Analytic idle fill avoids enumerating millions of dummy records.
            # This is NOMINAL demand, not assured throughput under congestion.
            for amounts in self.bytes:
                data = sum(amounts[key] for key in ("payload_transmission", "ordinary_protocol", "privacy_padding"))
                amounts["dummy"] = max(0, nominal_daily - data)
            fill = sum(amounts["dummy"] for amounts in self.bytes)
            self.link_bytes[0] += fill
            self.link_bytes[1] += fill
        ledgers = []
        for client, amounts in enumerate(self.bytes):
            private = amounts["dummy"] + amounts["privacy_padding"]
            wire = private + amounts["payload_transmission"] + amounts["ordinary_protocol"]
            ledger = {key + "_bytes": amounts[key] for key in (
                "payload_transmission", "ordinary_protocol", "privacy_padding", "dummy", "retransmitted_payload")}
            ledger.update(wire_bytes=wire, privacy_extra_bytes=private,
                          privacy_allowance_bytes=self.budgets[client].available,
                          budget_denials=self.budgets[client].denials,
                          first_budget_denial_ms=self.budgets[client].first_denial_ms,
                          projected_30_day_extra_bytes=None if self.scenario.exhausted else private * MONTH_DAYS)
            ledgers.append(ledger)
        sent = sum(self.delivered[key] for key in ("chat_messages", "bulk_messages"))
        assert sent + sum(self.failures.values()) == len(self.messages), "lost model accounting"
        assert sum(item["wire_bytes"] for item in ledgers) == self.link_bytes[0]
        assert not any(self.inflight) and not any(self.queued_bytes)
        assert not any(self.held_bytes) and not any(self.held_jobs) and not self.mix_groups
        bulk = [message for message in self.messages if message.kind == "bulk"]
        bulk_duration = (max(self.bulk_finish) - min(message.at_ms for message in bulk)
                         if self.bulk_finish else None)
        failures = dict(self.failures)
        budget_ok = all(item["privacy_extra_bytes"] <= item["privacy_allowance_bytes"] for item in ledgers)
        delay_ok = not self.intentional or max(self.intentional) <= CHAT_DELAY_MS
        conditions = []
        if not budget_ok:
            conditions.append("privacy_budget_exceeded")
        if any(budget.denials for budget in self.budgets):
            conditions.append("privacy_budget_exhausted")
        if failures:
            conditions.append("delivery_incomplete")
        if not delay_ok:
            conditions.append("chat_intentional_delay_exceeded")
        active = [len(seconds) for seconds in self.active_seconds]
        if self.policy == "fixed_serial_model":
            active[:2] = [DAY_MS // 1000] * 2
        return {
            "scenario": self.scenario.name, "clients": self.scenario.clients,
            "profile": self.profile, "policy": self.policy,
            "generated_messages": len(self.messages), "delivered_messages": sent,
            "delivered": dict(self.delivered), "failures": failures,
            "conditions": conditions, "numerical_targets_met": not conditions,
            "chat_completion_ms": describe(self.latency["chat"]),
            "chat_intentional_delay_ms": describe(self.intentional),
            "queue_wait_ms": describe(self.queue_wait),
            "bulk_completion_ms": bulk_duration,
            "bulk_goodput_kib_s": (self.delivered["bulk_bytes"] * 1000 / bulk_duration / 1024
                                   if bulk_duration else None),
            "peak_buffered_payload_bytes_per_client": max(self.peaks),
            "device_ledgers": ledgers, "counters": dict(self.counters),
            "observations": {
                "unit": "synthetic_logical_transmissions_not_packets",
                "link_duplex_bytes": self.link_bytes, "link_transmission_start_bins_1s": active,
                "chat_release_groups": len(self.release_clients),
                "release_groups_with_multiple_clients": sum(len(group) > 1 for group in self.release_clients.values()),
                "mixing_opportunities_are_anonymity_proof": False,
                "candidate_dummy_scope": "client_link_only",
                "both_end_linkage_evaluated": False,
            },
            "privacy_verdict": "not_qualified", "processed_events": self.processed_events,
        }


def simulate(scenario, policy, profile, seed, messages=None):
    if policy not in POLICIES or profile not in BUDGETS:
        raise ValueError("unknown fixed study model")
    if not 1 <= scenario.clients <= 8 or scenario.link_bytes_s <= 0:
        raise ValueError("invalid model population/capacity")
    messages = workload(scenario, seed) if messages is None else tuple(messages)
    if len(messages) > MAX_MESSAGES or len({message.number for message in messages}) != len(messages):
        raise ValueError("invalid synthetic workload size/identifiers")
    for message in messages:
        if (message.kind not in ("chat", "bulk") or not 0 <= message.client < scenario.clients or
                not 0 <= message.at_ms < DAY_MS or not 1 <= message.size <= CHUNK_BYTES):
            raise ValueError("invalid synthetic message")
    return Model(scenario, policy, profile, seed, messages).run()


def summarize(trials):
    groups = defaultdict(list)
    for trial in trials:
        groups[trial["profile"], trial["scenario"], trial["policy"]].append(trial)
    rows = []
    for (profile, scenario, policy), runs in sorted(groups.items()):
        def med(field):
            values = [run[field] for run in runs if run[field] is not None]
            return statistics.median(values) if values else None
        projections = [max(ledger["projected_30_day_extra_bytes"] for ledger in run["device_ledgers"])
                       for run in runs if scenario != "budget_exhaustion"]
        p95 = [run["chat_completion_ms"]["p95"] for run in runs if run["chat_completion_ms"]["p95"] is not None]
        rows.append({
            "profile": profile, "scenario": scenario, "policy": policy, "runs": len(runs),
            "numerical_passes": sum(run["numerical_targets_met"] for run in runs),
            "conditions": sorted({condition for run in runs for condition in run["conditions"]}),
            "worst_client_extra_mb_per_30_days_median": statistics.median(projections) / 1e6 if projections else None,
            "worst_client_extra_mb_per_30_days_range": [min(projections) / 1e6, max(projections) / 1e6] if projections else None,
            "chat_p95_ms_median": statistics.median(p95) if p95 else None,
            "chat_p95_ms_range": [min(p95), max(p95)] if p95 else None,
            "max_chat_intentional_delay_ms": max((run["chat_intentional_delay_ms"]["max"] or 0) for run in runs),
            "bulk_goodput_kib_s_median": med("bulk_goodput_kib_s"),
            "max_buffered_payload_bytes": max(run["peak_buffered_payload_bytes_per_client"] for run in runs),
            "rejected_messages": sum(sum(run["failures"].values()) for run in runs),
            "multi_client_release_groups": sum(run["observations"]["release_groups_with_multiple_clients"] for run in runs),
        })
    # Deliberate exhaustion/overload are retained above, but not treated as normal use.
    rankings = {}
    for profile in BUDGETS:
        ranking = []
        for policy in ("budgeted_padding", "chat_batching"):
            selected = [row for row in rows if row["profile"] == profile and row["policy"] == policy
                        and row["scenario"] not in ("budget_exhaustion", "overload")]
            ranking.append({"policy": policy,
                            "numerical_passes": sum(row["numerical_passes"] for row in selected),
                            "runs": sum(row["runs"] for row in selected),
                            "rejected_messages": sum(row["rejected_messages"] for row in selected),
                            "summed_scenario_extra_mb": sum(row["worst_client_extra_mb_per_30_days_median"] for row in selected)})
        rankings[profile] = sorted(ranking, key=lambda item: (-item["numerical_passes"], item["rejected_messages"], item["summed_scenario_extra_mb"]))
    return {"rows": rows, "cost_and_delivery_ranking_only": rankings,
            "anonymity_preserving_recommendation": None}


def study(repeats=5, seed=20260917):
    if type(repeats) is not int or not 1 <= repeats <= 10 or type(seed) is not int or not 0 <= seed < 2**32:
        raise ValueError("repeats must be 1..10; seed must be an unsigned 32-bit integer")
    trials = []
    for repeat in range(repeats):
        for scenario in SCENARIOS:
            generated = workload(scenario, seed + repeat)
            digest = hashlib.sha256(json.dumps(generated, separators=(",", ":")).encode()).hexdigest()
            for profile in BUDGETS:
                for policy in POLICIES:
                    result = simulate(scenario, policy, profile, seed + repeat, generated)
                    result.update(repeat=repeat, workload_sha256=digest)
                    trials.append(result)
    return {
        "schema": 1, "kind": "synthetic_relay_tradeoff_models", "status": "modeled",
        "privacy_verdict": "not_qualified", "seed": seed, "repeats": repeats,
        "model_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "targets": {"extra_bytes_per_30_days_per_device": BUDGETS,
                    "chat_intentional_route_delay_ms": CHAT_DELAY_MS},
        "assumptions": {
            "virtual_duration_ms": DAY_MS, "projection": "repeat the same workload day 30 times",
            "budget_period": "one thirtieth of the monthly cap each day; no borrowing between days, both directions and all modeled device traffic share it",
            "fixed_model_cover": "nominal 4 KiB/100 ms duplex on two outer links; idle contention is not simulated",
            "fixed_model_scheduling": "one client gate, geometric 3 s rounds with p=0.5; not the full production scheduler chain",
            "candidate_cover": "random idle-only client-link records; expected half of daily allowance, shared ledger with message padding",
            "framing": "illustrative 64 bytes per logical message and per aggregate reply, padded to multiples of 4096",
            "aggregation": "batching may share a request/reply; hypothetical format, no GC/1 compatibility claim",
            "chat_delay": "at most 1.5 s client batching plus 1.5 s intermediate batching/shuffle; retries do not repeat intentional shaping",
            "network": "three links, 20 ms propagation per traversal, shared interior serialization queues; no TLS/crypto execution",
            "faults": "one modeled lost reply with one retry for selected jobs; a 30 s first-link pause models reconnect",
            "queue_payload_bound_per_device": QUEUE_BYTES, "inflight_jobs": "one fixed-model, four other models",
            "buffer_accounting": "includes conservatively reserved client batch payload, ready queues and in-flight payload; excludes copies, metadata and crypto state",
            "budget_failure": "reject padded jobs and suppress cover explicitly; no silent unpadded fallback",
            "budget_exhaustion_case": "starts with zero remaining allowance; not a monthly consumption forecast",
        },
        "limitations": [
            "Model outputs are not measured transport throughput, Internet performance or anonymity bounds.",
            "The existing loopback benchmark remains separate; these simplified models are not calibrated to it.",
            "Ordinary overhead is assumed, not measured GC/1 cryptographic, TLS, HTTP2, TCP or handshake overhead.",
            "Link activity and coincident release counts are descriptive, not a both-end correlation or colluding-relay test.",
            "Candidate padding terminates at the first link; terminal activity, online presence and bulk volume remain observable.",
            "Batch aggregation is hypothetical and requires future protocol/receipt compatibility review.",
            "A numerical pass does not establish that the selected low budgets provide worthwhile chat anonymity.",
            "Numerical passes check delivery, budget and intentional delay, not a total-latency service target; congestion can still cause long waits.",
            "Admission allocation pools, fleet scheduling, real connection setup and mobile background delivery are not simulated.",
            "Buffer counts cover modeled payload, not actual process RSS; battery power and device suspension are unmeasured.",
        ],
        "summary": summarize(trials), "trials": trials,
    }


def markdown(report):
    def number(value):
        return "—" if value is None else f"{value:,.2f}"
    rows = ["# Selective chat privacy: synthetic tradeoff study", "",
            "**Models only. Privacy qualification: NOT QUALIFIED.**", "",
            "Targets: 250 MB/mobile and 1,000 MB/desktop additional traffic per 30 days, per device, both directions; at most 3 s intentional chat delay across the route.",
            "Projected traffic repeats each synthetic day 30 times. MB is decimal. The table uses the worst client in each run, then the median across runs.", "",
            "| Device | Workload | Model | Extra MB/month | Chat p95 ms | Bulk KiB/s | Numerical passes | Rejected messages, all runs |",
            "|---|---|---|---:|---:|---:|---:|---:|"]
    for row in report["summary"]["rows"]:
        rows.append(f'| {row["profile"]} | {row["scenario"]} | {row["policy"]} | '
                    f'{number(row["worst_client_extra_mb_per_30_days_median"])} | '
                    f'{number(row["chat_p95_ms_median"])} | {number(row["bulk_goodput_kib_s_median"])} | '
                    f'{row["numerical_passes"]}/{row["runs"]} | {row["rejected_messages"]} |')
    rows += ["", "Latency/goodput describe acknowledged model traffic. Rejections are retained; a fast surviving subset cannot qualify an incomplete run.",
             "", "## Ranking and decision", "",
             "The JSON ranks only cost and delivery among candidates, excluding intentional exhaustion/overload stress cases from the ranking. Those failures remain in the table. It does not rank anonymity.",
             "No anonymity-preserving production recommendation follows. The low budgets require privacy review; batching and random padding are hypotheses, not qualified profiles.",
             "", "## Assumptions and limits", ""]
    rows.extend(f"- {item}" for item in report["limitations"])
    return "\n".join(rows) + "\n"


def write_new(path, text):
    # Stage and fsync before publishing. An ENOSPC cannot truncate prior evidence.
    path = Path(path)
    fd, staged = tempfile.mkstemp(prefix=".tradeoffs-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        os.link(staged, path)  # Exclusive, including when destination is a symlink.
    finally:
        os.unlink(staged)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--markdown", type=Path)
    parser.add_argument("--repeats", type=int, default=5, choices=range(1, 11))
    parser.add_argument("--seed", type=int, default=20260917)
    args = parser.parse_args()
    if args.markdown and args.output.resolve() == args.markdown.resolve():
        parser.error("JSON and Markdown outputs must differ")
    for path in (args.output, args.markdown):
        if path is not None and (path.exists() or path.is_symlink()):
            parser.error(f"refusing to replace existing evidence: {path}")
    report = study(args.repeats, args.seed)
    write_new(args.output, json.dumps(report, indent=2, allow_nan=False) + "\n")
    if args.markdown:
        write_new(args.markdown, markdown(report))
    print(f'Modeled {len(report["trials"])} trials; privacy NOT QUALIFIED.')


if __name__ == "__main__":
    main()
