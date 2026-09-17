#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("relay_tradeoffs", Path(__file__).parents[1] / "relay-tradeoffs.py")
study = importlib.util.module_from_spec(spec)
spec.loader.exec_module(study)


class TradeoffsTest(unittest.TestCase):
    def message(self, number=0, client=0, at=100, size=128, kind="chat"):
        return study.Message(number, client, kind, at, size)

    def test_idle_baseline_matches_independent_nominal_month_cost(self):
        result = study.simulate(study.Scenario("idle"), "fixed_serial_model", "mobile", 1)
        ledger = result["device_ledgers"][0]
        self.assertEqual(ledger["projected_30_day_extra_bytes"], 212_336_640_000)
        self.assertEqual(result["observations"]["link_duplex_bytes"], [7_077_888_000, 7_077_888_000, 0])
        self.assertIn("privacy_budget_exceeded", result["conditions"])
        self.assertEqual(result["privacy_verdict"], "not_qualified")

    def test_budget_boundary_is_exact_and_failed_charge_preserves_balance(self):
        budget = study.Budget(4096)
        self.assertTrue(budget.charge(4096, 10))
        self.assertFalse(budget.charge(1, 11))
        self.assertEqual((budget.spent, budget.first_denial_ms), (4096, 11))
        self.assertFalse(budget.charge(4096, 12))
        self.assertEqual(budget.denials, 2)
        with self.assertRaises(ValueError):
            budget.charge(-1, 13)

    def test_padding_and_protocol_are_separate_and_unpadded_control_has_zero_tax(self):
        job = study.Job((self.message(),), 100)
        self.assertEqual(study.encoding(job, "budgeted_padding"), (4096, 4096, 128, 7936))
        self.assertEqual(study.encoding(job, "unpadded_control"), (192, 64, 128, 0))
        result = study.simulate(study.Scenario("test"), "unpadded_control", "mobile", 1, [self.message()])
        ledger = result["device_ledgers"][0]
        self.assertEqual(ledger["wire_bytes"], 256)
        self.assertEqual(ledger["privacy_extra_bytes"], 0)
        self.assertEqual(result["delivered_messages"], 1)
        # Six propagation delays and three traversals of each wire direction.
        expected_ms = 120 + 256 * 3 * 1000 / 262144
        self.assertAlmostEqual(result["chat_completion_ms"]["median"], expected_ms)

    def test_batching_does_not_cross_clients_or_exceed_total_delay(self):
        messages = [self.message(0, at=0), self.message(1, at=1000),
                    self.message(2, client=1, at=1000), self.message(3, at=3000)]
        jobs = study.jobs_for(messages, "chat_batching")
        self.assertEqual(len(jobs), 3)
        self.assertEqual(sum(len(job.messages) for job in jobs), 4)
        for job in jobs:
            self.assertEqual(len({message.client for message in job.messages}), 1)
            for message in job.messages:
                self.assertLessEqual(job.ready_ms - message.at_ms, 3000)
                self.assertGreaterEqual(job.ready_ms - message.at_ms, 0)
        self.assertEqual(len(jobs[0].messages), 2)

    def test_batching_reduces_burst_padding_without_losing_messages(self):
        messages = [self.message(index, at=1000 + index * 20) for index in range(20)]
        with patch.object(study, "DAY_MS", 10_000):
            # Keep this unit test small; the independent quota tests use full days.
            plain = study.simulate(study.Scenario("test"), "budgeted_padding", "mobile", 9, messages)
            batch = study.simulate(study.Scenario("test"), "chat_batching", "mobile", 9, messages)
        self.assertEqual(batch["delivered_messages"], 20)
        self.assertLess(batch["device_ledgers"][0]["privacy_padding_bytes"],
                        plain["device_ledgers"][0]["privacy_padding_bytes"] / 10)
        self.assertLessEqual(batch["chat_intentional_delay_ms"]["max"], 3000)

    def test_exhaustion_never_silently_sends_unpadded_chat(self):
        scenario = study.Scenario("test", exhausted=True)
        for policy in ("budgeted_padding", "chat_batching"):
            result = study.simulate(scenario, policy, "mobile", 3, [self.message()])
            self.assertEqual(result["delivered_messages"], 0)
            self.assertEqual(result["failures"], {"privacy_budget": 1})
            self.assertEqual(result["device_ledgers"][0]["wire_bytes"], 0)
            self.assertIsNone(result["device_ledgers"][0]["projected_30_day_extra_bytes"])
            self.assertIn("privacy_budget_exhausted", result["conditions"])
            self.assertFalse(result["numerical_targets_met"])

    def test_both_directions_cover_and_message_padding_share_device_budget(self):
        result = study.simulate(study.Scenario("shared_population", clients=8), "chat_batching", "mobile", 2)
        for ledger in result["device_ledgers"]:
            self.assertEqual(ledger["privacy_extra_bytes"], ledger["dummy_bytes"] + ledger["privacy_padding_bytes"])
            self.assertLessEqual(ledger["privacy_extra_bytes"], 250_000_000 // 30)
            self.assertEqual(ledger["wire_bytes"], ledger["privacy_extra_bytes"] +
                             ledger["ordinary_protocol_bytes"] + ledger["payload_transmission_bytes"])
        self.assertEqual(sum(ledger["wire_bytes"] for ledger in result["device_ledgers"]),
                         result["observations"]["link_duplex_bytes"][0])

    def test_loss_retries_charge_bytes_but_do_not_double_count_delivery(self):
        message = self.message()
        result = study.simulate(study.Scenario("test", loss_every=1), "unpadded_control", "mobile", 4, [message])
        self.assertEqual(result["delivered_messages"], 1)
        ledger = result["device_ledgers"][0]
        self.assertEqual(ledger["payload_transmission_bytes"], 256)
        self.assertEqual(ledger["retransmitted_payload_bytes"], 128)
        self.assertEqual(ledger["wire_bytes"], 512)
        self.assertEqual(result["counters"]["modeled_reply_losses"], 1)
        self.assertGreater(result["chat_completion_ms"]["median"], 500)

    def test_reconnect_wait_is_not_misreported_as_privacy_delay(self):
        result = study.simulate(study.Scenario("test", outage_ms=(0, 30_000)),
                                "unpadded_control", "desktop", 5, [self.message()])
        self.assertGreater(result["chat_completion_ms"]["max"], 29_000)
        self.assertEqual(result["chat_intentional_delay_ms"]["max"], 0)
        self.assertGreater(result["counters"]["outage_deferrals"], 0)

    def test_overload_is_bounded_and_retained_in_summary(self):
        result = study.simulate(study.Scenario("overload"), "unpadded_control", "desktop", 6)
        self.assertGreater(result["failures"].get("queue_capacity", 0), 0)
        self.assertLessEqual(result["peak_buffered_payload_bytes_per_client"], study.QUEUE_BYTES + 4 * study.CHUNK_BYTES)
        summary = study.summarize([result])
        self.assertGreater(summary["rows"][0]["rejected_messages"], 0)
        self.assertEqual(summary["rows"][0]["numerical_passes"], 0)

    def test_solo_release_is_not_a_mixing_or_anonymity_claim(self):
        result = study.simulate(study.Scenario("sparse_chat"), "chat_batching", "mobile", 7)
        self.assertEqual(result["observations"]["release_groups_with_multiple_clients"], 0)
        self.assertFalse(result["observations"]["both_end_linkage_evaluated"])
        self.assertEqual(result["privacy_verdict"], "not_qualified")

    def test_intermediate_batch_groups_different_clients_with_bounded_total_delay(self):
        messages = [self.message(0, client=0, at=0), self.message(1, client=1, at=0)]
        result = study.simulate(study.Scenario("test", clients=2), "chat_batching", "mobile", 3, messages)
        self.assertEqual(result["delivered_messages"], 2)
        self.assertEqual(result["observations"]["release_groups_with_multiple_clients"], 1)
        self.assertGreater(result["chat_intentional_delay_ms"]["max"], study.BATCH_MS)
        self.assertLessEqual(result["chat_intentional_delay_ms"]["max"], study.CHAT_DELAY_MS)
        self.assertGreater(result["chat_completion_ms"]["max"], study.CHAT_DELAY_MS)

    def test_retry_does_not_repeat_intentional_shaping(self):
        messages = [self.message(at=0)]
        normal = study.simulate(study.Scenario("test"), "chat_batching", "mobile", 3, messages)
        retry = study.simulate(study.Scenario("test", loss_every=1), "chat_batching", "mobile", 3, messages)
        self.assertEqual(normal["chat_intentional_delay_ms"], retry["chat_intentional_delay_ms"])
        self.assertEqual(retry["observations"]["chat_release_groups"], 1)
        self.assertEqual(retry["counters"]["modeled_reply_losses"], 1)
        self.assertGreater(retry["chat_completion_ms"]["max"], normal["chat_completion_ms"]["max"])

    def test_held_batches_count_toward_buffer_limit_before_release(self):
        messages = [self.message(index, at=100, size=400) for index in range(5)]
        with patch.object(study, "CHUNK_BYTES", 1000), patch.object(study, "QUEUE_BYTES", 1000):
            result = study.simulate(study.Scenario("test"), "chat_batching", "mobile", 3, messages)
        self.assertEqual(result["delivered_messages"], 2)
        self.assertEqual(result["failures"], {"queue_capacity": 3})
        self.assertEqual(result["peak_buffered_payload_bytes_per_client"], 800)

    def test_shared_hop_serializes_in_arrival_order_not_origin_order(self):
        large = self.message(0, client=0, at=0, size=16000)
        small = self.message(1, client=1, at=1, size=1)
        model = study.Model(study.Scenario("test", clients=2), "unpadded_control", "mobile", 3, (large, small))
        starts = []
        original = model.hop

        def record(now, transfer):
            if transfer[3:5] == (0, 1):
                starts.append(transfer[1])
            return original(now, transfer)

        model.hop = record
        result = model.run()
        self.assertEqual(result["delivered_messages"], 2)
        self.assertEqual(starts, [1, 0])

    def test_models_are_reproducible_and_workloads_are_matched(self):
        with patch.object(study, "SCENARIOS", (study.Scenario("sparse_chat"),)):
            first = study.study(repeats=1, seed=8)
            second = study.study(repeats=1, seed=8)
        self.assertEqual(first, second)
        self.assertEqual(len({trial["workload_sha256"] for trial in first["trials"]}), 1)
        self.assertIn("NOT QUALIFIED", study.markdown(first))
        self.assertIsNone(first["summary"]["anonymity_preserving_recommendation"])
        json.dumps(first, allow_nan=False)

    def test_invalid_inputs_fail_before_simulation(self):
        for repeats in (0, 11, True):
            with self.assertRaises(ValueError):
                study.study(repeats=repeats)
        with self.assertRaises(ValueError):
            study.study(seed=-1)
        for messages in ([self.message(), self.message()], [self.message(size=-1)], [self.message(at=float("nan"))]):
            with self.assertRaises(ValueError):
                study.simulate(study.Scenario("test"), "unpadded_control", "mobile", 1, messages)

    def test_evidence_is_exclusive_private_and_failed_write_does_not_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            study.write_new(path, "original")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                study.write_new(path, "replacement")
            self.assertEqual(path.read_text(), "original")
            failed = Path(directory) / "failed.json"
            with patch.object(study.os, "fsync", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    study.write_new(failed, "incomplete")
            self.assertFalse(failed.exists())
            self.assertEqual(sorted(p.name for p in Path(directory).iterdir()), ["result.json"])


if __name__ == "__main__":
    unittest.main()
