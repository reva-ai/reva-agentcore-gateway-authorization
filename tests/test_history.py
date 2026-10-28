import os
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from unittest import mock

from interceptor.history import (APPENDED, DUPLICATE, MAX_HOPS_READ, DynamoStore, MemoryStore,
                                 StoreError, paired_history)

from .support import settings


def hop(n: int, **extra):
    base = {"span": f"span{n}", "subject": {"type": "User", "id": "u1"},
            "action": "invokeTool", "resource": {"type": "Tool", "id": f"s/t{n}"},
            "time": f"2026-10-27T08:00:{n % 60:02d}.{n // 60:06d}Z", "role": "assistant",
            "content": f"call {n}"}
    base.update(extra)
    return base


class MemoryStoreBehaviour(unittest.TestCase):
    def setUp(self):
        self.clock = [1000.0]
        self.store = MemoryStore(settings(), now=lambda: self.clock[0])

    def test_establish_is_first_writer_wins(self):
        first = self.store.establish("t1", "alice", ["g"], "chat", 1, "2026-01-01T00:00:00Z")
        second = self.store.establish("t1", "mallory", [], "other", 9, "2030-01-01T00:00:00Z")
        self.assertEqual(second["principal"], "alice")
        self.assertEqual((second["thread_id"], second["turn"]), ("chat", 1))
        self.assertEqual(first, second)

    def test_turn_advances_once_per_trace(self):
        self.assertEqual(self.store.claim_turn("chat", "t1")[0], 1)
        self.assertEqual(self.store.claim_turn("chat", "t1")[0], 1)    # same trace, same turn
        self.assertEqual(self.store.claim_turn("chat", "t2")[0], 2)
        self.assertEqual(self.store.claim_turn("other-chat", "t3")[0], 1)
        started = self.store.claim_turn("chat", "t3")[1]
        self.assertEqual(started, self.store.claim_turn("chat", "t1")[1])  # chat start is stable

    def test_turn_is_clamped_at_the_thread_cap(self):
        store = MemoryStore(replace(settings(), max_threads_traces=2))
        for trace in ("a", "b", "c"):
            turn = store.claim_turn("chat", trace)[0]
        self.assertEqual(turn, 2)

    def test_append_is_idempotent_per_span(self):
        self.assertEqual(self.store.append_hop("t1", hop(1)), APPENDED)
        self.assertEqual(self.store.append_hop("t1", hop(1)), DUPLICATE)
        self.assertEqual(len(self.store.get_trace("t1")["hops"]), 1)

    def test_hops_come_back_in_time_order_whatever_order_they_were_written(self):
        for n in (3, 1, 2):
            self.store.append_hop("t1", hop(n))
        self.assertEqual([h["span"] for h in self.store.get_trace("t1")["hops"]],
                         ["span1", "span2", "span3"])

    def test_a_hop_written_before_the_header_is_still_read(self):
        self.store.append_hop("t1", hop(1))
        record = self.store.get_trace("t1")
        self.assertEqual((record["principal"], len(record["hops"])), ("", 1))
        self.store.establish("t1", "alice", [], "chat", 1, "S")
        record = self.store.get_trace("t1")
        self.assertEqual((record["principal"], len(record["hops"])), ("alice", 1))

    def test_nothing_written_reads_as_no_record(self):
        self.assertIsNone(self.store.get_trace("unknown"))

    def test_a_read_is_bounded(self):
        for n in range(MAX_HOPS_READ + 50):
            self.store.append_hop("t1", hop(n))
        self.assertEqual(len(self.store.get_trace("t1")["hops"]), MAX_HOPS_READ)

    def test_parallel_appends_lose_nothing(self):
        with ThreadPoolExecutor(max_workers=20) as pool:
            list(pool.map(lambda n: self.store.append_hop("t1", hop(n)), range(20)))
        self.assertEqual(len(self.store.get_trace("t1")["hops"]), 20)

    def test_the_same_span_from_many_threads_is_recorded_once(self):
        with ThreadPoolExecutor(max_workers=20) as pool:
            outcomes = list(pool.map(lambda _: self.store.append_hop("t1", hop(1)), range(20)))
        self.assertEqual(outcomes.count(APPENDED), 1)
        self.assertEqual(len(self.store.get_trace("t1")["hops"]), 1)

    def test_turns_are_unique_under_parallel_first_calls(self):
        with ThreadPoolExecutor(max_workers=10) as pool:
            turns = list(pool.map(lambda n: self.store.claim_turn("chat", f"t{n}")[0],
                                  range(10)))
        self.assertEqual(sorted(turns), list(range(1, 11)))

    def test_expired_rows_are_not_state(self):
        self.store.establish("t1", "alice", [], "chat", 1, "s")
        self.store.append_hop("t1", hop(1))
        self.assertIsNotNone(self.store.get_trace("t1"))
        self.clock[0] += settings().trace_ttl_seconds + 1
        self.assertIsNone(self.store.get_trace("t1"))


class PairedHistory(unittest.TestCase):
    def test_hops_and_messages_always_match_and_share_seq(self):
        hops, messages = paired_history([hop(1), hop(2), hop(3)], "none", 30)
        self.assertEqual([h["seq"] for h in hops], [1, 2, 3])
        self.assertEqual([m["seq"] for m in messages], [1, 2, 3])
        self.assertEqual(messages[0], {"seq": 1, "role": "assistant", "contentType": "text/plain",
                                       "content": "call 1", "timestamp": hop(1)["time"]})
        self.assertEqual(hops[0]["action"], "invokeTool")          # a bare string
        self.assertEqual(set(hops[0]), {"seq", "subject", "action", "resource", "time"})

    def test_the_call_under_evaluation_is_never_its_own_history(self):
        hops, messages = paired_history([hop(1), hop(2), hop(3)], "span2", 30)
        self.assertEqual([h["resource"]["id"] for h in hops], ["s/t1", "s/t3"])
        self.assertEqual([h["seq"] for h in hops], [1, 2])
        self.assertEqual(len(hops), len(messages))

    def test_past_the_cap_the_first_and_newest_are_kept_and_renumbered(self):
        stored = [hop(n) for n in range(1, 41)]
        hops, messages = paired_history(stored, "none", 30)
        self.assertEqual(len(hops), 30)
        self.assertEqual(hops[0]["resource"]["id"], "s/t1")        # where the prompt began
        self.assertEqual(hops[-1]["resource"]["id"], "s/t40")
        self.assertEqual([h["seq"] for h in hops], list(range(1, 31)))
        self.assertEqual(len(messages), 30)

    def test_empty_content_falls_back_to_the_action_and_resource(self):
        _, messages = paired_history([hop(1, content="")], "none", 30)
        self.assertEqual(messages[0]["content"], "invokeTool s/t1")

    def test_nothing_stored(self):
        self.assertEqual(paired_history([], "x", 30), ([], []))


class FakeTable:
    """Just enough of a boto3 Table to prove how DynamoStore reacts to the service."""

    def __init__(self):
        self.calls = []
        self.responses = []

    def _call(self, name, kwargs):
        self.calls.append((name, kwargs))
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    def update_item(self, **kwargs):
        return self._call("update_item", kwargs)

    def get_item(self, **kwargs):
        return self._call("get_item", kwargs)

    def put_item(self, **kwargs):
        return self._call("put_item", kwargs)

    def query(self, **kwargs):
        return self._call("query", kwargs)


def conditional_failure():
    from botocore.exceptions import ClientError
    return ClientError({"Error": {"Code": "ConditionalCheckFailedException",
                                  "Message": "The conditional request failed"}}, "PutItem")


def other_failure():
    from botocore.exceptions import ClientError
    return ClientError({"Error": {"Code": "AccessDeniedException",
                                  "Message": "not authorized"}}, "PutItem")


META_ROW = {"pk": "TR#t1", "sk": "#META", "principal": "alice", "groups": ["g"],
            "thread_id": "chat", "turn": 3, "started_at": "S", "expires_at": 2000}


def hop_row(n, **extra):
    h = hop(n)
    row = {"pk": "TR#t1", "sk": f"HOP#{h['span']}", "received_at": h["time"],
           "subject": h["subject"], "action": h["action"], "resource": h["resource"],
           "role": h["role"], "content": h["content"], "expires_at": 2000}
    row.update(extra)
    return row


class DynamoStoreBehaviour(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        self.store = DynamoStore(self.table, settings(), now=lambda: 1000.0)

    def test_claim_turn_first_call(self):
        self.table.responses = [{"Attributes": {"traces": ["t0", "t1"],
                                                "started_at": "2026-01-01T00:00:00Z"}}]
        self.assertEqual(self.store.claim_turn("chat", "t1"), (2, "2026-01-01T00:00:00Z"))
        name, call = self.table.calls[0]
        self.assertEqual(name, "update_item")
        self.assertEqual(call["Key"], {"pk": "TH#chat", "sk": "#META"})
        self.assertIn("NOT contains(#t, :trace)", call["ConditionExpression"])
        self.assertEqual(call["ReturnValues"], "UPDATED_NEW")
        self.assertEqual(call["ExpressionAttributeValues"][":exp"], 1000 + 86400)

    def test_claim_turn_for_a_trace_already_on_the_thread_reads_its_turn(self):
        self.table.responses = [conditional_failure(),
                                {"Item": {"traces": ["t0", "t1", "t2"], "started_at": "S"}}]
        self.assertEqual(self.store.claim_turn("chat", "t1"), (2, "S"))
        self.assertEqual(self.table.calls[1][1]["ConsistentRead"], True)

    def test_claim_turn_at_the_cap_is_clamped(self):
        self.table.responses = [conditional_failure(), {"Item": {"traces": ["a", "b"]}}]
        self.assertEqual(self.store.claim_turn("chat", "new")[0], 2)

    def test_establish_writes_the_header_row_only_if_absent(self):
        self.table.responses = [{}]
        record = self.store.establish("t1", "alice", ["g"], "chat", 2, "S")
        self.assertEqual((record["principal"], record["turn"], record["hops"]), ("alice", 2, []))
        name, call = self.table.calls[0]
        self.assertEqual(name, "put_item")
        item = call["Item"]
        self.assertEqual((item["pk"], item["sk"]), ("TR#t1", "#META"))
        self.assertEqual((item["principal"], item["thread_id"], item["turn"]),
                         ("alice", "chat", 2))
        self.assertEqual(item["expires_at"], 1000 + 3600)
        self.assertEqual(call["ConditionExpression"], "attribute_not_exists(#pk)")
        self.assertEqual(call["ExpressionAttributeNames"], {"#pk": "pk"})

    def test_establish_that_loses_a_race_adopts_the_stored_header(self):
        self.table.responses = [conditional_failure(),
                                {"Item": dict(META_ROW, principal="first-writer", turn=1)}]
        record = self.store.establish("t1", "second-writer", [], "other", 9, "X")
        self.assertEqual((record["principal"], record["turn"]), ("first-writer", 1))
        self.assertEqual(self.table.calls[1][0], "get_item")
        self.assertEqual(self.table.calls[1][1]["Key"], {"pk": "TR#t1", "sk": "#META"})

    def test_append_hop_is_one_conditional_put_of_its_own_row(self):
        self.table.responses = [{}]
        self.assertEqual(self.store.append_hop("t1", hop(1)), APPENDED)
        name, call = self.table.calls[0]
        self.assertEqual(name, "put_item")
        item = call["Item"]
        self.assertEqual((item["pk"], item["sk"]), ("TR#t1", "HOP#span1"))
        self.assertEqual((item["received_at"], item["role"], item["content"]),
                         (hop(1)["time"], "assistant", "call 1"))
        self.assertEqual(item["subject"], {"type": "User", "id": "u1"})
        self.assertEqual(item["expires_at"], 1000 + 3600)
        self.assertEqual(call["ConditionExpression"], "attribute_not_exists(#pk)")
        self.assertEqual(len(self.table.calls), 1)                 # no read-modify-write

    def test_append_hop_for_a_span_already_there_is_a_duplicate(self):
        self.table.responses = [conditional_failure()]
        self.assertEqual(self.store.append_hop("t1", hop(1)), DUPLICATE)
        self.assertEqual(len(self.table.calls), 1)

    def test_get_trace_is_one_consistent_bounded_query(self):
        self.table.responses = [{"Items": [META_ROW, hop_row(2), hop_row(1)]}]
        record = self.store.get_trace("t1")
        name, call = self.table.calls[0]
        self.assertEqual(name, "query")
        self.assertEqual(call["KeyConditionExpression"], "#pk = :pk")
        self.assertEqual(call["ExpressionAttributeValues"], {":pk": "TR#t1"})
        self.assertEqual(call["ConsistentRead"], True)
        self.assertEqual(call["Limit"], MAX_HOPS_READ + 1)
        self.assertEqual((record["principal"], record["groups"], record["turn"]),
                         ("alice", ["g"], 3))
        self.assertEqual([h["span"] for h in record["hops"]], ["span1", "span2"])  # by time
        self.assertEqual(record["hops"][0]["time"], hop(1)["time"])

    def test_get_trace_follows_a_page_boundary(self):
        self.table.responses = [{"Items": [META_ROW], "LastEvaluatedKey": {"pk": "TR#t1", "sk": "#META"}},
                                {"Items": [hop_row(1)]}]
        record = self.store.get_trace("t1")
        self.assertEqual(len(record["hops"]), 1)
        self.assertEqual(self.table.calls[1][1]["ExclusiveStartKey"],
                         {"pk": "TR#t1", "sk": "#META"})

    def test_get_trace_ignores_expired_rows_and_reports_none_when_nothing_is_left(self):
        self.table.responses = [{"Items": [dict(META_ROW, expires_at=999), hop_row(1)]}]
        record = self.store.get_trace("t1")
        self.assertEqual((record["principal"], len(record["hops"])), ("", 1))
        self.table.responses = [{"Items": [dict(META_ROW, expires_at=999),
                                           hop_row(1, expires_at=999)]}]
        self.assertIsNone(self.store.get_trace("t1"))
        self.table.responses = [{"Items": []}]
        self.assertIsNone(self.store.get_trace("t1"))

    def test_service_errors_become_store_errors(self):
        self.table.responses = [other_failure()]
        with self.assertRaises(StoreError):
            self.store.append_hop("t1", hop(1))
        self.table.responses = [other_failure()]
        with self.assertRaises(StoreError):
            self.store.get_trace("t1")
        self.table.responses = [other_failure()]
        with self.assertRaises(StoreError):
            self.store.establish("t1", "alice", [], "chat", 1, "S")
        self.table.responses = [other_failure()]
        with self.assertRaises(StoreError):
            self.store.claim_turn("chat", "t1")

    def test_custom_key_attribute_names(self):
        store = DynamoStore(self.table, replace(settings(), history_pk_attr="trace",
                                                history_sk_attr="part"))
        self.table.responses = [{}]
        store.append_hop("t1", hop(1))
        call = self.table.calls[0][1]
        self.assertEqual((call["Item"]["trace"], call["Item"]["part"]), ("TR#t1", "HOP#span1"))
        self.assertEqual(call["ExpressionAttributeNames"], {"#pk": "trace"})


class DynamoExpressionsAreValidAgainstTheServiceModel(unittest.TestCase):
    """botocore's Stubber validates every request against the DynamoDB API model, so a
    wrong parameter name or value type fails here. It cannot judge expression
    semantics; that is checked by the first live run."""

    def setUp(self):
        try:
            import boto3
            from botocore.stub import Stubber
        except ImportError:                                  # pragma: no cover
            self.skipTest("boto3 is not installed")
        env = {"AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "x",
               "AWS_DEFAULT_REGION": "us-west-2"}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        table = boto3.resource("dynamodb").Table("table")
        self.stubber = Stubber(table.meta.client)
        self.stubber.activate()
        self.addCleanup(self.stubber.deactivate)
        self.store = DynamoStore(table, settings(), now=lambda: 1000.0)

    def test_every_operation_builds_a_valid_request(self):
        self.stubber.add_response("update_item", {"Attributes": {
            "traces": {"L": [{"S": "t1"}]}, "started_at": {"S": "S"}}})
        self.assertEqual(self.store.claim_turn("chat", "t1")[0], 1)

        self.stubber.add_response("put_item", {})
        self.assertEqual(self.store.establish("t1", "alice", ["g"], "chat", 1, "S")["principal"],
                         "alice")

        self.stubber.add_response("put_item", {})
        self.assertEqual(self.store.append_hop("t1", hop(1)), APPENDED)

        self.stubber.add_client_error("put_item", "ConditionalCheckFailedException")
        self.assertEqual(self.store.append_hop("t1", hop(1)), DUPLICATE)

        self.stubber.add_response("query", {"Items": [
            {"pk": {"S": "TR#t1"}, "sk": {"S": "#META"}, "principal": {"S": "alice"},
             "turn": {"N": "1"}, "expires_at": {"N": "2000"}},
            {"pk": {"S": "TR#t1"}, "sk": {"S": "HOP#span1"}, "received_at": {"S": "t"},
             "action": {"S": "invokeTool"}, "role": {"S": "assistant"}, "content": {"S": "c"},
             "subject": {"M": {"type": {"S": "User"}, "id": {"S": "u1"}}},
             "resource": {"M": {"type": {"S": "Tool"}, "id": {"S": "s/t"}}},
             "expires_at": {"N": "2000"}}], "Count": 2})
        record = self.store.get_trace("t1")
        self.assertEqual((record["principal"], record["turn"], len(record["hops"])),
                         ("alice", 1, 1))

        self.stubber.add_client_error("put_item", "ConditionalCheckFailedException")
        self.stubber.add_response("get_item", {"Item": {
            "pk": {"S": "TR#t1"}, "sk": {"S": "#META"}, "principal": {"S": "first"},
            "turn": {"N": "1"}}})
        self.assertEqual(self.store.establish("t1", "second", [], "chat", 1, "S")["principal"],
                         "first")
        self.stubber.assert_no_pending_responses()


if __name__ == "__main__":
    unittest.main()
