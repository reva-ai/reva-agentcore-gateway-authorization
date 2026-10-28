"""Trace state in DynamoDB: who the trace is for, which chat it belongs to, and the hops so far.

The RTG judges a hop against what came before it in the same prompt, and a Lambda
keeps nothing between calls, so that state lives in a table. The layout mirrors the
RTG's own `trace_hop` table: one row per hop, plus one header row per trace.

    partition        sort            attributes
    TR#<trace id>    #META           principal, groups, thread_id, turn, started_at
    TR#<trace id>    HOP#<span id>   received_at, subject, action, resource, role, content
    TH#<thread id>   #META           traces [trace ids in arrival order], started_at

Every row has `expires_at` (a TTL attribute). The partition and sort attribute NAMES
are configurable (default `pk` and `sk`); the table needs a string partition key and a
string sort key.

Rules that keep it correct under concurrency and gateway retries:

  * Every write is ONE atomic call on ONE row. Parallel tool calls of one prompt each
    write their own hop row, so nothing is read-modified-written and nothing is lost.
  * A hop row is keyed by its span id and written only if absent: a gateway retry of
    the same call is a no-op, like the RTG's `ON CONFLICT DO NOTHING`.
  * The first call of a trace writes the header row BEFORE the RTG is asked
    (`establish`), only if absent, so a parallel hop or a retry after a denied first
    call finds the principal and thread. If two first calls race, the first writer wins
    and both adopt it.
  * The turn advances once per trace, not per call (`claim_turn`).
  * A hop is recorded only AFTER it is permitted, and the call under evaluation is
    never part of its own history.
  * One Query reads the header and the hops together. `#META` sorts before `HOP#`, so a
    bounded read always includes the header.
"""

from __future__ import annotations

import threading
import time
from decimal import Decimal
from typing import Any, Callable, Dict, List, Optional, Tuple

from .config import Settings
from .util import iso_now

APPENDED, DUPLICATE = "appended", "duplicate"

META = "#META"
HOP_PREFIX = "HOP#"
# A safety cap on what one call reads, like the RTG's own 200-hop read cap. A trace
# longer than this reads an arbitrary 200 hop rows; `paired_history` keeps the
# first and newest 30 of what was read.
MAX_HOPS_READ = 200


class StoreError(Exception):
    """The table could not be read or written."""


def _code(exc: Exception) -> str:
    return ((getattr(exc, "response", None) or {}).get("Error") or {}).get("Code", "")


def _native(value: Any) -> Any:
    """DynamoDB hands numbers back as Decimal and sets as set; make both plain."""
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, dict):
        return {k: _native(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_native(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted(_native(v) for v in value)
    return value


def _record(meta: Dict[str, Any], hops: List[Dict[str, Any]]) -> Dict[str, Any]:
    ordered = sorted(hops, key=lambda h: (h.get("time") or "", h.get("span") or ""))
    return {
        "principal": str(meta.get("principal") or ""),
        "groups": [str(g) for g in meta.get("groups") or []],
        "thread_id": str(meta.get("thread_id") or ""),
        "turn": int(meta.get("turn") or 1),
        "started_at": str(meta.get("started_at") or ""),
        "hops": ordered,
    }


def _hop_from_row(row: Dict[str, Any], span: str) -> Dict[str, Any]:
    return {"span": span, "subject": row.get("subject"), "action": row.get("action"),
            "resource": row.get("resource"), "time": row.get("received_at"),
            "role": row.get("role"), "content": row.get("content")}


class DynamoStore:
    def __init__(self, table: Any, cfg: Settings, now: Callable[[], float] = time.time):
        self.table = table
        self.pk = cfg.history_pk_attr
        self.sk = cfg.history_sk_attr
        self.trace_ttl = cfg.trace_ttl_seconds
        self.thread_ttl = cfg.thread_ttl_seconds
        self.max_traces = cfg.max_threads_traces
        self._now = now

    def _key(self, partition: str, sort: str) -> Dict[str, str]:
        return {self.pk: partition, self.sk: sort}

    def get_trace(self, trace_id: str) -> Optional[Dict[str, Any]]:
        """The trace's header and hops in one consistent Query, or None if it has neither."""
        query: Dict[str, Any] = {
            "KeyConditionExpression": "#pk = :pk",
            "ExpressionAttributeNames": {"#pk": self.pk},
            "ExpressionAttributeValues": {":pk": f"TR#{trace_id}"},
            "ConsistentRead": True,
            "Limit": MAX_HOPS_READ + 1,           # the header plus up to MAX_HOPS_READ hops
        }
        rows: List[Dict[str, Any]] = []
        try:
            while True:
                page = self.table.query(**query)
                rows.extend(page.get("Items") or [])
                last = page.get("LastEvaluatedKey")
                if not last or len(rows) > MAX_HOPS_READ:
                    break
                query["ExclusiveStartKey"] = last
        except Exception as exc:  # noqa: BLE001
            raise StoreError(f"get_trace: {exc}") from exc

        meta: Optional[Dict[str, Any]] = None
        hops: List[Dict[str, Any]] = []
        for raw in rows:
            row = _native(raw)
            # DynamoDB TTL deletion can lag by up to 48 hours; an expired row is not state.
            expires = row.get("expires_at")
            if isinstance(expires, (int, float)) and expires <= self._now():
                continue
            sort = str(row.get(self.sk) or "")
            if sort == META:
                meta = row
            elif sort.startswith(HOP_PREFIX):
                hops.append(_hop_from_row(row, sort[len(HOP_PREFIX):]))
        if meta is None and not hops:
            return None
        return _record(meta or {}, hops)

    def claim_turn(self, thread_id: str, trace_id: str) -> Tuple[int, str]:
        """(turn, chat start) for this trace on its thread. The first call of a trace
        appends it to the thread's list; any later call finds it already there."""
        key = self._key(f"TH#{thread_id}", META)
        now_iso = iso_now()
        try:
            result = self.table.update_item(
                Key=key,
                UpdateExpression=("SET #t = list_append(if_not_exists(#t, :empty), :one), "
                                  "#sa = if_not_exists(#sa, :now), #x = :exp"),
                ConditionExpression=("(attribute_not_exists(#t) OR NOT contains(#t, :trace)) "
                                     "AND (attribute_not_exists(#t) OR size(#t) < :cap)"),
                ExpressionAttributeNames={"#t": "traces", "#sa": "started_at",
                                          "#x": "expires_at"},
                ExpressionAttributeValues={
                    ":empty": [], ":one": [trace_id], ":trace": trace_id, ":now": now_iso,
                    ":exp": int(self._now()) + self.thread_ttl, ":cap": self.max_traces},
                ReturnValues="UPDATED_NEW",
            )
            attrs = _native(result["Attributes"])
            return len(attrs["traces"]), str(attrs.get("started_at") or now_iso)
        except Exception as exc:  # noqa: BLE001
            if _code(exc) != "ConditionalCheckFailedException":
                raise StoreError(f"claim_turn: {exc}") from exc
        try:
            item = _native(self.table.get_item(Key=key, ConsistentRead=True).get("Item") or {})
        except Exception as exc:  # noqa: BLE001
            raise StoreError(f"claim_turn read: {exc}") from exc
        traces = list(item.get("traces") or [])
        turn = traces.index(trace_id) + 1 if trace_id in traces else max(len(traces), 1)
        return turn, str(item.get("started_at") or now_iso)

    def establish(self, trace_id: str, principal: str, groups: List[str], thread_id: str,
                  turn: int, started_at: str) -> Dict[str, Any]:
        """Write the trace's header row once; return what is stored (the first writer's)."""
        key = self._key(f"TR#{trace_id}", META)
        item = dict(key, principal=principal, groups=list(groups), thread_id=thread_id,
                    turn=turn, started_at=started_at,
                    expires_at=int(self._now()) + self.trace_ttl)
        try:
            self.table.put_item(Item=item, ConditionExpression="attribute_not_exists(#pk)",
                                ExpressionAttributeNames={"#pk": self.pk})
            return _record(item, [])
        except Exception as exc:  # noqa: BLE001
            if _code(exc) != "ConditionalCheckFailedException":
                raise StoreError(f"establish: {exc}") from exc
        try:
            stored = self.table.get_item(Key=key, ConsistentRead=True).get("Item")
        except Exception as exc:  # noqa: BLE001
            raise StoreError(f"establish read: {exc}") from exc
        return _record(_native(stored) if stored else item, [])

    def append_hop(self, trace_id: str, hop: Dict[str, Any]) -> str:
        """Record a permitted hop in its own row, only if this span is not already there."""
        item = dict(self._key(f"TR#{trace_id}", HOP_PREFIX + hop["span"]),
                    received_at=hop["time"], subject=hop["subject"], action=hop["action"],
                    resource=hop["resource"], role=hop["role"], content=hop["content"],
                    expires_at=int(self._now()) + self.trace_ttl)
        try:
            self.table.put_item(Item=item, ConditionExpression="attribute_not_exists(#pk)",
                                ExpressionAttributeNames={"#pk": self.pk})
            return APPENDED
        except Exception as exc:  # noqa: BLE001
            if _code(exc) == "ConditionalCheckFailedException":
                return DUPLICATE
            raise StoreError(f"append_hop: {exc}") from exc


class MemoryStore:
    """The same behaviour in a dict, for tests and local runs. Lock-protected so a
    thread-pool test exercises the same atomicity the table gives."""

    def __init__(self, cfg: Settings, now: Callable[[], float] = time.time):
        self.cfg = cfg
        self._now = now
        self._lock = threading.Lock()
        # trace id -> {"meta": header row or None, "hops": {span id: hop row}}
        self.traces: Dict[str, Dict[str, Any]] = {}
        self.threads: Dict[str, Dict[str, Any]] = {}

    def get_trace(self, trace_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            entry = self.traces.get(trace_id)
            if not entry:
                return None
            now = self._now()
            meta = entry["meta"] if entry["meta"] and entry["meta"]["expires_at"] > now else None
            # The table returns hop rows in sort-key (span id) order and a bounded read
            # stops at MAX_HOPS_READ: do the same.
            rows = [(span, hop) for span, hop in sorted(entry["hops"].items())
                    if hop["expires_at"] > now][:MAX_HOPS_READ]
            hops = [_hop_from_row({"subject": h["subject"], "action": h["action"],
                                   "resource": h["resource"], "received_at": h["time"],
                                   "role": h["role"], "content": h["content"]}, span)
                    for span, h in rows]
            if meta is None and not hops:
                return None
            return _record(dict(meta or {}), hops)

    def claim_turn(self, thread_id: str, trace_id: str) -> Tuple[int, str]:
        with self._lock:
            item = self.threads.setdefault(thread_id, {"traces": [], "started_at": iso_now()})
            if trace_id not in item["traces"] and len(item["traces"]) < self.cfg.max_threads_traces:
                item["traces"].append(trace_id)
            item["expires_at"] = int(self._now()) + self.cfg.thread_ttl_seconds
            if trace_id in item["traces"]:
                return item["traces"].index(trace_id) + 1, item["started_at"]
            return max(len(item["traces"]), 1), item["started_at"]

    def establish(self, trace_id: str, principal: str, groups: List[str], thread_id: str,
                  turn: int, started_at: str) -> Dict[str, Any]:
        with self._lock:
            entry = self.traces.setdefault(trace_id, {"meta": None, "hops": {}})
            if entry["meta"] is None or entry["meta"]["expires_at"] <= self._now():
                entry["meta"] = {"principal": principal, "groups": list(groups),
                                 "thread_id": thread_id, "turn": turn,
                                 "started_at": started_at,
                                 "expires_at": int(self._now()) + self.cfg.trace_ttl_seconds}
            return _record(dict(entry["meta"]), [])

    def append_hop(self, trace_id: str, hop: Dict[str, Any]) -> str:
        with self._lock:
            entry = self.traces.setdefault(trace_id, {"meta": None, "hops": {}})
            if hop["span"] in entry["hops"]:
                return DUPLICATE
            entry["hops"][hop["span"]] = dict(
                hop, expires_at=int(self._now()) + self.cfg.trace_ttl_seconds)
            return APPENDED


def open_store(cfg: Settings) -> DynamoStore:
    """The DynamoDB-backed store. boto3 is preinstalled in the Lambda runtime."""
    import boto3
    from botocore.config import Config

    resource = boto3.resource("dynamodb", config=Config(
        connect_timeout=2, read_timeout=3, retries={"max_attempts": 2}))
    return DynamoStore(resource.Table(cfg.history_table), cfg)


def paired_history(stored: List[Dict[str, Any]], current_span: str, max_sent: int
                   ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """(hops, conversation messages) for the RTG: the path taken and what was said on it.

    Written and read together, so their counts always match and each pair shares a
    `seq` (the RTG merges a message and a hop with the same seq into one history node).
    The call being evaluated is left out. The RTG rejects a whole request over 32
    events, so past `max_sent` the first hop (where the prompt began) and the newest
    are kept, renumbered contiguously.
    """
    prior = [h for h in stored if h.get("span") != current_span]
    if len(prior) > max_sent:
        prior = prior[:1] + prior[-(max_sent - 1):] if max_sent > 1 else prior[-1:]

    hops: List[Dict[str, Any]] = []
    messages: List[Dict[str, Any]] = []
    for seq, hop in enumerate(prior, start=1):
        resource = hop.get("resource") or {}
        content = hop.get("content") or f"{hop.get('action', '')} {resource.get('id', '')}".strip()
        hops.append({"seq": seq, "subject": hop.get("subject"), "action": hop.get("action"),
                     "resource": resource, "time": hop.get("time")})
        messages.append({"seq": seq, "role": hop.get("role") or "assistant",
                         "contentType": "text/plain", "content": content or "(no content)",
                         "timestamp": hop.get("time")})
    return hops, messages
