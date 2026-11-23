"""An example configuration, run as a whole question: renamed tools and a prefixed policy store.

Three hops cross one gateway: BFF -> orchestrator (A2A), orchestrator -> analytics (A2A),
analytics -> tools (MCP). Txn-token model: entry hop sends User; nested hops carry
X-Transaction-Token and omit body subject/principal. Configuration holds only what is
specific to this setup: the tool server's entity name and the store's attribute prefix.
"""

import json
import unittest

from .support import a2a_payload, bearer, http_event, mcp_event, traceparent
from .test_decide import Harness

TRACE = "e" * 32
CHAT = "11111111-2222-3333-4444-555555555555"
SUB = "00000000-0000-4000-8000-000000000001"
TXN = "minted.txn.token"

EXAMPLE_ENV = {
    "REVA_AUTH_MODE": "bearer",
    "REVA_PROMPT_KEY": "content",
    "REVA_TARGETS": '{"acme-tools": {"id": "acme-mcp"}}',
    "REVA_CONTEXT_MAP": json.dumps({
        "countries": "Acme_req_countries",
        "tax_years": "Acme_req_tax_years",
        "clients": "Acme_req_clients",
        "service_lines": "Acme_req_service_lines",
        "ent_countries": "Acme_ent_countries",
        "ent_clients": "Acme_ent_clients",
        "ent_clearance": "Acme_ent_clearance"}),
}


class ExampleQuestion(unittest.TestCase):
    def test_three_hops_one_trace(self):
        user = bearer({"sub": SUB})
        with Harness(**EXAMPLE_ENV) as h:
            h.server.default = {"status": 200, "body": {"decision": True, "token": TXN}}
            # 1. BFF -> orchestrator: user JWT + thread id; no prior txn token.
            _, first_logs = h.run(http_event(
                "/acme-orchestrator/invocations", a2a_payload("Which Acme projects are at risk?"),
                headers={"Authorization": user, "traceparent": traceparent(TRACE),
                         "X-Reva-Thread-Id": CHAT}))
            first = h.body
            # 2. orchestrator -> analytics: same trace + JWT; prior txn token.
            _, second_logs = h.run(http_event(
                "/acme-analytics/invocations", a2a_payload("analyse at-risk projects for ACME"),
                headers={"Authorization": user, "traceparent": traceparent(TRACE),
                         "X-Reva-Thread-Id": CHAT, "X-Transaction-Token": TXN}))
            second = h.body
            # 3. analytics -> tools.
            args = {"countries": ["ES", "PT"], "clients": ["ACME"], "tax_years": [],
                    "service_lines": [], "ent_countries": ["ES", "PT", "FR", "US"],
                    "ent_clients": ["ACME"], "ent_clearance": "elevated"}
            _, third_logs = h.run(mcp_event(
                "acme-tools___query_project_health", args,
                headers={"Authorization": user, "traceparent": traceparent(TRACE),
                         "X-Reva-Thread-Id": CHAT, "X-Transaction-Token": TXN,
                         "Mcp-Session-Id": CHAT}))
            third = h.body

            # Entry hop: User subject. Nested hops: subject/principal omitted (from txn).
            self.assertEqual(first["subject"], {"type": "User", "id": SUB})
            self.assertEqual((first["action"]["name"], first["resource"]["id"]),
                             ("invokeAgent", "acme-orchestrator"))
            self.assertNotIn("subject", second)
            self.assertNotIn("principal", second)
            self.assertEqual((second["action"]["name"], second["resource"]["id"]),
                             ("invokeAgent", "acme-analytics"))
            self.assertNotIn("subject", third)
            self.assertEqual((third["action"]["name"], third["resource"]["type"],
                              third["resource"]["id"]),
                             ("invokeTool", "Tool", "acme-mcp/query_project_health"))

            entry = h.log(first_logs)
            self.assertEqual((entry["traceSource"], entry["threadSource"], entry["subjectSource"]),
                             ("traceparent", "header", "user"))
            self.assertEqual(h.log(second_logs)["subjectSource"], "transaction_token")
            self.assertEqual(h.log(third_logs)["subjectSource"], "transaction_token")
            self.assertEqual(h.log(second_logs)["threadSource"], "nested_hop")
            self.assertEqual(h.log(third_logs)["threadSource"], "nested_hop")

            self.assertEqual(first["principal"]["id"], SUB)
            for body in (first, second, third):
                self.assertEqual(body["transmission"]["promptKey"], "content")
            # The thread is recorded on the first call of a turn only; the RTG joins a later
            # hop to it through the trace and the transaction token.
            self.assertEqual(first["session"], {"id": CHAT})
            self.assertEqual(first["threadId"], CHAT)
            for nested in (second, third):
                self.assertNotIn("session", nested)
                self.assertNotIn("threadId", nested)
            self.assertEqual([b["transmission"]["role"] for b in (first, second, third)],
                             ["user", "agent", "agent"])
            self.assertNotIn("context", first)
            self.assertNotIn("context", second)

            context = third["context"]
            self.assertNotIn("hops", context)
            self.assertNotIn("conversation", context)
            self.assertEqual(context["Acme_req_countries"], ["ES", "PT"])
            self.assertEqual(context["Acme_ent_clearance"], "elevated")
            self.assertNotIn("Acme_req_tax_years", context)
            self.assertNotIn("Acme_req_service_lines", context)

            self.assertEqual(len(h.server.requests), 3)
            for index in range(3):
                self.assertEqual(h.server.requests[index]["path"],
                                 "/pdp/ai/access/ai/evaluation")
                self.assertEqual(h.server.header("Authorization", index)[:7], "Bearer ")
                self.assertEqual(h.server.header("X-Reva-Thread-Id", index),
                                 CHAT if index == 0 else None)
                self.assertEqual(h.server.header("X-Reva-Token-Request", index), "transaction")
                self.assertIsNone(h.server.header("policyStoreId", index))
                self.assertIsNone(h.server.header("X-API-Token", index))
            self.assertIsNone(h.server.header("X-Transaction-Token", 0))
            self.assertEqual(h.server.header("X-Transaction-Token", 1), TXN)
            self.assertEqual(h.server.header("X-Transaction-Token", 2), TXN)


if __name__ == "__main__":
    unittest.main()
