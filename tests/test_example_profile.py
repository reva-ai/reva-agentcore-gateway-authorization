"""An example configuration, run as a whole question: renamed tools and a prefixed policy store.

Three hops cross one gateway: BFF -> orchestrator (A2A), orchestrator -> analytics (A2A),
analytics -> tools (MCP). The agents follow the generic contract (a `traceparent` on every call,
the user's JWT and a thread id on the first call of the prompt, `X-Reva-Agent-Id` on each agent's
own calls), so the configuration holds only what is specific to this setup: the tool server's
entity name, the store's attribute prefix, and an RTG that uses bearer auth and `content` as the
prompt key.
"""

import json
import unittest

from .support import a2a_payload, bearer, http_event, mcp_event, traceparent
from .test_decide import Harness

TRACE = "e" * 32
CHAT = "11111111-2222-3333-4444-555555555555"
SUB = "00000000-0000-4000-8000-000000000001"

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
            # 1. BFF -> orchestrator: the user's token, a thread id, no agent id.
            _, first_logs = h.run(http_event(
                "/acme-orchestrator/invocations", a2a_payload("Which Acme projects are at risk?"),
                headers={"Authorization": user, "traceparent": traceparent(TRACE),
                         "X-Reva-Thread-Id": CHAT}))
            first = h.body
            # 2. orchestrator -> analytics: the same trace, its own agent id. No thread id
            #    and no user JWT are needed from here on; this example still forwards the token.
            _, second_logs = h.run(http_event(
                "/acme-analytics/invocations", a2a_payload("analyse at-risk projects for ACME"),
                headers={"Authorization": user, "traceparent": traceparent(TRACE),
                         "X-Reva-Agent-Id": "acme-orchestrator"}))
            second = h.body
            # 3. analytics -> tools.
            args = {"countries": ["ES", "PT"], "clients": ["ACME"], "tax_years": [],
                    "service_lines": [], "ent_countries": ["ES", "PT", "FR", "US"],
                    "ent_clients": ["ACME"], "ent_clearance": "elevated"}
            _, third_logs = h.run(mcp_event(
                "acme-tools___query_project_health", args,
                headers={"Authorization": user, "traceparent": traceparent(TRACE),
                         "X-Reva-Agent-Id": "acme-analytics"}))
            third = h.body

            # Subject, action, resource per hop.
            self.assertEqual(first["subject"], {"type": "User", "id": SUB})
            self.assertEqual((first["action"]["name"], first["resource"]["id"]),
                             ("invokeAgent", "acme-orchestrator"))
            self.assertEqual(second["subject"], {"type": "Agent", "id": "acme-orchestrator"})
            self.assertEqual((second["action"]["name"], second["resource"]["id"]),
                             ("invokeAgent", "acme-analytics"))
            self.assertEqual(third["subject"], {"type": "Agent", "id": "acme-analytics"})
            self.assertEqual((third["action"]["name"], third["resource"]["type"],
                              third["resource"]["id"]),
                             ("invokeTool", "Tool", "acme-mcp/query_project_health"))

            # Where each answer came from, as the decision log reports it.
            entry = h.log(first_logs)
            self.assertEqual((entry["traceSource"], entry["threadSource"], entry["subjectSource"]),
                             ("traceparent", "header", "user_fallback"))
            self.assertEqual(h.log(second_logs)["subjectSource"], "header:x-reva-agent-id")
            self.assertEqual(h.log(third_logs)["subjectSource"], "header:x-reva-agent-id")
            self.assertEqual(h.log(third_logs)["threadSource"], "stored")

            # The human and the chat survive every hop though only the first call was read for
            # them.
            for body in (first, second, third):
                self.assertEqual(body["principal"]["id"], SUB)
                self.assertEqual(body["session"]["id"], CHAT)
                self.assertEqual(body["session"]["turn"], 1)
                self.assertEqual(body["transmission"]["promptKey"], "content")

            # The path grows 0, 1, 2 and the conversation matches it hop for hop.
            self.assertEqual([len(b["context"]["hops"]) for b in (first, second, third)], [0, 1, 2])
            self.assertEqual(len(third["context"]["conversation"]["messages"]), 2)
            self.assertEqual(third["context"]["hops"][1]["subject"],
                             {"type": "Agent", "id": "acme-orchestrator"})
            self.assertEqual(third["context"]["conversation"]["messages"][0]["content"],
                             "Which Acme projects are at risk?")

            # Tool-hop scope reaches Cedar context under the store's prefixed names; empty
            # sets are dropped.
            context = third["context"]
            self.assertEqual(context["Acme_req_countries"], ["ES", "PT"])
            self.assertEqual(context["Acme_ent_clearance"], "elevated")
            self.assertNotIn("Acme_req_tax_years", context)
            self.assertNotIn("Acme_req_service_lines", context)

            # The RTG is called the way this RTG expects.
            # The edge gateway reads the policy store from the token, so no store id is sent.
            self.assertEqual(len(h.server.requests), 3)
            for index in range(3):
                self.assertEqual(h.server.header("Authorization", index)[:7], "Bearer ")
                self.assertIsNone(h.server.header("policyStoreId", index))
                self.assertIsNone(h.server.header("X-API-Token", index))


if __name__ == "__main__":
    unittest.main()
