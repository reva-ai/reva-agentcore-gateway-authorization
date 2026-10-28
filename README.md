# Reva runtime authorization for Amazon Bedrock AgentCore Gateway

A Lambda **interceptor** for an AgentCore Gateway. Before the gateway forwards a request to a target, it asks
Reva's RTG whether the call is allowed. The call either goes through, or the Lambda answers on the gateway's behalf
with a refusal and the tool or agent never runs.

It is the gateway-side counterpart of the Claude Code plugin and the Kong plugin, and it speaks the same RTG
contract (`POST /pdp/v2/ai/evaluation`; `200` allow, `403` deny).

```
agent ──► AgentCore Gateway ──► [ this Lambda ] ──► target (MCP tool / agent)
                                    │   ▲
                       RTG decision │   │ trace record: principal, chat, hops
                                    ▼   │
                                   RTG   DynamoDB (reva_trace_hop)
```

**Contents**

1. [How it works](#how-it-works)
2. [Setup, step by step](#setup-step-by-step)
3. [What agents must send](#what-agents-must-send)
4. [Verify it](#verify-it)
5. [Going live, updating, rolling back](#going-live-updating-rolling-back)
6. [Reference](#reference): [what it governs](#what-it-governs), [who is calling](#who-is-calling),
   [history](#history), [failure behaviour](#failure-behaviour), [configuration](#configuration)
7. [Example: renamed tools and a prefixed policy store](#example-renamed-tools-and-a-prefixed-policy-store)
8. [Troubleshooting](#troubleshooting)
9. [Tests](#tests) and [what is not in v1](#not-in-v1)

## How it works

For every request that reaches the gateway, the Lambda:

1. works out **what is being called** from the shape of the payload (a tool, or an agent) and **who is calling**
   (the user from the JWT, the agent from a claim or header);
2. reads the trace's earlier hops from DynamoDB, so the RTG sees the path so far;
3. asks the RTG;
4. on an allow, records the hop and lets the request through; on a deny, answers `403` itself.

It fails closed: if the RTG or the table is unavailable, or anything is misconfigured, the call is denied (see
[failure behaviour](#failure-behaviour) for the one switch that changes this).

The code is plain Python: the standard library plus `boto3`, which the Lambda runtime already provides. There is
nothing to install into the zip.

## Setup, step by step

Names used below (change them if you like): table `reva_trace_hop`, role `reva-interceptor-role`, function
`reva-agentcore-interceptor`. Replace `<region>` and `<account-id>` throughout. Create the Lambda in the **same
region** as the gateway, and the table and the secret in the **Lambda's region** (the function looks for both in its
own).

You need:

- an AWS account where you may create a DynamoDB table, an IAM role and a Lambda function, and may edit the gateway
  and its service role;
- an AgentCore Gateway whose authorizer accepts the **user's JWT** (the interceptor reads the user from it);
- a Reva **RTG token** (it goes into AWS Secrets Manager, step 2) and the RTG base URL if it is not
  `https://api.reva.ai`, with your agents, tools and policies already set up on the Reva side;
- the AWS CLI v2 if you want to use the commands. Every step also has console instructions.

### 1. Create the DynamoDB table

The table keeps, per trace, who the call is for, which chat it belongs to, and the hops permitted so far. It has a
string partition key `pk`, a string sort key `sk`, on-demand billing, and a time-to-live on `expires_at` so rows
clean themselves up. The layout is described under [history](#the-history-table).

**Console:** DynamoDB → Tables → Create table → table name `reva_trace_hop`, partition key `pk` (String), sort key
`sk` (String) → Table settings: Customize settings → Capacity mode: On-demand → Create table. Then open the table →
Additional settings → Time to Live (TTL) → Turn on → attribute name `expires_at`.

**CLI:**

```bash
aws dynamodb create-table --table-name reva_trace_hop --billing-mode PAY_PER_REQUEST \
  --attribute-definitions AttributeName=pk,AttributeType=S AttributeName=sk,AttributeType=S \
  --key-schema AttributeName=pk,KeyType=HASH AttributeName=sk,KeyType=RANGE \
  --region <region>
aws dynamodb update-time-to-live --table-name reva_trace_hop \
  --time-to-live-specification Enabled=true,AttributeName=expires_at --region <region>
```

A sort key can't be added to an existing table, so a table with a single key can't be reused. The interceptor
looks for `reva_trace_hop` unless `REVA_HISTORY_TABLE` names another table. Other key names are possible with
`REVA_HISTORY_PK_ATTR` and `REVA_HISTORY_SK_ATTR`.

### 2. Store the RTG token in Secrets Manager

The token is not kept in the function's configuration. The function reads it from a Secrets Manager secret on the
first call it evaluates, keeps it for 5 minutes, and reads it again after that, so rotating the token is a change
to the secret, with no redeploy. Create the secret in the **same region** as the function.

**Console:** Secrets Manager → Store a new secret → Secret type: Other type of secret → **Plaintext** tab → replace
the sample text with the token (the token only) → Next → Secret name `reva/secrets` → Next → Next → Store.
A key/value secret works too: use the key `RTG_TOKEN` (the interceptor's default key) and the token as its value.

**CLI:** put the token alone in a file, create the secret from it, then delete the file:

```bash
aws secretsmanager create-secret --name reva/secrets --secret-string file://token.txt --region <region>
rm token.txt
```

**Recommended: point the function at the secret by its ARN.** Copy the ARN (Secrets Manager → the secret → Secret ARN,
or `aws secretsmanager describe-secret --secret-id reva/secrets --query ARN --output text`) and set it as
`REVA_TOKEN_SECRET` in step 6. The function then fetches exactly that secret, whatever it is called and whichever
account it is in (see [Several AWS accounts](#several-aws-accounts)). Without the variable it falls back to the name
`reva/secrets`, so a secret created with that name works with no setting at all.

In a JSON secret the function reads the field `RTG_TOKEN`. To keep the token under another field name, set
`REVA_TOKEN_SECRET_KEY` to it: with `REVA_TOKEN_SECRET_KEY=ACME_RTG_TOKEN` the value of the field `ACME_RTG_TOKEN` is
used and every other field is ignored. A secret encrypted with the default key (`aws/secretsmanager`) needs no extra
permission; with your own KMS key the role also needs `kms:Decrypt` on it.

### 3. Create the Lambda's execution role

The role lets the function write its logs, use the table and read the token secret.

**Console:** IAM → Roles → Create role → Trusted entity: AWS service → Use case: Lambda → attach the managed policy
`AWSLambdaBasicExecutionRole` → name it `reva-interceptor-role` → Create role. Then open the role → Add permissions
→ Create inline policy → JSON, paste the permissions policy below → name it `reva-interceptor-access`.

**CLI:** save the trust policy as `trust.json` and the permissions policy as `permissions.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
```

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["dynamodb:Query", "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"],
      "Resource": "arn:aws:dynamodb:<region>:<account-id>:table/reva_trace_hop"
    },
    {
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "arn:aws:secretsmanager:<region>:<account-id>:secret:reva/secrets-*"
    }
  ]
}
```

```bash
aws iam create-role --role-name reva-interceptor-role \
  --assume-role-policy-document file://trust.json
aws iam attach-role-policy --role-name reva-interceptor-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
aws iam put-role-policy --role-name reva-interceptor-role \
  --policy-name reva-interceptor-access --policy-document file://permissions.json
```

All four table actions are needed: `Query` reads a trace, `PutItem` writes hop and header rows, `UpdateItem` advances
a chat's turn, `GetItem` reads a chat. A role that misses one makes the matching step fail, and a failed read or
header write denies the call (the log says `AccessDeniedException` and names the missing action). Secrets Manager
adds a random suffix to a secret's ARN (`reva/secrets-AbCdEf`), which is why the policy ends in `-*`; once you set the
full ARN in `REVA_TOKEN_SECRET`, you can put that exact ARN there instead. Without
`secretsmanager:GetSecretValue` every call is denied with `token_unavailable`.

### 4. Build the zip

From the root of this repository:

```bash
zip -r interceptor.zip handler.py interceptor -x "*__pycache__*"
```

`handler.py` must sit at the top of the zip, next to the `interceptor/` folder. Check with `unzip -l interceptor.zip`.
(`interceptor.zip` is git-ignored.)

### 5. Create the Lambda function and upload the zip

**Console:** Lambda → Create function → Author from scratch →

- Function name: `reva-agentcore-interceptor`
- Runtime: Python 3.12 (3.11 or newer; the tests run on 3.11)
- Architecture: x86_64 or arm64, both work (pure Python)
- Permissions → Change default execution role → Use an existing role → `reva-interceptor-role`

→ Create function. Then:

1. **Code** tab → Upload from → .zip file → choose `interceptor.zip` → Save.
2. **Code** tab → Runtime settings → Edit → Handler: `handler.lambda_handler` → Save.
3. **Configuration** tab → General configuration → Edit → Memory `256 MB`, Timeout `1 min` → Save.

The timeout must be well above `REVA_TIMEOUT_SECONDS` (15 s by default). The interceptor keeps
`REVA_SAFETY_MARGIN_MS` back from the function's own deadline so its fail-closed path always gets to run. AWS does
not document the gateway's own limit on how long it waits for an interceptor, so keep calls fast: lower
`REVA_TIMEOUT_SECONDS` if your gateway gives up sooner.

**CLI:**

```bash
aws lambda create-function --function-name reva-agentcore-interceptor \
  --runtime python3.12 --handler handler.lambda_handler \
  --role arn:aws:iam::<account-id>:role/reva-interceptor-role \
  --zip-file fileb://interceptor.zip --timeout 60 --memory-size 256 --region <region>
```

Do not put the Lambda in a VPC unless the VPC can reach both the RTG (internet or a private link) and DynamoDB
(a gateway endpoint). A function that cannot reach the RTG denies every call with `rtg_unavailable`.

### 6. Set the environment variables

**Console:** Configuration tab → Environment variables → Edit → Add environment variable. Values that are JSON
(`REVA_TARGETS`, `REVA_CONTEXT_MAP`) go on one line.

One variable is recommended: **`REVA_TOKEN_SECRET`**, set to the secret's full ARN (step 2). No variable is strictly
required: the host is `https://api.reva.ai`, the table is `reva_trace_hop`, the token is looked up by the name
`reva/secrets` if the variable is not set, and the RTG is called with `X-API-Token`. Set these as your setup needs:

| Variable | When |
|---|---|
| `REVA_TOKEN_SECRET` | **recommended**: the secret's full ARN, for example `arn:aws:secretsmanager:us-west-2:123456789012:secret:reva/secrets-AbCdEf`. Needed when the secret is not named `reva/secrets` or is in another account |
| `REVA_TOKEN_SECRET_KEY` | the secret is JSON and holds the token under a field other than `RTG_TOKEN` |
| `REVA_BASE_URL` | the RTG is not at `https://api.reva.ai` |
| `REVA_AUTH_MODE=bearer` | the RTG expects `Authorization: Bearer` instead of `X-API-Token` |
| `REVA_HISTORY_TABLE` | your table is not named `reva_trace_hop` |
| `REVA_TARGETS` | a gateway target's name differs from the tool or agent id in your policy store |
| `REVA_CONTEXT_MAP` | a policy reads values out of the call's arguments (see [configuration](#configuration)) |

For the first run, also set `REVA_MONITOR_MODE=true` (a deny is logged but the call still goes through) and
`REVA_DEBUG=true` (logs the event's shape and the RTG request; it contains prompts). Remove both before real use.

There is no `REVA_TOKEN` variable. Setting one is a configuration error, so a token is never left sitting in the
function's configuration by accident.

The full list is in [configuration](#configuration). A bad value never crashes the function: it is reported in the
log and every call is denied with `config_error` until you fix it.

### 7. Let the gateway invoke the function

AWS requires the **gateway's service role** to be allowed to invoke the interceptor, and recommends allowing only
that function.

Find the role: `aws bedrock-agentcore-control get-gateway --gateway-identifier <gateway-id>` shows its `roleArn`.
Add an inline policy to that role:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "lambda:InvokeFunction",
    "Resource": "arn:aws:lambda:<region>:<account-id>:function:reva-agentcore-interceptor"
  }]
}
```

```bash
aws iam put-role-policy --role-name <gateway-service-role> \
  --policy-name invoke-reva-interceptor --policy-document file://invoke-policy.json
```

(Console: IAM → Roles → the gateway's role → Add permissions → Create inline policy → JSON.) AWS's pages do not say
whether a resource policy on the Lambda is also needed. For a gateway in the same account the role's policy is
enough; if the gateway reports that it cannot invoke the function, check this step first.

### 8. Attach the interceptor to the gateway

The gateway needs one **REQUEST** interceptor with **`passRequestHeaders: true`**. Without that flag the gateway
does not hand the Lambda any headers, so it never sees the user's token or the `traceparent`, and every first call
is denied with `missing_authorization`.

Save this as `interceptors.json`:

```json
[{
  "interceptor": {"lambda": {"arn": "arn:aws:lambda:<region>:<account-id>:function:reva-agentcore-interceptor"}},
  "interceptionPoints": ["REQUEST"],
  "inputConfiguration": {"passRequestHeaders": true}
}]
```

Then attach it. For a new gateway the list goes on `create-gateway` as `--interceptor-configurations`. For an
existing gateway use `update-gateway`:

```bash
aws bedrock-agentcore-control update-gateway --gateway-identifier <gateway-id> \
  --interceptor-configurations file://interceptors.json  # plus the gateway's other required parameters
```

AWS's documentation does not list the required parameters of `update-gateway`. Read the gateway first with
`get-gateway`, pass back its current name, role, protocol type and authorizer for any parameter the call asks for,
and see `aws bedrock-agentcore-control update-gateway help`. The console's gateway page may also have an
interceptor section; AWS does not document its wording. The field names above are the documented ones.

A gateway holds at most one REQUEST and one RESPONSE interceptor. This function ignores the response leg (it
answers the response unchanged), so attach it as REQUEST only; a RESPONSE attachment only adds a Lambda call to
every response.

### 9. Update the agents

Every agent that calls through the gateway has to send a few things. See [what agents must send](#what-agents-must-send).
The one that matters most is the same `traceparent` on every call of a prompt.

### 10. Check that it works

See [verify it](#verify-it).

## What agents must send

| | Required | Why |
|---|---|---|
| `Authorization: Bearer <user JWT>` on the **first gateway call of each prompt**, and `passRequestHeaders: true` on the gateway | yes | the principal is read from it once and stored |
| the same W3C **`traceparent`** on every call of one prompt | yes | it correlates the hops and keys the stored record. An OpenTelemetry-instrumented HTTP client normally propagates it; check yours |
| a **thread id** on the first call of each prompt: `X-Reva-Thread-Id`, or A2A `contextId`, or `Mcp-Session-Id` | recommended | links prompts of one chat. Without one, each prompt is its own chat (a warning is logged) |
| `X-Reva-Agent-Id: <the agent's RTG entity id>` on an agent's own outbound calls | only for an `Agent` subject | nothing else in the event says which agent is calling |
| values a policy needs to see (countries, clients, ...) in the call: **tool arguments** for a tool call, the message's **`metadata`** for an agent call | only where a policy reads them | see `REVA_CONTEXT_MAP` below; the keys must match the map's |
| hop lists, conversation blocks, session ids, turn numbers | **no** | kept in DynamoDB |

Later hops of a prompt need only the `traceparent` (the gateway still requires whatever token its authorizer
accepts). If an agent sends no agent id its hops are still evaluated, with the user as subject and
`subjectSource` set to `user_fallback` in the log.

An A2A call carries its extra values like this:

```json
{
  "jsonrpc": "2.0",
  "method": "message/send",
  "params": {
    "message": {
      "role": "user",
      "parts": [{"text": "analyse at-risk projects for ACME"}],
      "metadata": {"countries": ["ES", "PT"], "clients": ["ACME"]}
    }
  }
}
```

`metadata` is a standard, free-form A2A field. Only the keys listed in `REVA_CONTEXT_MAP` are ever sent on to the
RTG; the rest stays here. Leave out empty values.

## Verify it

### A test event from the Lambda console

Lambda → your function → Test tab → create a new event, paste this, and press Test. Use a tool that exists in your
policy store (the name is `<gateway target>___<tool>`), and a JWT whose `sub` is a user the RTG knows. The
`traceparent` is any valid value.

```json
{
  "interceptorInputVersion": "1.0",
  "mcp": {
    "gatewayRequest": {
      "path": "/mcp",
      "httpMethod": "POST",
      "headers": {
        "Authorization": "Bearer <jwt>",
        "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        "X-Reva-Thread-Id": "test-chat-1"
      },
      "body": {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "my-target___my_tool", "arguments": {"q": "hello"}}
      }
    }
  }
}
```

To make a throwaway JWT (the interceptor reads the payload and does not verify the signature, because the gateway
already has):

```bash
python3 - <<'EOF'
import base64, json
b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
print(f"{b({'alg': 'none'})}.{b({'sub': 'test-user'})}.x")
EOF
```

- **Allowed:** the response is `{"interceptorOutputVersion": "1.0", "mcp": {"transformedGatewayRequest": {"body": ...}}}`.
- **Denied:** the response has `transformedGatewayResponse` with `statusCode` `403` and a `data.code` saying why.

A test event is a real call: it goes to the RTG and, if allowed, writes a row to the table.

### End to end

1. Ask your agent a question that crosses the gateway.
2. **CloudWatch Logs** → log group `/aws/lambda/reva-agentcore-interceptor`. Each evaluated call logs one line like
   `{"event":"decision","decision":"permit","outcome":"allow","trace":"...","traceSource":"traceparent","thread":"...",
   "action":"invokeTool","resource":"my-target/my_tool","subjectType":"Agent","subjectSource":"header:x-reva-agent-id",
   "turn":1,"firstCall":true,"hopsSent":0,...}`. `decision` is `permit`, `deny`, or one of `permit_conditional`,
   `monitor_would_deny` (monitor mode: the RTG said no, the call went through) and `permit_fail_open` (the RTG could
   not be asked and `REVA_FAIL_OPEN=true`). Check that `trace` is the same for every hop of the prompt, `subjectType`
   is what you expect, and `traceSource` says `traceparent`.
3. **DynamoDB** → `reva_trace_hop` → Explore table items. After a prompt you should see a `TR#<trace>` / `#META`
   row, one `TR#<trace>` / `HOP#<span>` row per permitted hop, and a `TH#<thread>` / `#META` row.
4. In the **RTG's decision log**, the later hops should arrive with the earlier ones in `context.hops` and the
   same thread id.

If something is off, see [troubleshooting](#troubleshooting).

## Going live, updating, rolling back

**Before real traffic**

- Remove `REVA_DEBUG` and `REVA_MONITOR_MODE`. With monitor mode on, nothing is ever blocked.
- Decide on `REVA_FAIL_OPEN`. The default `false` blocks calls while the RTG is unreachable; `true` lets them
  through (policy denials are never let through, only outages).
- Set a retention period on the function's log group. Logs hold trace and thread ids and a short hash of the user,
  never tokens, JWTs or headers; with `REVA_DEBUG` on they also hold prompts.

**Rotating the RTG token:** change the secret's value (Secrets Manager → the secret → Retrieve secret value → Edit).
The function uses the new value within 5 minutes; nothing is redeployed. If a refresh ever fails, the last token it
read keeps being used and a `token_refresh_failed` warning is logged.

**Updating the code**

1. Lambda → Code → Actions → Download .zip: keep the version that works now.
2. Rebuild the zip (step 4) and upload it (Code → Upload from → .zip file). The handler and the environment
   variables stay as they are.
3. Run a test event.

**Rolling back:** upload the zip you downloaded. To take the interceptor out of the path altogether, remove it from
the gateway's interceptor configuration (step 8).

## Reference

### What it governs

It reads the gateway event, works out *what is being called* from the shape of the payload, and asks the RTG
about that. Entity types come from the protocol; ids come from the payload.

| Payload | action | resource | prompt sent to the RTG |
|---|---|---|---|
| MCP `tools/call`, `params.name = <target>___<tool>` | `invokeTool` | `Tool` `<target>/<tool>` | the arguments as JSON |
| A2A `message/send` to `/<target>/invocations` | `invokeAgent` | `Agent` `<target>` | the message's text parts |
| plain AgentCore Runtime call to `/<target>/invocations` | `invokeAgent` | `Agent` `<target>` | `prompt`/`input`/`message`/`query`/`text`, else the body |
| MCP `initialize`, `tools/list`, `ping`, notifications, GET/DELETE | not evaluated | | |
| anything else on an HTTP target (including inference/LLM traffic) | not evaluated by default (`REVA_UNCLASSIFIED=deny` refuses it) | | |

LLM calls only reach a gateway if an agent's model client is pointed at the gateway's `/inference` endpoint; an
agent that calls Bedrock, LiteLLM or OpenAI directly never touches it. Evaluating that traffic is not part of v1.

`REVA_TARGETS` can rename a target's entity id (`{"acme-tools": {"id": "acme-mcp"}}`) or exclude a target
(`{"public": {"kind": "skip"}}`). It is the only topology configuration.

### Who is calling

| | Where it comes from |
|---|---|
| **principal** (`User`) | the bearer JWT's `REVA_USER_CLAIM` (default `sub`). Decoded **once**, on the first call of a trace, and stored. Later hops read it from DynamoDB. |
| **subject** | with `REVA_AUTHORIZE_AGENT=true` (default): `Agent(id)` if an agent id resolves, otherwise the user. With `false`: the user on every hop. |
| **agent id** | JWT claim `act.sub` (RFC 8693 token exchange), then the header `X-Reva-Agent-Id`. `REVA_AGENT_CLAIMS` adds claims, `REVA_AGENT_HEADER` renames the header, `REVA_AGENT_ID_MAP` maps values to RTG entity ids. |
| **groups** | optional: the claim in `REVA_GROUPS_CLAIM` becomes `UserGroup` parents of the user. |

The gateway has already validated the JWT, so it is decoded without re-verifying. Nothing in the gateway event
identifies the calling agent, which is why the agent id has to come from the token or a header. `client_id` and
`azp` are not used by default: when an agent forwards the user's token they name the UI app on every hop.
**The header is a caller assertion and can be forged.**

### History

Per trace, in DynamoDB (`REVA_HISTORY=interceptor`, the default): who the trace is for, which chat it belongs to,
the turn number, and the hops permitted so far. Each call asks the RTG about itself with `context.hops` and
`context.conversation.messages` (paired, same `seq`) describing the hops before it, and `session`
`{id, turn, startedAt}`. A hop is recorded only after it is permitted, once per call (a gateway retry does not
duplicate it), and the call under evaluation is never part of its own history. A call costs one `Query`, the RTG
call and one `PutItem`; a trace's first call adds a few writes.

`REVA_HISTORY=rtg` is for an RTG that keeps thread history itself: only `traceparent` and the thread id are
sent, nothing is stored, and the JWT is decoded on every hop.

#### The history table

The layout mirrors the RTG's own `trace_hop` table: one row per hop, plus a header row per trace.

| Partition key | Sort key | Holds |
|---|---|---|
| `TR#<trace id>` | `#META` | the trace's header: `principal`, `groups`, `thread_id`, `turn`, `started_at` |
| `TR#<trace id>` | `HOP#<span id>` | one permitted hop: `received_at`, `subject`, `action`, `resource`, `role`, `content` |
| `TH#<thread id>` | `#META` | the chat: `traces` (trace ids in arrival order), `started_at` |

Every row carries `expires_at`. Traces live 1 h from their first call, threads 24 h.

- A hop row is written only if absent, so a gateway retry of the same call is recorded once. Parallel tool calls
  each write their own row, so none is lost.
- The header row is written before the RTG is asked, only if absent, so the first writer wins a race.
- One consistent `Query` reads the header and the hops together, at most 200 rows.

### Failure behaviour

| Situation | Result |
|---|---|
| RTG `403`, or a `decision: false` body, or `401 USER_NOT_FOUND`/`USER_DISABLED` | **deny** (`REVA_MONITOR_MODE=true` logs it and passes) |
| any other RTG `4xx` (the request is invalid) | **deny**, never fails open |
| RTG `401`/`404`/`408`/`413`/`424`/`425`/`429`/`5xx`, timeout, unreachable, or the history table unreadable | **deny**; **pass** if `REVA_FAIL_OPEN=true` (and the hop is not recorded). Transient faults are retried once inside the time the Lambda has left |
| RTG `200` with `guardrails.outcome = conditional_allow` | **deny** (the gateway has no "ask"); `REVA_CONDITIONAL_ALLOW=allow` passes |
| the RTG token cannot be read from Secrets Manager (and none was read before) | **deny** with `token_unavailable`, never fails open: without the credential the RTG cannot be asked |
| no user token on a trace's first call, no principal claim, a malformed MCP body, a JSON-RPC batch containing `tools/call`, bad configuration, any internal error | **deny**, never fails open |

A deny is HTTP `403` (`REVA_DENY_STATUS`). MCP and A2A calls get a JSON-RPC error whose `data.code` says why; a plain
Runtime call gets `{"error": {"type": "permission_denied", "code": ..., "message": ...}}`. The caller sees only
`REVA_DENY_MESSAGE` and the code; the RTG's reason is in the Lambda log. Tokens, JWTs and headers are never logged.

| Code | Meaning |
|---|---|
| `policy_denied` | the RTG said no (or `conditional_allow` with `REVA_CONDITIONAL_ALLOW=deny`) |
| `rtg_rejected` | the RTG found the request invalid (a `4xx` other than `401`/`403`/`404`/`408`/`413`/`424`/`425`/`429`) |
| `rtg_unavailable` | the RTG could not be asked or answered with an outage-type status |
| `token_unavailable` | the RTG token could not be read from Secrets Manager |
| `history_unavailable` | the history table could not be read or its header written |
| `config_error` | a configuration value is invalid; the log line names it |
| `missing_authorization`, `invalid_authorization`, `principal_unresolved` | no bearer token, not a JWT, or no user claim on a trace's first call |
| `traceparent_missing` | no trace id and `REVA_ON_MISSING_TRACEPARENT=deny` |
| `malformed_body`, `batch_unsupported`, `malformed_event` | the request is not something it can judge safely |
| `unresolvable_resource`, `unclassified_traffic` | no entity id could be worked out, or `REVA_UNCLASSIFIED=deny` |
| `internal_error` | an unexpected exception, turned into a deny |

AWS does not document what the gateway does when an interceptor Lambda errors or times out, and says it may retry
the call. So the function never raises (an unexpected exception becomes a deny), and everything it writes is safe
to repeat.

### Several AWS accounts

By default everything the function uses is in **its own account and region**: the secret (found by name) and the
history table. With several accounts there are two ways to go.

**One deployment per account (simplest).** Repeat the setup in each account: its own table, its own secret, its own
Lambda. Nothing is shared.

**One token for all accounts.** Keep the secret in one account (A) and let the functions in the others (B) read it.
Name the secret by its **full ARN** in `REVA_TOKEN_SECRET`; the function then asks Secrets Manager in the ARN's
region. Nothing in the code changes, but AWS needs access granted on both sides and a key you manage. From AWS's
cross-account guide:

1. Encrypt the secret with a customer-managed KMS key. AWS says the managed key `aws/secretsmanager` can't be used
   for cross-account access.
2. The secret's resource policy (account A) allows the Lambda role in account B:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Principal": {"AWS": "arn:aws:iam::<account-b>:role/reva-interceptor-role"},
       "Action": "secretsmanager:GetSecretValue",
       "Resource": "*"
     }]
   }
   ```
3. The KMS key's policy (account A) allows that role `kms:Decrypt` and `kms:DescribeKey`.
4. The Lambda role's own policy (account B) allows the secret and the key, by ARN:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue",
        "Resource": "arn:aws:secretsmanager:<region>:<account-a>:secret:reva/secrets-AbCdEf"},
       {"Effect": "Allow", "Action": "kms:Decrypt",
        "Resource": "arn:aws:kms:<region>:<account-a>:key/<key-id>"}
     ]
   }
   ```
5. Set `REVA_TOKEN_SECRET` on the function to the secret's full ARN.

The history table is always in the function's own account and region (it is addressed by name), so each account keeps
its own. Keep the interceptor Lambda in the gateway's account too: AWS's pages do not document a gateway invoking a
function in another account.

### Configuration

Everything is an environment variable.

| Variable | Default | |
|---|---|---|
| `REVA_BASE_URL` | `https://api.reva.ai` | RTG base URL; the path is fixed |
| `REVA_TOKEN_SECRET`, `REVA_TOKEN_SECRET_KEY` | `reva/secrets`, `RTG_TOKEN` | the Secrets Manager secret holding the RTG credential. **Recommended: set `REVA_TOKEN_SECRET` to the secret's full ARN**; the name is only the fallback, and a secret in another account needs its ARN (see "Several AWS accounts"). It is read on the first evaluated call and every 5 minutes. A plaintext secret is the token; a JSON secret is read at the key. `REVA_TOKEN` is not read: setting it is a configuration error |
| `REVA_AUTH_MODE` | `api-token` | `api-token` sends `X-API-Token`; `bearer` sends `Authorization: Bearer` (+ `policyStoreId` if set) |
| `REVA_POLICY_STORE_ID` | | optional; sent as `policyStoreId` in bearer mode. Normally unnecessary: the edge gateway takes the store from the token. Needed when the RTG is called directly |
| `REVA_VERIFY_USER_SCOPE`, `REVA_ORIGIN_APP` | off | send `X-Reva-Verification-Codes: CODE_USER_SCOPE` and `X-API-Origin-App` for the edge's known-user check. `REVA_VERIFY_USER_SCOPE=true` needs `REVA_ORIGIN_APP` (otherwise a configuration error) |
| `REVA_PROMPT_KEY` | `userQuery` | name of the prompt field in `transmission` (older stores use `content`) |
| `REVA_TIMEOUT_SECONDS`, `REVA_RETRIES`, `REVA_SAFETY_MARGIN_MS` | `15`, `1`, `2000` | per-attempt timeout, retries, time kept back from the Lambda's own deadline |
| `REVA_USER_CLAIM` | `sub` | principal claim |
| `REVA_GROUPS_CLAIM` | off | list claim → `UserGroup` parents |
| `REVA_AUTHORIZE_AGENT` | `true` | `false`: the user is the subject on every hop |
| `REVA_AGENT_CLAIMS`, `REVA_AGENT_HEADER`, `REVA_AGENT_ID_MAP` | `act.sub`, `x-reva-agent-id`, `{}` | see "Who is calling" |
| `REVA_TARGETS` | `{}` | per-target `id` alias, `endpoint`, `kind: skip` |
| `REVA_CONTEXT_MAP` | `{}` | `{"<argument>": "<Cedar context attribute>"}`. A tool call's arguments are `params.arguments`; an agent call's (A2A) are the message's `metadata`. Only mapped keys are sent, empty values are dropped, and no other context attributes are ever added |
| `REVA_UNCLASSIFIED` | `skip` | `deny` refuses HTTP traffic that is neither A2A nor `/<target>/invocations` |
| `REVA_UNKNOWN_RESOURCE` | `deny` | `unknown` sends `unknown-*` ids instead (reads as allow at the RTG) |
| `REVA_EVAL_BUILTIN_TOOLS` | `false` | evaluate the gateway's own search tool |
| `REVA_TOOL_PARENTS` | `false` | also send `MCPServer` as the Tool's parent and tool properties |
| `REVA_TRACE_HEADER` | off | a header carrying a trace id, for callers that cannot send `traceparent` |
| `REVA_ON_MISSING_TRACEPARENT` | `mint` | `deny` refuses calls with no trace id. A minted trace has no history |
| `REVA_HISTORY`, `REVA_HISTORY_TABLE` | `interceptor`, `reva_trace_hop` | `rtg` needs no table. Set the table name only if yours differs |
| `REVA_HISTORY_PK_ATTR`, `REVA_HISTORY_SK_ATTR` | `pk`, `sk` | the table's partition and sort key names |
| `REVA_TRACE_TTL_SECONDS`, `REVA_THREAD_TTL_SECONDS` | `3600`, `86400` | |
| `REVA_MAX_HOPS_SENT`, `REVA_CONTENT_MAX_BYTES`, `REVA_PROMPT_MAX_BYTES` | `30`, `1500`, `12000` | the RTG rejects history over 32 events, 64 KiB, or any string over 16 KiB, so `REVA_MAX_HOPS_SENT` is capped at 30 (the first hop and the newest ones are kept) |
| `REVA_FAIL_OPEN`, `REVA_MONITOR_MODE`, `REVA_CONDITIONAL_ALLOW` | `false`, `false`, `deny` | see "Failure behaviour" |
| `REVA_DENY_MESSAGE`, `REVA_DENY_STATUS` | generic message, `403` | |
| `REVA_DEBUG` | `false` | log the event's shape and the RTG request body (it contains prompts: development only) |

## Example: renamed tools and a prefixed policy store

A setup that follows the contract above (a `traceparent` on every call, the user's JWT and a thread id on the first
call of each prompt, and `X-Reva-Agent-Id` on each agent's own calls) needs little configuration. Three things in
this example differ from the defaults: the policy store knows the tool server as `acme-mcp` (the gateway target is
`acme-tools`), it prefixes Cedar attributes with `Acme_`, and its RTG expects bearer authentication and `content` as
the prompt key. So the interceptor is configured, not changed (`tests/test_example_profile.py` runs this as a
three-hop question):

```
REVA_BASE_URL=https://<your RTG host>   REVA_AUTH_MODE=bearer
REVA_PROMPT_KEY=content
REVA_TARGETS={"acme-tools": {"id": "acme-mcp"}}
REVA_CONTEXT_MAP={"countries": "Acme_req_countries", "tax_years": "Acme_req_tax_years",
                  "clients": "Acme_req_clients", "service_lines": "Acme_req_service_lines",
                  "ent_countries": "Acme_ent_countries", "ent_clients": "Acme_ent_clients",
                  "ent_clearance": "Acme_ent_clearance"}
```

Why the last two settings exist, and when you would not need them:

- `REVA_TARGETS` renames the gateway target `acme-tools` to `acme-mcp`, the server name the policy store knows its
  tools by. A tool id that matches no entity is not denied: no permit and no forbid match it, so it reads as an
  allow. A customer who registers tools as `<gateway target>/<tool>` needs no alias.
- `REVA_CONTEXT_MAP` copies a call's arguments into the Cedar attributes the policies read (`countries` becomes
  `Acme_req_countries`). The RTG does not lift arguments into context itself, so without the map a scope
  `forbid ... when` never matches and the call is allowed. Policies that do not look at arguments need no map.
  A tool call carries its arguments in `params.arguments`. An agent call (A2A `message/send`) has no argument map,
  so the caller's free-form `metadata` plays that part: it is read from the message, the send params and the
  request, the most specific winning a repeated key. An agent that wants a scope policy to judge its hand-off puts
  the values in `metadata` under names the map lists; the interceptor adds nothing the map does not name.

There is no store id in the block: the edge gateway reads it from the token. The token itself is in the Secrets
Manager secret (`reva/secrets`), not in the block.

## Troubleshooting

The Lambda's log group is `/aws/lambda/<function name>`. Useful lines have an `event` field: `decision`,
`local_deny` (denied before asking the RTG; `code` says why), `warn`, `error`, `skip`.

| Symptom | Cause | Fix |
|---|---|---|
| every call denied, `config_error` | a bad environment variable; the log line names it. Usual suspects: JSON that does not parse in `REVA_TARGETS` or `REVA_CONTEXT_MAP`, a leftover `REVA_TOKEN` (the token now comes from Secrets Manager), a leftover `REVA_HISTORY_KEY_ATTR` from the first version of this interceptor | fix or delete the variable |
| every call denied, `token_unavailable` | the secret cannot be read: it does not exist under that name in the function's region, the role lacks `secretsmanager:GetSecretValue` on it (or `kms:Decrypt` on its key), or a JSON secret has no field `RTG_TOKEN`; for another account's secret, its resource policy or its key's policy does not allow the role | step 2 and step 3; the log line's reason names the cause |
| `missing_authorization` | the gateway is not passing headers, or the first call of the trace has no bearer token | step 8: `passRequestHeaders: true`; make the first call carry the user's JWT |
| `invalid_authorization` or `principal_unresolved` | the token is not a JWT, or has no `sub` (or the claim in `REVA_USER_CLAIM`) | send the user's JWT; set `REVA_USER_CLAIM` |
| `AccessDeniedException` for `dynamodb:Query` (or another action), `history_unavailable` | the execution role lacks an action | step 3: all four actions on the table's ARN |
| `cannot open table` or `ResourceNotFoundException` | the table name or region is wrong | the function reads the table in its own region; check `REVA_HISTORY_TABLE` |
| nothing is saved in the table | the call carried no `traceparent` (the log says `traceparent_missing`: a minted trace has no history), or every call was denied (hops are recorded only after a permit), or `REVA_HISTORY=rtg` | send the same `traceparent` on every call |
| `rtg_unavailable` | the RTG cannot be reached from the Lambda, or is slow | check the URL, a VPC without internet, and `REVA_TIMEOUT_SECONDS` against the function timeout |
| `rtg_unavailable` with status `401` in the log | wrong token or auth mode (with `REVA_FAIL_OPEN=true` these calls would pass instead) | the value of the secret (it may take 5 minutes to be picked up), `REVA_AUTH_MODE` |
| `rtg_rejected` (the RTG answers `400`) | the request is invalid for the store: the prompt key, or a context attribute the schema does not declare | `REVA_PROMPT_KEY`; check what `REVA_CONTEXT_MAP` sends (`REVA_DEBUG` shows the body) |
| everything is allowed although a policy should block it | the resource id matches no entity in the store, the policy reads an attribute nobody sends, or `REVA_MONITOR_MODE` is on | `REVA_TARGETS`; `REVA_CONTEXT_MAP` and the agents' arguments/`metadata`; turn monitor mode off |
| the subject is the user, not the agent (`subjectSource: user_fallback`) | the agent sent no `X-Reva-Agent-Id` and the token has no `act.sub` | send the header |
| a scope policy never fires on an agent-to-agent call | the values are not in the message `metadata`, or their names are not in `REVA_CONTEXT_MAP` | see [what agents must send](#what-agents-must-send) |
| the gateway reports it cannot invoke the interceptor | the gateway's role lacks `lambda:InvokeFunction` on the function | step 7 |

## Tests

```bash
python3 -m unittest discover -s tests -t .
```

No network and no AWS account: a loopback server stands in for the RTG, an in-memory store for the table, and
botocore's `Stubber` checks every DynamoDB request against the service model. It cannot judge the expressions'
semantics; the first run against a real table does.

## Not in v1

- evaluating inference/LLM traffic (an `invokeModel` hop on a `Model`)
- a `RESPONSE` interceptor: capturing answers, earlier-prompt `session.messages`, screening tool results
- `tools/list` filtering
- deployment templates and an attach script
- an allow-list for agent ids

## License

Apache License 2.0. See [LICENSE](LICENSE).
