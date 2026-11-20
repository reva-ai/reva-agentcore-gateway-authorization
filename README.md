# Reva runtime authorization for Amazon Bedrock AgentCore Gateway

A Lambda **interceptor** for an AgentCore Gateway. Before the gateway forwards a request to a target, it asks
Reva's RTG whether the call is allowed. The call either goes through, or the Lambda answers on the gateway's behalf
with a refusal and the tool or agent never runs.

It is the gateway-side counterpart of the Claude Code plugin, and it speaks the same RTG contract
(`POST /pdp/ai/access/ai/evaluation` with `rtg/a2a` body; a `2xx` with `decision: true` is an allow, a `403`
carrying a verdict is a deny; `X-Reva-Token-Request: transaction` mints a txn token).

```
agent ──► AgentCore Gateway ──► [ this Lambda ] ──► target (MCP tool / agent)
                                    │
                       RTG decision │   hop history lives in the RTG (Postgres)
                                    ▼
                                   RTG
```

**Contents**

1. [How it works](#how-it-works)
2. [Setup, step by step](#setup-step-by-step)
3. [Deploy with CloudFormation](#deploy-with-cloudformation) (instead of most of the setup steps)
4. [What agents must send](#what-agents-must-send)
5. [Verify it](#verify-it)
6. [Going live, updating, rolling back](#going-live-updating-rolling-back)
7. [Reference](#reference): [what it governs](#what-it-governs), [context variables](#context-variables),
   [who is calling](#who-is-calling-token-enrich),
   [history](#history), [failure behaviour](#failure-behaviour), [configuration](#configuration)
8. [Example: renamed tools and a prefixed policy store](#example-renamed-tools-and-a-prefixed-policy-store)
9. [Troubleshooting](#troubleshooting)
10. [Tests](#tests) and [what is not in v1](#not-in-v1)

## How it works

For every request that reaches the gateway, the Lambda:

1. works out **what is being called** from the shape of the payload (a tool, or an agent) and **who is calling**
   (token enrich: user JWT on `Authorization`, and on nested hops the minted `X-Transaction-Token`);
2. asks the RTG, sending `traceparent` on every hop, and on the first call of a trace the thread id and `session.id`
   so the RTG can attach earlier turns (nested hops send the txn token instead; the RTG already has the thread);
3. on an allow, lets the request through (and injects a minted txn token); on a deny, answers `403` itself.
4. on the RESPONSE of the UI chat turn, best-effort POSTs `/trace/summarize` so later turns get `session.messages`.

Hop history lives in the RTG. The interceptor sends `traceparent`, and on the first call the thread id and
`session.id`; it does not send `context.hops` or prior `session.messages`.

It fails closed: if the RTG is unavailable, or anything is misconfigured, the call is denied (see
[failure behaviour](#failure-behaviour) for the one switch that changes this).

The code is plain Python: the standard library plus `boto3`, which the Lambda runtime already provides (Secrets
Manager). There is nothing to install into the zip.

## Setup, step by step

**Two ways to set it up. Pick one.**

| | A. CloudFormation (one stack) | B. By hand |
|---|---|---|
| What it does | Creates the token secret, the role and the function in one stack | You create each of them yourself (steps 1 to 6) |
| What you follow | [Deploy with CloudFormation](#deploy-with-cloudformation), then steps 7 to 9 | Steps 1 to 9 below |
| Choose it when | you want the quickest start | you want to control each piece, or already have some of them |

Either way you attach the interceptor to the gateway (step 7) and update the agents (step 8) yourself, and you check it
works (step 9). The code is the same in both: build the zip as in step 3, getting the code first as described there.

Names used below (change them if you like): role `reva-interceptor-role`, function
`reva-agentcore-interceptor`. Replace `<region>` and `<account-id>` throughout. Create the Lambda in the **same
region** as the gateway, and the secret in the **Lambda's region**.

You need:

- an AWS account where you may create an IAM role and a Lambda function, and may edit the gateway and its service role;
- an AgentCore Gateway whose authorizer accepts the **user's JWT** (the interceptor reads the user from it);
- a Reva **RTG token** (it goes into AWS Secrets Manager, step 1) and the RTG base URL if it is not
  `https://api.reva.ai`, with your agents, tools and policies already set up on the Reva side (including RTG
  trace/history tables for multi-hop context);
- the AWS CLI v2 if you want to use the commands. Every step also has console instructions.

### 1. Store the RTG token in Secrets Manager

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
`REVA_TOKEN_SECRET` in step 5. The function then fetches exactly that secret, whatever it is called and whichever
account it is in (see [Several AWS accounts](#several-aws-accounts)). Without the variable it falls back to the name
`reva/secrets`, so a secret created with that name works with no setting at all.

In a JSON secret the function reads the field `RTG_TOKEN`. To keep the token under another field name, set
`REVA_TOKEN_SECRET_KEY` to it: with `REVA_TOKEN_SECRET_KEY=ACME_RTG_TOKEN` the value of the field `ACME_RTG_TOKEN` is
used and every other field is ignored. A secret encrypted with the default key (`aws/secretsmanager`) needs no extra
permission; with your own KMS key the role also needs `kms:Decrypt` on it.

### 2. Create the Lambda's execution role

The role lets the function write its logs and read the token secret.

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

Secrets Manager adds a random suffix to a secret's ARN (`reva/secrets-AbCdEf`), which is why the policy ends in
`-*`; once you set the full ARN in `REVA_TOKEN_SECRET`, you can put that exact ARN there instead. Without
`secretsmanager:GetSecretValue` every call is denied with `token_unavailable`.

### 3. Build the zip

**Get the code first.** Clone the repository, or unzip GitHub's "Download ZIP" and open the folder it creates:

```bash
git clone https://github.com/reva-ai/reva-agentcore-gateway-authorization.git
cd reva-agentcore-gateway-authorization
```

Then, from the root of that folder (the one that contains `handler.py`):

```bash
zip -r interceptor.zip handler.py interceptor -x "*__pycache__*"
```

`handler.py` must sit at the top of the zip, next to the `interceptor/` folder. Check with `unzip -l interceptor.zip`.
(`interceptor.zip` is git-ignored.)

**Upload the zip you build with this command, not the zip GitHub gives you.** GitHub's "Download ZIP" wraps everything
in a folder (`reva-agentcore-gateway-authorization-main/`), so `handler.py` is not at the top of it and Lambda fails with
`Unable to import module 'handler'`. You can name your zip anything: use the same name wherever the steps say
`interceptor.zip`.

### 4. Create the Lambda function and upload the zip

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

Do not put the Lambda in a VPC unless the VPC can reach the RTG (internet or a private link). A function that
cannot reach the RTG denies every call with `rtg_unavailable`.

### 5. Set the environment variables

**Console:** Configuration tab → Environment variables → Edit → Add environment variable. Values that are JSON
(`REVA_TARGETS`, `REVA_CONTEXT_MAP`) go on one line.

One variable is recommended: **`REVA_TOKEN_SECRET`**, set to the secret's full ARN (step 1). No variable is strictly
required: the host is `https://api.reva.ai`, the token is looked up by the name `reva/secrets` if the variable is not
set, and the RTG is called with `X-API-Token: Bearer <token>`. Set these as your setup needs:

| Variable | When |
|---|---|
| `REVA_TOKEN_SECRET` | **recommended**: the secret's full ARN, for example `arn:aws:secretsmanager:us-west-2:123456789012:secret:reva/secrets-AbCdEf`. Needed when the secret is not named `reva/secrets` or is in another account |
| `REVA_TOKEN_SECRET_KEY` | the secret is JSON and holds the token under a field other than `RTG_TOKEN` |
| `REVA_BASE_URL` | the RTG is not at `https://api.reva.ai` |
| `REVA_AUTH_MODE=bearer` | the RTG expects the gateway credential in `Authorization: Bearer` instead of `X-API-Token: Bearer` |
| `REVA_TARGETS` | a gateway target's name differs from the tool or agent id in your policy store |
| `REVA_CONTEXT_MAP` | a policy reads a value from the call under another name than the call's own (see [context variables](#context-variables)) |

For the first run, also set `REVA_MONITOR_MODE=true` (a deny is logged but the call still goes through) and
`REVA_DEBUG=true` (logs the event's shape and the RTG request; it contains prompts). Remove both before real use.

There is no `REVA_TOKEN` variable. Setting one is a configuration error, so a token is never left sitting in the
function's configuration by accident.

The full list is in [configuration](#configuration). A bad value never crashes the function: it is reported in the
log and every call is denied with `config_error` until you fix it.

### 6. Let the gateway invoke the function

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

### 7. Attach the interceptor to the gateway

The gateway needs **REQUEST + RESPONSE** with **`passRequestHeaders: true`**. Without that flag the gateway
does not hand the Lambda any headers, so it never sees the user's token or the `traceparent`, and every call is
denied with `missing_authorization`. RESPONSE finalizes the turn (`/trace/summarize`) for `session.messages`.

Save this as `interceptors.json`:

```json
[{
  "interceptor": {"lambda": {"arn": "arn:aws:lambda:<region>:<account-id>:function:reva-agentcore-interceptor"}},
  "interceptionPoints": ["REQUEST", "RESPONSE"],
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

A gateway holds at most one REQUEST and one RESPONSE interceptor. Attach this Lambda as **both**:
REQUEST evaluates the call; RESPONSE best-effort POSTs `/pdp/ai/access/ai/trace/summarize` at the
**end of the UI chat turn** (when the session/thread key is present again — not mid-trace nested hops)
so later turns get `session.messages`. Some HTTP RESPONSE events arrive without a `gatewayRequest`: a Runtime
agent can then embed `_reva` in its JSON body. A tool's `Mcp-Session-Id` does not mark the entry
hop, because agents send it on their nested tool calls as well.

### 8. Update the agents

Every agent that calls through the gateway has to send a few things. See [what agents must send](#what-agents-must-send).
The ones that matter most are the same `traceparent` on every call of a prompt, the user's JWT, and
on nested hops the minted `X-Transaction-Token` (token enrich).

### 9. Check that it works

See [verify it](#verify-it).

## Deploy with CloudFormation

The template [cloudformation/agentcore-gateway-interceptor.json](cloudformation/agentcore-gateway-interceptor.json)
does setup steps 1 to 4 and 6 in one stack. Attaching the interceptor to the gateway (step 7) and updating the agents
(step 8) stay manual: CloudFormation cannot change a gateway it did not create.

| The stack creates | Name |
|---|---|
| Secrets Manager secret for the RTG token | `reva/secrets`, holding `{"RTG_TOKEN": "abc"}` (parameter `TokenSecretName`) |
| Lambda function, its execution role and log group | generated names |
| Permission for the gateway to invoke the function | only when you set `GatewayServiceRoleName` |

**1. Put the zip in S3.** CloudFormation reads the code from a bucket in the stack's region. Build the zip as in step 3
(get the code first, and upload the zip you build, not GitHub's own download), then upload it under a new key for each
version:

```bash
zip -r interceptor.zip handler.py interceptor -x "*__pycache__*"
aws s3 cp interceptor.zip s3://<bucket>/interceptor-1.0.0.zip --region <region>
```

**2. Deploy the stack.** In the console: CloudFormation → Create stack → upload the template file.

```bash
aws cloudformation deploy --template-file cloudformation/agentcore-gateway-interceptor.json \
  --stack-name reva-agentcore-interceptor --capabilities CAPABILITY_IAM --region <region> \
  --parameter-overrides CodeS3Bucket=<bucket> CodeS3Key=interceptor-1.0.0.zip \
  GatewayServiceRoleName=<name of your gateway's service role>
```

Leave out `GatewayServiceRoleName` if you would rather add the invoke permission yourself (step 6).

**3. Set the real token.** The secret is created with the placeholder value `abc`. Replace it: Secrets Manager → `reva/secrets`
→ Retrieve secret value → Edit, and keep the field name `RTG_TOKEN`. Or from a shell (the token is not echoed or
stored in the shell history):

```bash
read -rs RTG_TOKEN && aws secretsmanager put-secret-value --secret-id reva/secrets --region <region> \
  --secret-string "{\"RTG_TOKEN\": \"$RTG_TOKEN\"}" && unset RTG_TOKEN
```

The function uses the new value within 5 minutes. Until then the RTG rejects `abc` and calls are denied; keep `FailOpen`
at its default `false`, because with `true` a rejected token would let calls through unchecked.

**4. Attach the interceptor.** The stack's `InterceptorConfiguration` output is the `interceptors.json` of step 7:

```bash
aws cloudformation describe-stacks --stack-name reva-agentcore-interceptor --region <region> \
  --query "Stacks[0].Outputs[?OutputKey=='InterceptorConfiguration'].OutputValue" --output text > interceptors.json
```

Then run step 7's `update-gateway` with it, update the agents (step 8) and check it works ([verify it](#verify-it)).

Parameters that matter most (the others map to the `REVA_*` settings in the [configuration](#configuration) table and
all have defaults):

| Parameter | Default | |
|---|---|---|
| `CodeS3Bucket`, `CodeS3Key` | required, `interceptor.zip` | where the zip is |
| `RtgBaseUrl`, `RtgAuthMode` | `https://api.reva.ai`, `api-token` | the RTG and how the token is sent |
| `TargetsJson`, `ContextMapJson` | `{}`, `{}` | `REVA_TARGETS` and `REVA_CONTEXT_MAP` |
| `MonitorMode`, `FailOpen`, `DebugLogging` | `false` | the first run's `MonitorMode=true` logs denials without blocking |
| `GatewayServiceRoleName` | empty | the gateway's service role, to give it permission to invoke the function |

Good to know:
- The stack fails if a secret named `reva/secrets` already exists in the region. Change `TokenSecretName`, or delete
  the existing one. Two stacks in one region need different secret names.
- To update the code (redeploy): zip → upload under a **new** `CodeS3Key` →
  `cloudformation deploy` with that key (and your existing parameters). See
  [CLOUDFORMATION_SETUP.md — Updating the interceptor code later](CLOUDFORMATION_SETUP.md#updating-the-interceptor-code-later-redeploy).
  Editing the secret's value is not undone by a stack update.
- Hop history lives in the RTG and is unaffected by deleting the stack. Secrets Manager keeps a deleted secret for a
  recovery period, so a stack re-created straight away may need a different `TokenSecretName`.

## What agents must send

| | Required | Why |
|---|---|---|
| `Authorization: Bearer <user JWT>`, and `passRequestHeaders: true` on the gateway | yes on the UI entry hop; send on nested hops when the runtime forwards it | token enrich: RTG reads the user from the JWT (`REVA_USER_CLAIM`) |
| the same W3C **`traceparent`** on every call of one prompt | yes | correlates hops so the RTG can attach earlier history. An OpenTelemetry-instrumented HTTP client normally propagates it; check yours |
| a **session/thread id** on the UI chat turn: `X-Reva-Session-Id` (preferred), or `X-Reva-Thread-Id`, or A2A `contextId`, or `Mcp-Session-Id` | yes for multi-turn chat + summarize | links prompts of one chat. Only `X-Reva-Session-Id` / `X-Reva-Thread-Id` mark the entry RESPONSE for `/trace/summarize`. It is sent to the RTG on the first call only; nested hops (a txn token is present) send none. Without one, each prompt is its own chat |
| `X-Transaction-Token` from the prior allow on nested hops | yes for nested hops | token enrich: RTG derives Agent subject from the token. Entry allow mints it via `X-Reva-Token-Request: transaction` |
| values a policy needs to see (countries, clients, ...) in the call: **tool arguments** for a tool call, the **`metadata`** of the request, message or parts for an agent call | only where a policy reads them | sent under their own names ([context variables](#context-variables)); `REVA_CONTEXT_MAP` renames chosen keys to the attributes a policy reads |
| hop lists, conversation blocks, prior `session.messages`, turn numbers | **no** | kept by the RTG; the interceptor only sends `session.id` |

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

`metadata` is a standard, free-form A2A field. Every key in the request's, the message's and each part's `metadata`
is sent on to the RTG under its own name, within the [rules for context variables](#context-variables); an empty
value is left out. The A2A HTTP+JSON binding carries the same fields in `POST /<agent>/message:send`'s body.

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
# Use a registered alg (e.g. HS256). RTG's go-jwt ParseUnverified rejects alg:none.
# The signature is not verified (ingress already authenticated the caller).
b = lambda d: base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).rstrip(b"=").decode()
print(f"{b({'alg': 'HS256', 'typ': 'JWT'})}.{b({'sub': 'test-user'})}.e30")
EOF
```

- **Allowed:** the response is `{"interceptorOutputVersion": "1.0", "mcp": {"transformedGatewayRequest": {"body": ...}}}`.
- **Denied:** the response has `transformedGatewayResponse` with `statusCode` `403` and a `data.code` saying why.

A test event is a real call: it goes to the RTG. The interceptor does not write a local hop row; the RTG records the
hop in its own store.

### End to end

1. Ask your agent a question that crosses the gateway.
2. **CloudWatch Logs** → log group `/aws/lambda/reva-agentcore-interceptor`. Each evaluated call logs one line like
   `{"event":"decision","decision":"permit","outcome":"allow","trace":"...","traceSource":"traceparent","thread":"...",
   "action":"invokeTool","resource":"my-target/my_tool","subjectType":"derived","subjectSource":"transaction_token",
   ...}`. `decision` is `permit`, `deny`, or one of `permit_conditional`, `monitor_would_deny` (monitor mode: the RTG
   said no, the call went through) and `permit_fail_open` (the RTG could not be asked and `REVA_FAIL_OPEN=true`).
   Check that `trace` is the same for every hop of the prompt, `subjectType` is what you expect, and `traceSource`
   says `traceparent`.
4. In the **RTG's decision log**, hops of one prompt share a `traceparent` / thread id; the RTG attaches earlier
   hops from its store for that trace.

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
2. Rebuild the zip (step 3) and upload it (Code → Upload from → .zip file). The handler and the environment
variables stay as they are.
3. Run a test event.

**Rolling back:** upload the zip you downloaded. To take the interceptor out of the path altogether, remove it from
the gateway's interceptor configuration (step 7).

## Reference

### What it governs

It reads the gateway event, works out *what is being called* from the shape of the payload, and asks the RTG
about that. Entity types come from the protocol; ids come from the payload.

| Payload | action | resource | prompt sent to the RTG |
|---|---|---|---|
| MCP `tools/call`, `params.name = <target>___<tool>` | `invokeTool` | `Tool` `<target>/<tool>` | the arguments as JSON |
| A2A `message/send` (JSON-RPC) to `/<target>/invocations` | `invokeAgent` | `Agent` `<target>` | the message's text parts, and its data parts as JSON |
| A2A HTTP+JSON binding: `POST /<target>/message:send` or `/message:stream` | `invokeAgent` | `Agent` `<target>` | the same |
| plain AgentCore Runtime call to `/<target>/invocations` | `invokeAgent` | `Agent` `<target>` | `prompt` / nested `input.prompt` / …, else the body |
| Gateway inference / OpenAI-compatible `chat/completions` (`model` + `messages`) | `invokeModel` | `Model` `<model>` | last user message |
| MCP `initialize`, `tools/list`, `ping`, notifications, GET/DELETE | not evaluated | | |
| anything else on an HTTP target | not evaluated by default (`REVA_UNCLASSIFIED=deny` refuses it) | | |

LLM hops only appear when the agent's model client uses the gateway (e.g. `AGENTCORE_LLM_URL`). Direct
OpenAI/Bedrock calls never reach this Lambda.

`REVA_TARGETS` can rename a target's entity id (`{"acme-tools": {"id": "acme-mcp"}}`) or exclude a target
(`{"public": {"kind": "skip"}}`). It is the only topology configuration.

### Context variables

Besides the prompt, the interceptor sends name/value pairs from the request body to the RTG as `context`, so a
policy can match on them, for example *refuse this tool when `priority` is `high`*. The rules are the Kong plugin's
(2.1.0). Which fields are read depends on the call:

| Call | Read from | Sent under |
|---|---|---|
| MCP `tools/call` | everything in `params` except the tool name: `arguments` and `_meta` | the field's own name, so `_meta.progressToken` is sent as `progressToken` |
| A2A (JSON-RPC and HTTP+JSON) | every `metadata` object: the request's, the message's and each message part's | the metadata's own names |
| Model (OpenAI chat) | `metadata`, and the settings at the top of the body, such as `max_tokens`, `stream` and `user` | the field's own name |

`model`, `messages` and `tools` are not context: the model is the resource and the messages are the prompt.
Everything in the fields above goes to the RTG (a tool's arguments already travel in the prompt), so keep out of
them anything you do not want evaluated, or set `REVA_CONTEXT_FROM_BODY=false`.

- A nested object becomes dotted names: `{"customer": {"tier": "gold"}}` is sent as `customer.tier`.
- When a name appears more than once, the more specific one wins: a part's metadata over the message's over the
  request's; MCP `arguments` over `_meta`; for a model call, a top-level setting over `metadata`.
- Only these values are sent: text, `true` or `false`, whole numbers, and lists of one of those. Null, decimals (so
  `temperature: 0.2`), objects inside lists, empty values and lists that mix types are left out.
- Names the RTG uses itself (`action`, `subject`, `resource`, `history` and a few others), names that look like
  credentials (`password`, `apiKey`, `authorization`, `cookie`), and values that look like a bearer token or a JWT
  are left out.
- A call carries at most 64 pairs and 512 bytes of JSON in all. When there is more, the pairs that fit are sent,
  taken in alphabetical order of name, and the rest are left out.
- Context is sent on every call, first or later hop, and describes that call.
- `REVA_CONTEXT_MAP` copies chosen keys to the attribute names a policy reads (`countries` becomes
  `Acme_req_countries`). Mapped pairs follow the same rules, replace a body pair of the same name, and
  are first in line for the 64 pairs and 512 bytes.
- The RTG refuses a whole request when one pair is outside what it reads. The pairs are filtered first; if the RTG
  still answers `400` to a request carrying context, the call is evaluated once more without it.
- With `REVA_DEBUG=true` the log lists, by name and reason and never by value, the pairs that were left out
  (`debug_context_left_out`).

### Who is calling (token enrich)

| | Where it comes from |
|---|---|
| **principal** (`User`) | the bearer JWT's `REVA_USER_CLAIM` (default `sub`), when `Authorization` is present. |
| **subject (UI entry hop)** | `User` from the JWT (body includes `subject` / `principal`), `transmission.role` is `user`. |
| **subject (nested hop)** | derived by the RTG from `X-Transaction-Token` (body omits subject/principal and the thread id; `transmission.role` is the call's own, `agent` by default). Send the user JWT as well when the runtime forwards it (`Authorization` + txn). |
| **groups** | optional: the claim in `REVA_GROUPS_CLAIM` becomes `UserGroup` parents of the user (entry hop only). |

The gateway has already validated the JWT, so it is decoded without re-verifying. Nested Agent identity
comes from the minted transaction token, not from `X-Reva-Agent-Id`. Absence of a txn token is **not**
how entry vs nested is decided for summarize — that uses the explicit `X-Reva-Session-Id` / `X-Reva-Thread-Id` on the call.

### History

The RTG keeps thread/hop history (Postgres `trace_hop` / tracesummary). The interceptor sends `traceparent` and,
on the first call of a trace, the thread id and `session.id` (same value); a nested hop sends the txn token and
no thread. It does not send `context.hops` or prior `session.messages`. On the
RESPONSE of the UI chat turn it POSTs `/trace/summarize` with the final answer, read from the response body: an
OpenAI chat completion, an MCP tool result, an A2A Message or Task (JSON-RPC or HTTP+JSON), or a Runtime agent's
`message` / `reply` / `text` / `content` / `output`. A body that is not JSON, or in no known shape, is sent as it
is, up to 16 KB.

### Failure behaviour

| Situation | Result |
|---|---|
| RTG `403` with a verdict (a `decision` or `error_type` in the body), a `2xx` with `decision: false`, a `2xx` with no `decision: true`, or `401 USER_NOT_FOUND`/`USER_DISABLED` | **deny** (`REVA_MONITOR_MODE=true` logs it and passes) |
| any other RTG `4xx` (the request is invalid) | **deny**, never fails open. A `400` on a request that carried context is first evaluated again without it |
| RTG `401`/`404`/`408`/`413`/`424`/`425`/`429`/`5xx`, a `403` with no verdict (an edge or proxy refusing, not the RTG), timeout, unreachable | **deny**; **pass** if `REVA_FAIL_OPEN=true`. Transient faults are retried once inside the time the Lambda has left |
| RTG `200` with `guardrails.outcome = conditional_allow` | **deny** (the gateway has no "ask"); `REVA_CONDITIONAL_ALLOW=allow` passes |
| the RTG token cannot be read from Secrets Manager (and none was read before) | **deny** with `token_unavailable`, never fails open: without the credential the RTG cannot be asked |
| no user token, no principal claim, a malformed MCP body, a JSON-RPC batch containing `tools/call`, bad configuration, any internal error | **deny**, never fails open |

A deny is HTTP `403` (`REVA_DENY_STATUS`). MCP and A2A calls get a JSON-RPC error whose `data.code` says why; a plain
Runtime call gets `{"error": {"type": "permission_denied", "code": ..., "message": ...}}`. The caller sees only
`REVA_DENY_MESSAGE` and the code; the RTG's reason is in the Lambda log. Tokens, JWTs and headers are never logged.

| Code | Meaning |
|---|---|
| `policy_denied` | the RTG said no (or `conditional_allow` with `REVA_CONDITIONAL_ALLOW=deny`) |
| `rtg_rejected` | the RTG found the request invalid (a `4xx` other than `401`/`403`/`404`/`408`/`413`/`424`/`425`/`429`) |
| `rtg_unavailable` | the RTG could not be asked or answered with an outage-type status (or a `403` with no verdict) |
| `token_unavailable` | the RTG token could not be read from Secrets Manager |
| `config_error` | a configuration value is invalid; the log line names it |
| `missing_authorization`, `invalid_authorization`, `principal_unresolved` | no bearer token, not a JWT, or no user claim |
| `traceparent_missing` | no trace id and `REVA_ON_MISSING_TRACEPARENT=deny` |
| `malformed_body`, `batch_unsupported`, `malformed_event` | the request is not something it can judge safely |
| `unresolvable_resource`, `unclassified_traffic` | no entity id could be worked out, or `REVA_UNCLASSIFIED=deny` |
| `internal_error` | an unexpected exception, turned into a deny |

AWS does not document what the gateway does when an interceptor Lambda errors or times out, and says it may retry
the call. So the function never raises (an unexpected exception becomes a deny), and everything it writes is safe
to repeat.

### Several AWS accounts

By default the secret the function uses is in **its own account and region** (found by name). With several accounts
there are two ways to go.

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

Keep the interceptor Lambda in the gateway's account: AWS's pages do not document a gateway invoking a function in
another account.

### Configuration

Everything is an environment variable.

| Variable | Default | |
|---|---|---|
| `REVA_BASE_URL` | `https://api.reva.ai` | RTG base URL; the path is fixed |
| `REVA_TOKEN_SECRET`, `REVA_TOKEN_SECRET_KEY` | `reva/secrets`, `RTG_TOKEN` | the Secrets Manager secret holding the RTG credential. **Recommended: set `REVA_TOKEN_SECRET` to the secret's full ARN**; the name is only the fallback, and a secret in another account needs its ARN (see "Several AWS accounts"). It is read on the first evaluated call and every 5 minutes. A plaintext secret is the token; a JSON secret is read at the key. `REVA_TOKEN` is not read: setting it is a configuration error |
| `REVA_AUTH_MODE` | `api-token` | `api-token` sends `X-API-Token: Bearer <token>` (the user's JWT stays on `Authorization`); `bearer` sends the token as `Authorization: Bearer` (+ `policyStoreId` if set). The summarize call always uses `Authorization: Bearer` |
| `REVA_POLICY_STORE_ID` | | optional; sent as `policyStoreId` in bearer mode. Normally unnecessary: the edge gateway takes the store from the token. Needed when the RTG is called directly |
| `REVA_VERIFY_USER_SCOPE`, `REVA_ORIGIN_APP` | off | send `X-Reva-Verification-Codes: CODE_USER_SCOPE` and `X-API-Origin-App` for the edge's known-user check. `REVA_VERIFY_USER_SCOPE=true` needs `REVA_ORIGIN_APP` (otherwise a configuration error) |
| `REVA_PROMPT_KEY` | `userQuery` | name of the prompt field in `transmission` (older stores use `content`) |
| `REVA_TIMEOUT_SECONDS`, `REVA_RETRIES`, `REVA_SAFETY_MARGIN_MS` | `15`, `1`, `2000` | per-attempt timeout, retries, time kept back from the Lambda's own deadline |
| `REVA_USER_CLAIM` | `sub` | principal claim |
| `REVA_GROUPS_CLAIM` | off | list claim → `UserGroup` parents |
| `REVA_TARGETS` | `{}` | per-target `id` alias, `endpoint`, `kind: skip` |
| `REVA_CONTEXT_FROM_BODY` | `true` | send the name/value pairs of the request body as context (see [context variables](#context-variables)); `false` sends only what `REVA_CONTEXT_MAP` names |
| `REVA_CONTEXT_MAP` | `{}` | `{"<argument>": "<Cedar context attribute>"}`: sends a call's argument under the attribute name a policy reads. A tool call's arguments are `params.arguments`; an agent call's (A2A) are the `metadata` of the message, the send params and the request. Empty values are dropped; a mapped pair replaces a body pair of the same name |
| `REVA_UNCLASSIFIED` | `skip` | `deny` refuses HTTP traffic that is neither A2A nor `/<target>/invocations` |
| `REVA_UNKNOWN_RESOURCE` | `deny` | `unknown` sends `unknown-*` ids instead (reads as allow at the RTG) |
| `REVA_EVAL_BUILTIN_TOOLS` | `false` | evaluate the gateway's own search tool |
| `REVA_TOOL_PARENTS` | `false` | also send `MCPServer` as the Tool's parent and tool properties |
| `REVA_TRACE_HEADER` | off | a header carrying a trace id, for callers that cannot send `traceparent` |
| `REVA_ON_MISSING_TRACEPARENT` | `mint` | `deny` refuses calls with no trace id. A minted trace has no history |
| `REVA_PROMPT_MAX_BYTES` | `12000` | prompt clipped before it is sent to the RTG |
| `REVA_FAIL_OPEN`, `REVA_MONITOR_MODE`, `REVA_CONDITIONAL_ALLOW` | `false`, `false`, `deny` | see "Failure behaviour" |
| `REVA_DENY_MESSAGE`, `REVA_DENY_STATUS` | generic message, `403` | |
| `REVA_DEBUG` | `false` | log the event's shape and the RTG request body (it contains prompts: development only) |

## Example: renamed tools and a prefixed policy store

A setup that follows the txn-token contract (a `traceparent`, the user's JWT, a thread id on the entry hop, and
`X-Transaction-Token` on nested hops) needs only a mapping. Two things in this example differ from the defaults:
the policy store knows the tool server as `acme-mcp` (the gateway target is `acme-tools`), and it prefixes Cedar
attributes with `Acme_` (see `tests/test_example_profile.py`):

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
  `Acme_req_countries`). The interceptor sends a call's arguments and metadata under their own names too,
  but this store's policies read the prefixed names, so a scope `forbid ... when` needs the map to match. Policies
  that read the call's own names need no map. A tool call carries its arguments in `params.arguments`. An agent
  call (A2A `message/send`) has no argument map, so the caller's free-form `metadata` plays that part: it is read
  from the message, the send params and the request, the most specific winning a repeated key. An agent that wants
  a scope policy to judge its hand-off puts the values in `metadata` under names the map lists.

There is no store id in the block: the edge gateway reads it from the token. The token itself is in the Secrets
Manager secret (`reva/secrets`), not in the block.

Scope values reach the RTG as context: a tool call's arguments or an agent call's A2A `metadata`, under their own
names and, where `REVA_CONTEXT_MAP` names them, under the policy's attribute names. Agents do not assert hop lists,
conversation blocks, or scope blocks.

## Troubleshooting

The Lambda's log group is `/aws/lambda/<function name>`. Useful lines have an `event` field: `decision`,
`local_deny` (denied before asking the RTG; `code` says why), `warn`, `error`, `skip`.

| Symptom | Cause | Fix |
|---|---|---|
| every call denied, `config_error` | a bad environment variable; the log line names it. Usual suspects: JSON that does not parse in `REVA_TARGETS` or `REVA_CONTEXT_MAP`, a leftover `REVA_TOKEN` (the token now comes from Secrets Manager) | fix or delete the variable |
| every call denied, `token_unavailable` | the secret cannot be read: it does not exist under that name in the function's region, the role lacks `secretsmanager:GetSecretValue` on it (or `kms:Decrypt` on its key), or a JSON secret has no field `RTG_TOKEN`; for another account's secret, its resource policy or its key's policy does not allow the role | step 1 and step 2; the log line's reason names the cause |
| `missing_authorization` | the gateway is not passing headers, or a call has neither a bearer JWT nor a txn token | step 7: `passRequestHeaders: true`; send the user JWT (and txn token on nested hops) |
| `invalid_authorization` or `principal_unresolved` | the token is not a JWT, or has no `sub` (or the claim in `REVA_USER_CLAIM`) | send the user's JWT; set `REVA_USER_CLAIM` |
| `rtg_unavailable` | the RTG cannot be reached from the Lambda, or is slow | check the URL, a VPC without internet, and `REVA_TIMEOUT_SECONDS` against the function timeout |
| `rtg_unavailable` with status `401` in the log | wrong token or auth mode (with `REVA_FAIL_OPEN=true` these calls would pass instead) | the value of the secret (it may take 5 minutes to be picked up), `REVA_AUTH_MODE` |
| `rtg_rejected` (the RTG answers `400`) | the request is invalid for the store: the prompt key, or a context attribute the schema does not declare | `REVA_PROMPT_KEY`; check what is sent as context (`REVA_DEBUG` shows the body and names what was left out). A `400` caused by context alone is retried without it |
| everything is allowed although a policy should block it | the resource id matches no entity in the store, the policy reads an attribute nobody sends, or `REVA_MONITOR_MODE` is on | `REVA_TARGETS`; `REVA_CONTEXT_MAP` and the agents' arguments/`metadata`; turn monitor mode off |
| nested hop still sends User in the body (`subjectSource: user`) | prior hop's transaction token was not forwarded | forward `X-Transaction-Token` from the previous allow |
| a scope policy never fires on an agent-to-agent call | the values are not in the `metadata`, their names differ from the policy's (and are not in `REVA_CONTEXT_MAP`), or the value was left out by a [context rule](#context-variables) (a decimal, a name like `password`, more than 512 bytes) | see [what agents must send](#what-agents-must-send); `REVA_DEBUG` names what was left out |
| the gateway reports it cannot invoke the interceptor | the gateway's role lacks `lambda:InvokeFunction` on the function | step 6 |

## Tests

```bash
python3 -m unittest discover -s tests -t .
```

No network and no AWS account: a loopback server stands in for the RTG.

## Not in v1

- screening / redacting tool or model **results** on the RESPONSE leg (summarize only)
- `tools/list` filtering
- an attach script: the CloudFormation template creates the resources but does not attach the interceptor to an existing gateway
- an allow-list for agent ids

**Now included:** `invokeModel` on gateway inference / OpenAI-compatible chat bodies, and RESPONSE
`/trace/summarize` for `session.messages` (agents that call the LLM *outside* the gateway still
produce no model hop — point them at `AGENTCORE_LLM_URL` on the gateway).

## License

Apache License 2.0. See [LICENSE](LICENSE).
