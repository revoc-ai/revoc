# Secret Rules

!!! note "Authoritative reference"
    The [Rule Catalog](catalog.md) is generated from the code and lists every
    pattern with the decision the engine actually makes. Where this page
    differs from it, the catalog is correct.

REVOC ships with 10 secret detection rules active by default. Secret rules are
Security tier (3): detecting any secret in a request causes the entire request
to be blocked. A secret in a model response or tool result blocks it the same way.

## The Umbrella Rule: `secret_block_v1`

`secret_block_v1` is a catch-all Security-tier rule that fires whenever **any**
secret-type finding is detected. It blocks the request unconditionally, regardless
of any custom allow rules at lower tiers.

All individual secret rules below also feed into this umbrella.

## Rule Reference

### `secret_aws_key_v1` — AWS Access Key ID

**Pattern:** `(?:A3T[A-Z0-9]|AKIA|AGPA|AIPA|AROA|ASCA|ASIA)[A-Z0-9]{16}`

**Example:** `AKIAIOSFODNN7EXAMPLE`

**Action on request:** Block (`secret_block_v1`)

**Action on response:** Block (`secret_block_v1`)

---

### `secret_aws_secret_v1` — AWS Secret Access Key

**Pattern:** 40-character base64 string in proximity to AWS context keywords

**Example:** `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`

**Action on request:** Block

**Action on response:** Block (`secret_block_v1`)

---

### `secret_github_token_v1` — GitHub Personal Access Token

**Pattern:** `ghp_[0-9a-zA-Z]{36}` or `github_pat_[0-9a-zA-Z_]{82}`

**Example:** `ghp_16C7e42F292c6912E7710c838347Ae178B4a`

**Action on request:** Block

**Action on response:** Block (`secret_block_v1`)

---

### `secret_openai_key_v1` — OpenAI API Key

**Pattern:** `sk-[a-zA-Z0-9]{48}` or `sk-proj-[a-zA-Z0-9_\-]{64,}`

**Example:** `sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789...`

**Action on request:** Block

**Action on response:** Block (`secret_block_v1`)

---

### `secret_anthropic_key_v1` — Anthropic API Key

**Pattern:** `sk-ant-[a-zA-Z0-9\-_]{95}`

**Example:** `sk-ant-api03-...`

**Action on request:** Block

**Action on response:** Block (`secret_block_v1`)

---

### `secret_generic_api_key_v1` — Generic API Key in JSON

**Pattern:** `"(?:api[_-]?key|apikey)"\s*:\s*"([A-Za-z0-9\-_]{20,})"`

**Example:** `{"api_key": "AbCdEfGhIjKlMnOpQrSt"}`

**Action on request:** Block

**Action on response:** Block (`secret_block_v1`)

---

### `secret_private_key_v1` — PEM Private Key

**Pattern:** `-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`

**Action on request:** Block

**Action on response:** Block (`secret_block_v1`)

---

### `secret_jwt_v1` — JWT Token in Content

**Pattern:** `eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+`

**Note:** JWTs in `Authorization: Bearer` headers are not inspected by this rule —
only JWTs that appear inside message content.

**Action on request:** Block (if appears in message content)

**Action on response:** Block (`secret_block_v1`)

---

### `secret_password_json_v1` — Password Field in JSON Body

**Pattern:** `"(?:password|passwd|secret)"\s*:\s*"([^"]{6,})"`

**Example:** `{"password": "hunter2"}`

**Action on request:** Block

**Action on response:** Block (`secret_block_v1`)

## Why Requests Are Blocked (Not Redacted)

PII rules redact because the PII may be legitimately needed context — masking it
allows the request to proceed with the sensitive value removed.

Secrets are different: there is no legitimate reason to include an API key,
private key, or password in an LLM prompt. A secret in a prompt is always either
a developer error or an injection attempt. Blocking the entire request rather than
redacting the secret prevents the model from generating a response that might
reference or leak the secret through inference.

## Viewing Secret Findings in the Dashboard

Secret findings never show the matched value — only the entity type, field name,
and position in the text. You can see which rule fired and at what character offset,
but the actual key or password is never stored in the audit log or displayed.
