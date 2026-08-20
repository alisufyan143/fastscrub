# Cloud & Infrastructure Secrets Detectors 🔑

`fastscrub` features specialized zero-copy parsers for high-entropy infrastructure credentials, API tokens, cryptographic private keys, and database connection strings.

---

## 1. Cloud Provider Credentials

### AWS Access Key IDs (`[REDACTED_AWS_KEY]`)
* **Prefixes**: `AKIA`, `ASIA`, `ABIA`, `AROA`, `AIDA`
* **Length**: Exactly 20 uppercase alphanumeric characters (`[A-Z0-9]{20}`).
* **Example**:
    * Input: `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`
    * Output: `AWS_ACCESS_KEY_ID=[REDACTED_AWS_KEY]`

### Google Cloud Platform Keys (`[REDACTED_GCP_KEY]`)
* **Prefix**: `AIza`
* **Length**: Exactly 39 characters (`AIza[0-9A-Za-z\\-_]{35}`).
* **Example**:
    * Input: `apiKey: "AIzaSyExampleTestingKey123456789012345"`
    * Output: `apiKey: "[REDACTED_GCP_KEY]"`

---

## 2. Developer & CI/CD Tokens

### GitHub Personal Access Tokens (`[REDACTED_GITHUB_TOKEN]`)
* **Prefixes**: `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`
* **Specification**: Modern fine-grained (`github_pat_`) and classic (`ghp_`) GitHub credentials.
* **Example**:
    * Input: `git clone https://ghp_YOUR_GITHUB_TOKEN@github.com/org/repo`
    * Output: `git clone https://[REDACTED_GITHUB_TOKEN]@github.com/org/repo`

### GitLab Personal & OAuth Tokens (`[REDACTED_SECRET]`)
* **Prefix**: `glpat-` (20 characters, base64url charset).
* **Example**:
    * Input: `export GITLAB_TOKEN=glpat-YOUR_GITLAB_TOKEN`
    * Output: `export GITLAB_TOKEN=[REDACTED_SECRET]`

### PyPI Upload Tokens (`[REDACTED_SECRET]`)
* **Prefix**: `pypi-AgEIcHlwaS5vcmc`
* **Specification**: Scoped upload tokens for Python Package Index.
* **Example**:
    * Input: `twine upload -u __token__ -p pypi-YOUR_PYPI_TOKEN dist/*`
    * Output: `twine upload -u __token__ -p [REDACTED_SECRET] dist/*`

---

## 3. AI & LLM Platform Keys

### OpenAI API & Admin Keys (`[REDACTED_SECRET]`)
* **Prefixes**: `sk-proj-`, `sk-admin-`, `sk-` (followed by 48+ base64url characters).
* **Example**:
    * Input: `openai.api_key = "sk-proj-YOUR_OPENAI_KEY"`
    * Output: `openai.api_key = "[REDACTED_SECRET]"`

### Anthropic Claude API Keys (`[REDACTED_SECRET]`)
* **Prefix**: `sk-ant-` (followed by 90+ base64url characters).
* **Example**:
    * Input: `client = anthropic.Anthropic(api_key="sk-ant-YOUR_ANTHROPIC_KEY")`
    * Output: `client = anthropic.Anthropic(api_key="[REDACTED_SECRET]")`

### HuggingFace User Access Tokens (`[REDACTED_SECRET]`)
* **Prefix**: `hf_` (followed by 34+ alphanumeric characters).
* **Example**:
    * Input: `huggingface-cli login --token hf_YOUR_HUGGINGFACE_TOKEN`
    * Output: `huggingface-cli login --token [REDACTED_SECRET]`

---

## 4. Financial & Communication Services

### Stripe Live & Test API Keys (`[REDACTED_STRIPE_KEY]`)
* **Prefixes**: `sk_live_`, `sk_test_`, `rk_live_`, `rk_test_`, `pk_live_`, `pk_test_`
* **Length**: Standard 24 to 34 alphanumeric characters.
* **Example**:
    * Input: `stripe.api_key = "sk_live_YOUR_STRIPE_KEY"`
    * Output: `stripe.api_key = "[REDACTED_STRIPE_KEY]"`

### Slack Bot & User Tokens (`[REDACTED_SLACK_TOKEN]`)
* **Prefixes**: `xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-`
* **Example**:
    * Input: `SLACK_BOT_TOKEN = "xoxb-YOUR_SLACK_BOT_TOKEN"`
    * Output: `SLACK_BOT_TOKEN = "[REDACTED_SLACK_TOKEN]"`

### HashiCorp Vault Tokens (`[REDACTED_SECRET]`)
* **Prefixes**: `hvs.`, `hvb.` (Vault Service & Batch tokens).
* **Example**:
    * Input: `VAULT_TOKEN=hvs.YOUR_VAULT_TOKEN`
    * Output: `VAULT_TOKEN=[REDACTED_SECRET]`

---

## 5. Web & Database Credentials

### JSON Web Tokens (`[REDACTED_JWT]`)
* **Anchor**: `.`
* **Format**: Three base64url segments separated by dots (`header.payload.signature`).
* **Validation**: Header must decode to JSON starting with `{"alg":...` (typically `eyJ...`).
* **Example**:
    * Input: `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozG4m1e_k7k...`
    * Output: `Bearer [REDACTED_JWT]`

### Database Connection Strings (`[REDACTED_DB_CONN]`)
* **Anchor**: `:` followed by `//`
* **Schemes**: `postgres://`, `postgresql://`, `mysql://`, `mongodb://`, `mongodb+srv://`, `redis://`, `amqp://`, `cassandra://`
* **Validation**: Parses URI credentials `user:password@host:port/database`.
* **Example**:
    * Input: `DATABASE_URL=postgresql://db_user:P@ssw0rd123!@postgres.internal.net:5432/production`
    * Output: `DATABASE_URL=[REDACTED_DB_CONN]`

### Cryptographic Private Key Blocks (`[REDACTED_PRIVATE_KEY]`)
* **Anchors**: `-----BEGIN`
* **Types**: RSA, DSA, EC, OPENSSH, PGP, and standard PKCS#8 `PRIVATE KEY` blocks.
* **Example**:
    * Input: `-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----`
    * Output: `[REDACTED_PRIVATE_KEY]`
