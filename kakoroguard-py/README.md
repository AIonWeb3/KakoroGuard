# kakoroguard-py

Python SDK for AI Agents and LLM scripts to generate cryptographic Ed25519 identities and sign requests for the **KakoroGuard** on-chain RBAC system on Stellar & Soroban.

---

## ⚡ 5-Line Quickstart

```python
from kakoroguard import AgentKeypair, create_auth_headers
import requests

keypair = AgentKeypair.from_secret("SCZ4...YOUR_STELLAR_SECRET_SEED...")
payload = {"prompt": "Analyze treasury reserves", "max_tokens": 500}
headers = create_auth_headers(payload, keypair)
response = requests.post("https://api.provider.com/v1/inference", json=payload, headers=headers)
print(response.status_code, response.json())
```

---

## 🔑 Key Management

### Generate a New Keypair
```python
from kakoroguard import AgentKeypair

keypair = AgentKeypair.generate()
print("Agent Public Key (G-address):", keypair.public_key)
print("Agent Secret Seed (S-seed):", keypair.secret_seed)
```

### Load Existing Keys
```python
# From a Stellar StrKey secret seed:
keypair = AgentKeypair.from_secret("S...")

# From raw 32 bytes or 64-character hex seed:
keypair = AgentKeypair.from_secret("0123456789abcdef...")

# Public-key only (for verification, cannot sign):
verifier = AgentKeypair.from_public_key("G...")
```

---

## ✍️ Signing Requests & Replay Protection

KakoroGuard serializes payloads canonically (alphabetically sorted keys, strict compact separators) and binds an epoch timestamp in milliseconds to prevent replay attacks:

```python
from kakoroguard import sign_request, generate_auth_header, create_auth_headers

payload = {"action": "execute_trade", "asset": "XLM", "amount": 1000}

# 1. Sign directly:
signature_hex = sign_request(payload, keypair)

# 2. Generate structured AgentAuthHeader:
auth = generate_auth_header(payload, keypair)
print(auth.public_key, auth.timestamp, auth.signature)

# 3. Generate standard HTTP headers:
headers = create_auth_headers(payload, keypair)
# Headers produced:
# X-Agent-Public-Key: G...
# X-Agent-Timestamp: 1710000000000
# X-Agent-Signature: <64-byte Ed25519 signature in hex>
# Authorization: KakoroGuard key="G...",ts="...",sig="..."
```

---

## 🛡️ Error Handling

All SDK exceptions derive from `KakoroGuardError`:
- `AgentKeyError`: Malformed or invalid keypair/seed.
- `AgentSigningError`: Failure during request signing.
- `AgentSignatureInvalid`: Signature verification failure.
- `AgentTimestampExpiredError`: Replay attack protection failure (stale timestamp > 5m).
- `SerializationError`: Payload could not be canonically serialized.

---

## 🧪 Testing & Code Quality

```bash
# Run test suite with 100% line coverage
pytest --cov=kakoroguard --cov-report=term-missing

# Strict type checking
mypy kakoroguard

# Code formatting
black --check kakoroguard tests
ruff check kakoroguard tests
```
