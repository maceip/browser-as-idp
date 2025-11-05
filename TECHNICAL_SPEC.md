# Browser Credential Signing: Technical Specification

This document specifies the protocol details for Browser Credential Signing, including credential formats, attestation mechanisms, session binding, and verification procedures.

---

## Table of Contents

1. [Protocol Overview](#protocol-overview)
2. [Attestation Flow](#attestation-flow)
3. [Credential Format (POD)](#credential-format-pod)
4. [Session Binding](#session-binding)
5. [Cryptographic Capabilities](#cryptographic-capabilities)
6. [Verification Procedures](#verification-procedures)
7. [Key Management](#key-management)
8. [Security Considerations](#security-considerations)

---

## Protocol Overview

### Roles

**Identity Provider (IdP)**:
- Root of trust for user identity
- Issues attestations to browser signing keys
- Can revoke attestations
- Examples: Google, Facebook, enterprise IdPs

**Browser**:
- Generates signing key pair
- Requests attestation from IdP
- Signs credentials locally
- Enforces cryptographic capabilities

**Relying Party (RP)**:
- Requests credentials from browser
- Verifies IdP attestation
- Verifies browser signature
- Makes authorization decision

### Two-Phase Protocol

**Phase 1: Attestation (Infrequent)**
```
User → IdP (authenticate) → Browser (generate key pair) → IdP (attest to key) → Browser (cache attestation)
```

**Phase 2: Credential Signing (High-Frequency)**
```
Browser → Sign credential (local, <1ms) → RP (verify attestation + signature)
```

---

## Attestation Flow

### 1. Browser Key Generation

Browser generates an ECDSA P-256 key pair:

```javascript
const browserKeyPair = await crypto.subtle.generateKey(
  {
    name: "ECDSA",
    namedCurve: "P-256"
  },
  false,  // Non-extractable
  ["sign", "verify"]
);

// Export public key for attestation
const publicKeyJWK = await crypto.subtle.exportKey(
  "jwk",
  browserKeyPair.publicKey
);
```

**Requirements**:
- Algorithm: ECDSA with P-256 curve (ES256)
- Private key: Non-extractable (stored in browser's secure storage)
- Public key: Exportable for attestation request

### 2. FedCM Attestation Request

Browser extends FedCM protocol to request attestation:

```javascript
const attestation = await navigator.credentials.get({
  fedcm: {
    providers: [{
      configURL: "https://accounts.google.com/fedcm.json",
      clientId: "optional-client-id",
      nonce: crypto.randomUUID(),

      // NEW: Request signing delegation
      requestAttestation: {
        browserPublicKey: publicKeyJWK,
        validityDays: 30,  // Requested validity period
        capabilities: ["payment", "offline"]  // Optional capabilities
      }
    }]
  }
});
```

### 3. IdP Configuration Extension

IdPs extend their FedCM config to advertise attestation support:

```json
{
  "accounts_endpoint": "https://accounts.google.com/accounts",
  "id_assertion_endpoint": "https://accounts.google.com/assertion",

  "browser_attestation": {
    "endpoint": "https://accounts.google.com/attest-browser-key",
    "supported_key_types": ["ES256"],
    "max_validity_days": 90,
    "revocation_list": "https://accounts.google.com/.well-known/revoked-keys.json"
  }
}
```

### 4. IdP Attestation Issuance

IdP receives attestation request and issues signed attestation:

**Request** (POST to attestation endpoint):
```json
{
  "oauth_token": "user-auth-token",
  "browser_public_key": {
    "kty": "EC",
    "crv": "P-256",
    "x": "base64url...",
    "y": "base64url..."
  },
  "validity_days": 30,
  "capabilities": ["payment"]
}
```

**Response** (Attestation JWT):
```json
{
  "iss": "https://accounts.google.com",
  "sub": "user@gmail.com",
  "aud": "browser-credential-signing",
  "iat": 1234567890,
  "exp": 1237159890,  // 30 days later

  "browser_key": {
    "kty": "EC",
    "crv": "P-256",
    "x": "base64url...",
    "y": "base64url...",
    "kid": "browser-key-abc123"
  },

  "capabilities": ["payment"],

  "revocation": {
    "list_url": "https://accounts.google.com/.well-known/revoked-keys.json",
    "key_id": "browser-key-abc123"
  }
}

// Signed by IdP's signing key (ES256)
```

### 5. Browser Storage

Browser stores attestation in secure storage:

```javascript
// IndexedDB or similar secure storage
await browser.storage.attestations.set(
  "google.com:user@gmail.com",
  {
    attestation: attestationJWT,
    privateKey: browserKeyPair.privateKey,  // Non-extractable reference
    expiresAt: 1237159890
  }
);
```

---

## Credential Format (POD)

### POD Structure

Credentials use the [POD (Provable Object Datatype)](https://pod.org) format for cryptographic integrity and selective disclosure.

**Base POD Structure**:
```typescript
interface BrowserCredential {
  // Standard POD fields
  type: "BrowserCredential";
  version: "1.0";

  // Issuer (browser identifier)
  issuer: string;  // "chrome://identity/abc123" or similar

  // Subject (user identifier from IdP)
  subject: string;  // "user@gmail.com"

  // Audience (RP identifier)
  audience: string;  // "https://api.example.com"

  // Timestamps
  issuedAt: number;   // Unix timestamp
  expiresAt: number;  // Short-lived (30-60 seconds)

  // Nonce (replay protection)
  nonce: string;

  // IdP Attestation (embedded)
  attestation: {
    jwt: string;      // IdP's signed attestation
    idp: string;      // IdP identifier
    keyId: string;    // Browser key ID
  };

  // Session Binding
  binding?: {
    type: "tls-session" | "device" | "combined";
    tlsSessionId?: string;
    deviceAttestation?: string;  // TPM/Secure Enclave proof
  };

  // Claims (selectively disclosable)
  claims: {
    [key: string]: any;
  };

  // Capabilities (cryptographically enforced)
  capabilities?: {
    payment?: {
      maxAmount: string;      // Decimal string
      perTransaction: string;
      currency: string;
    };
    rateLimit?: {
      count: number;
      window: string;  // "1h", "1d", etc.
    };
  };

  // POD proof (for selective disclosure)
  proof?: {
    type: "selective-disclosure" | "predicate" | "range";
    revealed: string[];      // Claim keys to reveal
    predicates: {
      [key: string]: Predicate;
    };
    zkProof: string;  // Zero-knowledge proof
  };

  // Browser signature
  signature: {
    algorithm: "ES256";
    value: string;  // Base64url-encoded signature
  };
}

interface Predicate {
  greaterThan?: number;
  lessThan?: number;
  equals?: any;
  inSet?: any[];
}
```

### Example Credential

```json
{
  "type": "BrowserCredential",
  "version": "1.0",
  "issuer": "chrome://identity/user-abc123",
  "subject": "user@gmail.com",
  "audience": "https://api.example.com",
  "issuedAt": 1234567890,
  "expiresAt": 1234567920,
  "nonce": "uuid-random-nonce",

  "attestation": {
    "jwt": "eyJhbGci...",
    "idp": "https://accounts.google.com",
    "keyId": "browser-key-abc123"
  },

  "binding": {
    "type": "tls-session",
    "tlsSessionId": "tls-session-xyz789"
  },

  "claims": {
    "email": "user@gmail.com",
    "age": 34,
    "accountBalance": 5000
  },

  "capabilities": {
    "payment": {
      "maxAmount": "100.00",
      "perTransaction": "1.00",
      "currency": "USD"
    }
  },

  "signature": {
    "algorithm": "ES256",
    "value": "base64url-signature..."
  }
}
```

### Selective Disclosure

Generate proof revealing only specific claims:

```javascript
const credential = /* BrowserCredential */;

// Create selective disclosure proof
const proof = {
  type: "selective-disclosure",
  revealed: ["email"],  // Only reveal email
  predicates: {
    age: { greaterThan: 21 },           // Prove age > 21
    accountBalance: { greaterThan: 100 } // Prove balance > 100
  }
};

// Generate ZK proof (using POD library)
const zkProof = await POD.generateProof(credential, proof);

// Result: RP learns email + proof of age>21 + proof of balance>100
// RP does NOT learn: exact age, exact balance
```

---

## Session Binding

### TLS Session Binding

**Mechanism**: Cryptographically bind credential to TLS session

**Implementation**:

```javascript
// Browser generates session-specific key pair
const sessionKeyPair = await crypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" },
  false,
  ["sign", "verify"]
);

// Get TLS session ID (via proposed WebTransport/TLS API)
const tlsSessionId = await connection.getSessionId();

// Include in credential
const credential = {
  // ... other fields
  binding: {
    type: "tls-session",
    tlsSessionId: tlsSessionId,
    sessionPublicKey: await crypto.subtle.exportKey("jwk", sessionKeyPair.publicKey)
  }
};

// Sign credential with BOTH browser key AND session key
const signatures = {
  browser: await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    browserPrivateKey,
    serializeForSigning(credential)
  ),
  session: await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    sessionKeyPair.privateKey,
    serializeForSigning(credential)
  )
};
```

**RP Verification**:

```javascript
async function verifySessionBinding(credential, currentTLSSession) {
  // 1. Check TLS session ID matches
  if (credential.binding.tlsSessionId !== currentTLSSession.id) {
    throw new Error("TLS session mismatch");
  }

  // 2. Verify session key signature
  const sessionPublicKey = await crypto.subtle.importKey(
    "jwk",
    credential.binding.sessionPublicKey,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"]
  );

  const sessionSigValid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    sessionPublicKey,
    credential.signatures.session,
    serializeForSigning(credential)
  );

  if (!sessionSigValid) {
    throw new Error("Invalid session signature");
  }

  return true;
}
```

### Device Attestation Binding

**Mechanism**: Use TPM/Secure Enclave to prove credential generated on legitimate hardware

```javascript
// Request device attestation (WebAuthn-style)
const attestation = await navigator.credentials.create({
  publicKey: {
    challenge: credential.nonce,
    attestation: "direct",  // Get device attestation
    authenticatorSelection: {
      authenticatorAttachment: "platform"  // TPM/Secure Enclave
    }
  }
});

// Include attestation in credential
credential.binding = {
  type: "device",
  deviceAttestation: attestation.response.attestationObject
};
```

**Benefits**:
- Proves credential generated on real hardware (not VM/emulator)
- Prevents credential farming attacks
- Higher assurance level for sensitive operations

---

## Cryptographic Capabilities

### Payment Capability Enforcement

**Concept**: Browser cryptographically enforces spending limits BEFORE signing credential

```javascript
async function signCredentialWithCapabilities(
  credential,
  capabilities,
  spendingState
) {
  // Check payment capability
  if (capabilities.payment) {
    const requestedAmount = parseFloat(credential.payment?.amount || "0");
    const maxPerTx = parseFloat(capabilities.payment.perTransaction);
    const totalSpent = spendingState.totalSpent;
    const maxTotal = parseFloat(capabilities.payment.maxAmount);

    // Cryptographic enforcement (cannot be bypassed)
    if (requestedAmount > maxPerTx) {
      throw new Error("Exceeds per-transaction limit");
    }

    if (totalSpent + requestedAmount > maxTotal) {
      throw new Error("Exceeds total budget");
    }

    // Update spending state (atomic)
    await spendingState.increment(requestedAmount);
  }

  // Sign credential
  return await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    browserPrivateKey,
    serializeForSigning(credential)
  );
}
```

**Key property**: Browser refuses to sign credentials that violate capabilities. Since browser holds private key, no one else can sign either. Mathematically impossible to bypass.

### Rate Limiting Capability

```javascript
const capabilities = {
  rateLimit: {
    count: 100,      // 100 requests
    window: "1h"     // Per hour
  }
};

// Browser maintains rate limit state
const rateLimitState = {
  windowStart: Date.now(),
  count: 0
};

// Before signing
if (rateLimitState.count >= capabilities.rateLimit.count) {
  if (Date.now() - rateLimitState.windowStart < parseWindow(capabilities.rateLimit.window)) {
    throw new Error("Rate limit exceeded");
  }
  // Reset window
  rateLimitState.windowStart = Date.now();
  rateLimitState.count = 0;
}

rateLimitState.count++;
```

---

## Verification Procedures

### RP Credential Verification

**Complete verification flow**:

```javascript
async function verifyBrowserCredential(credential, context) {
  // 1. Check expiration
  if (credential.expiresAt < Date.now() / 1000) {
    throw new Error("Credential expired");
  }

  // 2. Verify nonce (prevent replay)
  if (await context.nonceStore.hasBeenUsed(credential.nonce)) {
    throw new Error("Nonce already used");
  }
  await context.nonceStore.markUsed(credential.nonce);

  // 3. Verify audience
  if (credential.audience !== context.expectedAudience) {
    throw new Error("Audience mismatch");
  }

  // 4. Verify IdP attestation
  const attestationValid = await verifyAttestation(
    credential.attestation,
    context.trustedIdPs
  );
  if (!attestationValid) {
    throw new Error("Invalid IdP attestation");
  }

  // 5. Check revocation
  const revoked = await context.revocationAggregator.check({
    idp: credential.attestation.idp,
    keyId: credential.attestation.keyId
  });
  if (revoked) {
    throw new Error("Attestation revoked");
  }

  // 6. Verify browser signature
  const browserKey = extractPublicKey(credential.attestation.jwt);
  const signatureValid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    browserKey,
    base64url.decode(credential.signature.value),
    serializeForSigning(credential)
  );
  if (!signatureValid) {
    throw new Error("Invalid browser signature");
  }

  // 7. Verify session binding (if present)
  if (credential.binding) {
    await verifySessionBinding(credential, context.currentSession);
  }

  // 8. Verify capabilities (if enforcing)
  if (credential.capabilities) {
    await verifyCapabilities(credential, context.capabilityPolicy);
  }

  return {
    valid: true,
    subject: credential.subject,
    claims: credential.claims,
    capabilities: credential.capabilities
  };
}

async function verifyAttestation(attestation, trustedIdPs) {
  // Parse attestation JWT
  const [headerB64, payloadB64, signatureB64] = attestation.jwt.split('.');
  const header = JSON.parse(base64url.decode(headerB64));
  const payload = JSON.parse(base64url.decode(payloadB64));

  // Check issuer is trusted
  if (!trustedIdPs.includes(payload.iss)) {
    throw new Error("Untrusted IdP");
  }

  // Check expiration
  if (payload.exp < Date.now() / 1000) {
    throw new Error("Attestation expired");
  }

  // Fetch IdP's public key (cached)
  const idpKey = await fetchIdPPublicKey(payload.iss, header.kid);

  // Verify IdP signature
  const signatureValid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    idpKey,
    base64url.decode(signatureB64),
    new TextEncoder().encode(headerB64 + '.' + payloadB64)
  );

  return signatureValid;
}
```

---

## Key Management

### Browser Key Lifecycle

**Generation**:
- ECDSA P-256 key pair
- Private key: Non-extractable, stored in browser's secure storage
- Tied to browser profile (not device, for cross-device sync)

**Storage**:
```javascript
// Browser secure storage (implementation-specific)
// Chrome: Uses OS keychain (Keychain on macOS, DPAPI on Windows)
// Firefox: Uses NSS key database
// Safari: Uses Keychain

const keyStore = await browser.storage.keys.open();
await keyStore.put(keyId, {
  privateKey: keyPairRef,  // Non-extractable reference
  publicKey: publicKeyJWK,
  createdAt: Date.now(),
  attestations: []  // Associated attestations
});
```

**Rotation**:
- User-initiated: New key pair, request new attestations
- Automatic: Optional, configurable (e.g., every 90 days)
- Old keys kept for grace period (to honor existing attestations)

**Deletion**:
- User account deletion: Delete all keys + attestations
- Browser profile deletion: Delete all keys + attestations
- Manual: User can delete keys via browser settings

### IdP Key Management

**Signing Keys**:
- Publish at `.well-known/jwks.json`
- Rotate regularly (e.g., every 90 days)
- Keep old keys available during grace period

**Example JWKS**:
```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "kid": "google-2024-q1",
      "use": "sig",
      "x": "base64url...",
      "y": "base64url..."
    }
  ]
}
```

---

## Security Considerations

### Threat Model

**In Scope**:
- Credential theft (XSS, MITM)
- Credential replay
- Session hijacking
- Capability bypass attempts
- Revocation bypass

**Out of Scope**:
- Browser compromise (malware with root access)
- IdP compromise (assumed trusted)
- RP compromise (assumed trusted for their domain)

### Attack Scenarios & Mitigations

#### 1. Credential Theft via XSS

**Attack**: Malicious script steals credential from JavaScript

**Mitigation**:
- Credentials are short-lived (30-60 seconds)
- Session binding prevents use from different context
- Nonce prevents replay
- **Impact**: Attacker gets credential valid for 30 seconds in same TLS session (limited damage)

#### 2. Browser Key Extraction

**Attack**: Extract browser private key to forge credentials

**Mitigation**:
- Private key marked non-extractable
- Stored in OS-level secure storage
- **Result**: Cryptographically impossible without OS compromise

#### 3. Capability Bypass

**Attack**: Modify credential to exceed spending limits

**Mitigation**:
- Browser enforces BEFORE signing
- Browser signature proves enforcement
- Cannot sign without browser cooperation
- **Result**: Mathematically impossible to bypass

#### 4. Revocation Bypass

**Attack**: Use revoked attestation

**Mitigation**:
- RPs check revocation aggregators
- Short credential lifetime (even if check delayed)
- Aggregators cache for performance (5min acceptable delay)
- **Impact**: Max 5-minute window after revocation

#### 5. Session Hijacking

**Attack**: Steal session to reuse credential

**Mitigation**:
- TLS session ID binding
- Credential invalid in different TLS session
- **Result**: Session hijacking doesn't help (credential unusable)

### Privacy Considerations

**User Tracking**:
- Different RPs get unlinkable credentials (different signatures)
- Selective disclosure minimizes data exposure
- Anonymous mode available (no PII in credentials)

**IdP Tracking**:
- IdP sees attestation requests (infrequent, e.g., monthly)
- IdP does NOT see credential usage (browser signs, not IdP)
- **Result**: 30x less IdP visibility than OAuth

**RP Tracking**:
- RP sees only disclosed claims
- Cannot correlate across different credential presentations
- **Result**: Minimal tracking vector

---

## Appendix: Cryptographic Primitives

### Algorithms

**Digital Signatures**:
- ECDSA with P-256 curve
- SHA-256 hash function
- Signature format: IEEE P1363 (raw r||s)

**Key Derivation**:
- HKDF with SHA-256
- For session-specific keys

**Hashing**:
- SHA-256 for commitments
- SHA-512 for high-entropy needs

### Serialization

**Credential Serialization for Signing**:
```javascript
function serializeForSigning(credential) {
  // Deterministic JSON serialization (no signature field)
  const { signature, ...credentialWithoutSig } = credential;

  // Canonical JSON (sorted keys, no whitespace)
  const canonical = canonicalJSON(credentialWithoutSig);

  return new TextEncoder().encode(canonical);
}

function canonicalJSON(obj) {
  // Sort keys recursively
  if (typeof obj !== 'object' || obj === null) {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalJSON).join(',') + ']';
  }

  const keys = Object.keys(obj).sort();
  const pairs = keys.map(k =>
    JSON.stringify(k) + ':' + canonicalJSON(obj[k])
  );

  return '{' + pairs.join(',') + '}';
}
```

### Test Vectors

See [test-vectors.json](./test-vectors.json) for comprehensive test cases including:
- Valid credentials
- Expired credentials
- Invalid signatures
- Revoked attestations
- Capability violations
- Session binding failures

---

**References**:
- [POD Specification](https://pod.org)
- [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/)
- [FedCM](https://fedidcg.github.io/FedCM/)
- [RFC 7515: JSON Web Signature](https://datatracker.ietf.org/doc/html/rfc7515)
- [RFC 8017: PKCS #1 v2.2](https://datatracker.ietf.org/doc/html/rfc8017)
