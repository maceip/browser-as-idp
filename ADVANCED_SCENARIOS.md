# Advanced Scenarios & Revocation Architecture

This document covers advanced deployment scenarios including revocation aggregation, P2P authentication, browser extensions as IdPs, and cross-browser credential portability.

---

## Table of Contents

1. [Revocation Aggregation Architecture](#revocation-aggregation-architecture)
2. [P2P Authentication](#p2p-authentication)
3. [Browser Extensions as IdPs](#browser-extensions-as-idps)
4. [Cross-Browser Portability](#cross-browser-portability)
5. [Offline-First Scenarios](#offline-first-scenarios)
6. [Enterprise Deployment](#enterprise-deployment)

---

## Revocation Aggregation Architecture

### The Scaling Challenge

**Problem**: With millions of IdPs, RPs cannot query each IdP individually for revocation status.

**Traditional approaches that don't scale**:
- Certificate Revocation Lists (CRLs): 1M IdPs × 1KB = 1GB
- Online Certificate Status Protocol (OCSP): 10B queries/day to distributed IdPs

### Solution: Aggregator Layer

**Architecture**:

```
┌─────────────────────────────────────────────────────────────┐
│                  REVOCATION AGGREGATORS                     │
│                                                             │
│  Google          Cloudflare      Fastly      Akamai        │
│  revocation.     revocation.     revocation. revocation.   │
│  googleapis.com  cloudflare.com  fastly.com  akamai.com    │
│                                                             │
│  - Receive revocations from all IdPs                       │
│  - Serve revocation checks to all RPs                      │
│  - CDN caching for performance                             │
│  - 99.9% SLA                                               │
└─────────────────────────────────────────────────────────────┘
            ↑                                    ↓
    (publish revocations)               (check revocations)
            ↑                                    ↓
┌───────────────────────┐             ┌─────────────────────┐
│   1M+ IdPs            │             │   RPs               │
│                       │             │                     │
│ - Enterprise IdPs     │             │ - APIs              │
│ - Social IdPs         │             │ - Websites          │
│ - Community IdPs      │             │ - Services          │
│ - Personal IdPs       │             │ - Agent endpoints   │
└───────────────────────┘             └─────────────────────┘
```

### Aggregator API Specification

#### Publishing Revocations (IdP → Aggregator)

```http
POST https://revocation.googleapis.com/v1/publish
Content-Type: application/json
Authorization: Bearer <idp-api-key>

{
  "idp": "https://community-idp.example",
  "revocations": [
    {
      "browserKey": "browser-key-abc123",
      "revokedAt": 1234567890,
      "reason": "account-compromised"
    },
    {
      "browserKey": "browser-key-def456",
      "revokedAt": 1234567895,
      "reason": "user-requested"
    }
  ],
  "signature": "..."  // IdP signature over revocations
}
```

**Response**:
```json
{
  "published": true,
  "count": 2,
  "propagationTime": "< 30s",  // SLA: revocations visible within 30s
  "cacheInvalidated": true
}
```

#### Checking Revocations (RP → Aggregator)

```http
GET https://revocation.googleapis.com/v1/check?idp=https://community-idp.example&key=browser-key-abc123
Cache-Control: public, max-age=300
```

**Response** (cached 5 minutes):
```json
{
  "revoked": true,
  "revokedAt": 1234567890,
  "reason": "account-compromised",
  "checkedAt": 1234567900,
  "nextCheck": 1234568200  // Check again in 5 minutes
}
```

**Response** (not revoked):
```json
{
  "revoked": false,
  "checkedAt": 1234567900,
  "nextCheck": 1234568200
}
```

### Implementation: Google Aggregator

```javascript
// Google Cloud Functions implementation
import { Firestore } from '@google-cloud/firestore';
import { CloudCDN } from '@google-cloud/cdn';

const db = new Firestore();
const cdn = new CloudCDN();

// Publish endpoint (called by IdPs)
export async function publishRevocation(req, res) {
  const { idp, revocations, signature } = req.body;

  // 1. Verify IdP signature
  const idpPublicKey = await fetchIdPPublicKey(idp);
  const signatureValid = await verifySignature(
    { idp, revocations },
    signature,
    idpPublicKey
  );

  if (!signatureValid) {
    return res.status(403).json({ error: 'Invalid IdP signature' });
  }

  // 2. Store revocations
  const batch = db.batch();

  for (const revocation of revocations) {
    const docRef = db.collection('revocations').doc(
      `${idp}:${revocation.browserKey}`
    );

    batch.set(docRef, {
      idp: idp,
      browserKey: revocation.browserKey,
      revokedAt: revocation.revokedAt,
      reason: revocation.reason,
      publishedAt: Date.now()
    });
  }

  await batch.commit();

  // 3. Invalidate CDN cache
  for (const revocation of revocations) {
    await cdn.purge(
      `/v1/check?idp=${encodeURIComponent(idp)}&key=${revocation.browserKey}`
    );
  }

  res.json({
    published: true,
    count: revocations.length,
    propagationTime: '< 30s',
    cacheInvalidated: true
  });
}

// Check endpoint (called by RPs)
export async function checkRevocation(req, res) {
  const { idp, key } = req.query;

  if (!idp || !key) {
    return res.status(400).json({ error: 'Missing idp or key parameter' });
  }

  // Query Firestore (fast read from multi-region)
  const docRef = db.collection('revocations').doc(`${idp}:${key}`);
  const doc = await docRef.get();

  const response = {
    revoked: doc.exists,
    checkedAt: Date.now(),
    nextCheck: Date.now() + 300000  // 5 minutes
  };

  if (doc.exists) {
    const data = doc.data();
    response.revokedAt = data.revokedAt;
    response.reason = data.reason;
  }

  // Cache for 5 minutes
  res.set('Cache-Control', 'public, max-age=300');
  res.json(response);
}
```

### Scaling Analysis

**Assumptions**:
- 1M IdPs
- 100 revocations/day per IdP = 100M revocations/day
- 10B credential verifications/day
- 99% cache hit rate (5-minute cache TTL)

**Aggregator load**:
- Ingress (revocations): 100M/day = 1,157 writes/sec
- Egress (checks): 10B/day × 1% cache miss = 100M/day = 1,157 reads/sec
- Cached reads: 10B/day × 99% = 9.9B/day (served from CDN)

**Infrastructure**:
- Firestore: Handles 10K writes/sec, 100K reads/sec (10x margin)
- Cloud CDN: Handles unlimited cached reads
- Total cost: ~$10-20K/month per aggregator

**Revenue potential**:
- Free tier: 10K checks/day per RP
- Paid: $0.01 per 1,000 checks
- Enterprise: Custom SLA + pricing
- Estimated: $150K-1M/month revenue per aggregator

**ROI**: 5-50x

### Multi-Aggregator Redundancy

**RPs configure multiple aggregators for failover**:

```javascript
const aggregators = [
  'https://revocation.googleapis.com',
  'https://revocation.cloudflare.com',
  'https://revocation.fastly.com'
];

async function checkRevocation(idp, browserKey) {
  // Try aggregators in order (failover)
  for (const aggregator of aggregators) {
    try {
      const response = await fetch(
        `${aggregator}/v1/check?idp=${encodeURIComponent(idp)}&key=${browserKey}`,
        { timeout: 5000 }  // 5s timeout
      );

      if (response.ok) {
        return await response.json();
      }
    } catch (error) {
      console.warn(`Aggregator ${aggregator} failed, trying next`);
      continue;
    }
  }

  // All aggregators failed - fail open or closed?
  // Recommendation: Fail open (allow) for short-lived credentials
  return { revoked: false, checkedAt: Date.now() };
}
```

### Emergency Revocation Broadcast

**For critical breaches** (rare, e.g., IdP key compromise):

```javascript
// IdP broadcasts emergency revocation
await fetch('https://revocation.googleapis.com/v1/emergency', {
  method: 'POST',
  body: JSON.stringify({
    idp: "https://accounts.google.com",
    severity: "critical",
    revokeAll: true,  // Revoke ALL attestations
    reason: "idp-key-compromise",
    signature: "..."
  })
});

// Aggregator broadcasts to RPs via WebPush/SSE
aggregator.broadcast({
  type: "emergency-revocation",
  idp: "https://accounts.google.com",
  action: "revoke-all",
  severity: "critical"
});

// RPs receive broadcast and immediately reject credentials
rpServer.on('emergency-revocation', (event) => {
  if (event.idp === trustedIdP && event.action === 'revoke-all') {
    // Immediately reject all credentials from this IdP
    credentialCache.invalidateAll(event.idp);
    console.error(`Emergency: All credentials from ${event.idp} revoked`);
  }
});
```

---

## P2P Authentication

### Use Case: Direct Device-to-Device Auth

**Scenario**: Two devices need to authenticate without server involvement (e.g., local multiplayer, file sharing, IoT pairing).

**Flow**:

```
Device A                          Device B
   │                                 │
   │  1. Discover (mDNS/Bluetooth)  │
   │ ◄────────────────────────────► │
   │                                 │
   │  2. Establish TLS connection   │
   │ ◄────────────────────────────► │
   │                                 │
   │  3. Exchange credentials        │
   │     (browser-signed)            │
   │ ────────────────────────────►  │
   │ ◄────────────────────────────  │
   │                                 │
   │  4. Verify credentials          │
   │     (check IdP attestation)     │
   │ ✓                             ✓│
   │                                 │
   │  5. Authenticated connection    │
   │ ◄────────────────────────────► │
```

### Implementation with Direct Sockets API

```javascript
// Device A: Run identity server
async function startP2PIdentityServer() {
  const server = new TCPServerSocket({
    localPort: 8443,
    localAddress: "0.0.0.0"
  });

  console.log("P2P identity server listening on port 8443");

  for await (const connection of server.connections) {
    handleP2PConnection(connection);
  }
}

async function handleP2PConnection(connection) {
  const reader = connection.readable.getReader();
  const writer = connection.writable.getWriter();

  // 1. Receive credential request
  const { value } = await reader.read();
  const request = JSON.parse(new TextDecoder().decode(value));

  // 2. Generate credential for peer
  const credential = await navigator.credentials.sign({
    delegation: myAttestation,
    audience: connection.remoteAddress,
    nonce: request.nonce,
    binding: {
      type: "p2p",
      peerAddress: connection.remoteAddress
    }
  });

  // 3. Send credential to peer
  await writer.write(
    new TextEncoder().encode(JSON.stringify({
      credential: credential,
      publicKey: await exportPublicKey(myAttestation)
    }))
  );

  console.log(`Authenticated peer: ${connection.remoteAddress}`);
}

// Device B: Request credential from peer
async function authenticateWithPeer(peerAddress) {
  const socket = new TCPSocket(peerAddress, 8443);

  const reader = socket.readable.getReader();
  const writer = socket.writable.getWriter();

  // 1. Request credential
  const nonce = crypto.randomUUID();
  await writer.write(
    new TextEncoder().encode(JSON.stringify({
      type: "credential_request",
      nonce: nonce
    }))
  );

  // 2. Receive credential
  const { value } = await reader.read();
  const response = JSON.parse(new TextDecoder().decode(value));

  // 3. Verify credential
  const valid = await verifyBrowserCredential(response.credential);

  if (valid) {
    console.log(`Authenticated peer: ${peerAddress}`);
    return response.credential.subject;
  } else {
    throw new Error("Peer authentication failed");
  }
}
```

**Benefits**:
- No server required (fully P2P)
- Works offline
- Browser-signed credentials provide trust
- IdP attestation verifiable locally (cached)

---

## Browser Extensions as IdPs

### Use Case: Portable Identity Across Browsers

**Scenario**: User wants same identity across Chrome, Firefox, Safari via synced extension.

**Implementation**:

```javascript
// Extension manifest.json
{
  "manifest_version": 3,
  "name": "Personal Identity Provider",
  "permissions": [
    "storage",
    "identity"
  ],
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [{
    "matches": ["<all_urls>"],
    "js": ["content.js"]
  }]
}

// background.js - Extension acts as IdP
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'get-credential') {
    handleCredentialRequest(request, sender).then(sendResponse);
    return true;  // Async response
  }
});

async function handleCredentialRequest(request, sender) {
  // 1. Load extension's signing key (synced across browsers)
  const extensionKey = await chrome.storage.sync.get('signingKey');

  // 2. Load IdP attestation (from Google/etc.)
  const attestation = await chrome.storage.local.get('idpAttestation');

  // 3. Generate credential
  const credential = await signCredential({
    delegation: attestation,
    audience: sender.url,
    nonce: request.nonce,
    privateKey: extensionKey
  });

  return { credential };
}

// content.js - Inject credential API into page
window.personalIdentity = {
  async getCredential(audience, nonce) {
    const response = await chrome.runtime.sendMessage({
      type: 'get-credential',
      audience: audience,
      nonce: nonce
    });

    return response.credential;
  }
};

// Page uses extension-provided identity
const credential = await window.personalIdentity.getCredential(
  window.location.origin,
  await fetchNonce()
);
```

**Benefits**:
- Identity portable across browsers (extension syncs key)
- User controls identity (not browser vendor)
- Works anywhere extension is installed
- Can provide additional features (password manager, etc.)

---

## Cross-Browser Portability

### Challenge

**User has credentials in Chrome, wants to use in Firefox.**

### Solution: Encrypted Export/Import

```javascript
// Chrome: Export credential
async function exportCredential(password) {
  // 1. Get browser key + attestations
  const browserKey = await chrome.storage.keys.get('main');
  const attestations = await chrome.storage.attestations.getAll();

  // 2. Encrypt with user password
  const exportData = {
    browserKey: browserKey,  // Private key (encrypted)
    attestations: attestations,
    exportedAt: Date.now()
  };

  const encrypted = await encryptWithPassword(
    JSON.stringify(exportData),
    password
  );

  // 3. Save to file
  const blob = new Blob([encrypted], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'browser-credentials-export.enc';
  a.click();
}

// Firefox: Import credential
async function importCredential(file, password) {
  // 1. Read encrypted file
  const encrypted = await file.arrayBuffer();

  // 2. Decrypt with password
  const decrypted = await decryptWithPassword(encrypted, password);
  const exportData = JSON.parse(decrypted);

  // 3. Import browser key
  const browserKey = await crypto.subtle.importKey(
    "jwk",
    exportData.browserKey,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );

  await browser.storage.keys.set('main', browserKey);

  // 4. Import attestations
  for (const attestation of exportData.attestations) {
    await browser.storage.attestations.set(attestation.id, attestation);
  }

  console.log("Credentials imported successfully");
}
```

**Alternative: Cloud Backup**

```javascript
// Backup to user's cloud storage (encrypted)
async function backupToCloud(cloudProvider, password) {
  const exportData = await exportCredential(password);

  // Upload to user's Google Drive / iCloud / Dropbox
  await cloudProvider.upload('browser-credentials.enc', exportData);
}

// Restore from cloud
async function restoreFromCloud(cloudProvider, password) {
  const encrypted = await cloudProvider.download('browser-credentials.enc');
  await importCredential(encrypted, password);
}
```

---

## Offline-First Scenarios

### Use Case 1: Retail POS During Network Outage

**Scenario**: Store POS system needs to authorize payments during network outage.

```javascript
// POS terminal (running in browser)
class OfflinePOS {
  constructor() {
    this.offlineQueue = [];
  }

  async processPayment(amount, customerCredential) {
    try {
      // Try online authorization
      const authorization = await this.authorizeOnline(amount, customerCredential);
      return authorization;

    } catch (networkError) {
      // Network down - use offline authorization
      console.log("Network unavailable, using offline mode");

      // Verify credential locally (browser signature + cached attestation)
      const credentialValid = await this.verifyOffline(customerCredential);

      if (!credentialValid) {
        throw new Error("Invalid credential");
      }

      // Check spending limit (if in credential)
      if (customerCredential.capabilities?.payment) {
        const limit = parseFloat(customerCredential.capabilities.payment.perTransaction);
        if (amount > limit) {
          throw new Error(`Exceeds limit: $${limit}`);
        }
      }

      // Queue for settlement when online
      const transaction = {
        id: crypto.randomUUID(),
        amount: amount,
        credential: customerCredential,
        timestamp: Date.now(),
        status: "pending-settlement"
      };

      this.offlineQueue.push(transaction);
      await this.saveOfflineQueue();

      return {
        authorized: true,
        transactionId: transaction.id,
        offline: true,
        settlementPending: true
      };
    }
  }

  async verifyOffline(credential) {
    // 1. Verify browser signature (cryptographic, no network needed)
    const browserSignatureValid = await verifyBrowserSignature(credential);

    // 2. Verify IdP attestation (cached attestation + IdP public key)
    const cachedAttestation = await this.cache.getAttestation(credential.attestation.idp);
    const attestationValid = await verifyAttestation(credential, cachedAttestation);

    // 3. Check expiration
    const notExpired = credential.expiresAt > Date.now() / 1000;

    return browserSignatureValid && attestationValid && notExpired;
  }

  async settleOfflineTransactions() {
    // When network restored, settle queued transactions
    for (const tx of this.offlineQueue) {
      try {
        await this.settlementService.settle(tx);
        tx.status = "settled";
      } catch (error) {
        console.error(`Settlement failed for ${tx.id}:`, error);
        tx.status = "settlement-failed";
      }
    }

    // Remove settled transactions
    this.offlineQueue = this.offlineQueue.filter(tx => tx.status !== "settled");
    await this.saveOfflineQueue();
  }
}
```

### Use Case 2: Aircraft In-Flight Services

**Scenario**: Passengers purchasing in-flight WiFi, food, etc. without ground connectivity.

```javascript
// Flight attendant tablet
class InFlightPurchaseSystem {
  async processPurchase(seatNumber, item, passengerCredential) {
    // Verify passenger credential (fully offline)
    const credentialValid = await this.verifyPassengerCredential(passengerCredential);

    if (!credentialValid) {
      return { success: false, error: "Invalid credential" };
    }

    // Record purchase (offline queue)
    const purchase = {
      flight: this.flightNumber,
      seat: seatNumber,
      item: item,
      amount: item.price,
      credential: passengerCredential,
      timestamp: Date.now()
    };

    await this.offlinePurchases.add(purchase);

    // Issue receipt (browser signs)
    const receipt = await navigator.credentials.sign({
      delegation: this.tabletAttestation,
      audience: passengerCredential.subject,
      receipt: purchase,
      nonce: crypto.randomUUID()
    });

    return {
      success: true,
      receipt: receipt,
      settlementOnLanding: true
    };
  }

  async settleOnLanding() {
    // After landing, connect to ground network and settle
    const settlements = await this.settleWithPaymentProcessor(
      this.offlinePurchases.getAll()
    );

    return settlements;
  }
}
```

---

## Enterprise Deployment

### Use Case: Internal Corporate IdP

**Scenario**: Enterprise wants browser credential signing for internal apps, using corporate IdP.

```javascript
// Corporate IdP configuration
{
  "idp": "https://identity.acmecorp.com",

  "browser_attestation": {
    "endpoint": "https://identity.acmecorp.com/attest-browser-key",
    "device_requirements": {
      "tpm_required": true,          // Require TPM attestation
      "managed_devices_only": true,  // Only corporate-managed devices
      "os_versions": ["Windows 11", "macOS 13+"]
    },
    "validity_days": 7,  // Short validity for high security
    "requires_reauthentication": "daily"  // Re-auth daily
  },

  "revocation_aggregator": "https://revocation.acmecorp.com"  // Private aggregator
}

// Corporate device enrollment
async function enrollCorporateDevice() {
  // 1. Device attestation (TPM)
  const deviceAttestation = await navigator.credentials.create({
    publicKey: {
      attestation: "direct",
      authenticatorSelection: {
        authenticatorAttachment: "platform"
      }
    }
  });

  // 2. Request attestation from corporate IdP
  const attestation = await navigator.credentials.get({
    fedcm: {
      providers: [{
        configURL: "https://identity.acmecorp.com/fedcm.json",
        requestAttestation: {
          deviceAttestation: deviceAttestation,
          employeeId: await getEmployeeId()
        }
      }]
    }
  });

  // 3. Browser now has corporate attestation
  // Can access internal apps with browser credentials
}

// Internal app uses browser credentials
async function accessInternalAPI() {
  const credential = await navigator.credentials.sign({
    delegation: corporateAttestation,
    audience: "https://internal-api.acmecorp.com",
    nonce: await fetchNonce(),
    binding: {
      type: "device",
      deviceAttestation: tpmAttestation
    }
  });

  const response = await fetch("https://internal-api.acmecorp.com/data", {
    headers: { Authorization: `Bearer ${credential}` }
  });

  return response.json();
}
```

**Enterprise benefits**:
- Device management (only corporate devices)
- Audit trails (private aggregator logs all credential usage)
- High security (TPM + daily re-auth)
- No external IdP dependency (internal IdP only)

---

## Appendix: Revocation List Format

### Standard Revocation List (JSON)

```json
{
  "issuer": "https://accounts.google.com",
  "issuedAt": 1234567890,
  "nextUpdate": 1234571490,  // Update every hour

  "revocations": [
    {
      "browserKey": "browser-key-abc123",
      "revokedAt": 1234567890,
      "reason": "account-compromised",
      "keyId": "abc123"
    },
    {
      "browserKey": "browser-key-def456",
      "revokedAt": 1234567850,
      "reason": "user-requested",
      "keyId": "def456"
    }
  ],

  "signature": "..."  // IdP signature over entire list
}
```

### Bloom Filter Format (Compact)

```json
{
  "issuer": "https://accounts.google.com",
  "issuedAt": 1234567890,
  "nextUpdate": 1234571490,

  "bloomFilter": {
    "size": 10000,  // Bits
    "hashFunctions": 7,
    "falsePositiveRate": 0.001,
    "filter": "base64-encoded-bloom-filter..."
  },

  "signature": "..."
}
```

**Usage**:
```javascript
// Check if key is revoked (fast, local)
const mightBeRevoked = bloomFilter.contains(browserKey);

if (mightBeRevoked) {
  // Might be false positive - check aggregator
  const definitelyRevoked = await aggregator.check(idp, browserKey);
}
```

---

**References**:
- [Direct Sockets API](https://github.com/WICG/direct-sockets)
- [Certificate Transparency](https://certificate.transparency.dev/)
- [Bloom Filter RFC](https://www.ietf.org/archive/id/draft-vixie-dnsext-dns0x20-00.html)
- [mDNS/DNS-SD](https://datatracker.ietf.org/doc/html/rfc6763)
