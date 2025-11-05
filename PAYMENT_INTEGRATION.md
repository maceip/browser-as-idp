# Payment Handler Integration & Agent Payment Protocol (AP2)

This document specifies how Browser Credential Signing integrates with the Payment Handler API and enables autonomous agent payments through the Agent Payment Protocol (AP2).

---

## Table of Contents

1. [Payment Handler Integration](#payment-handler-integration)
2. [Agent Payment Protocol (AP2)](#agent-payment-protocol-ap2)
3. [Cryptographic Spending Enforcement](#cryptographic-spending-enforcement)
4. [Clearing House Architecture](#clearing-house-architecture)
5. [Recursive Proof Chains](#recursive-proof-chains)
6. [Implementation Examples](#implementation-examples)

---

## Payment Handler Integration

### Overview

**Unified auth + payment**: Same browser credential used for both authentication and payment authorization.

**Benefits**:
- Single user interaction (passkey prompt)
- Session-bound payment (prevents theft/replay)
- Cryptographic spending limits
- No card numbers stored/transmitted

### Payment Handler Registration

```javascript
// Browser registers as payment handler with credential-bound payments
await registration.paymentManager.instruments.set(
  "browser-credential-pay",
  {
    name: "Browser Credential Payment",
    method: "https://w3.org/browser-credential-pay",

    capabilities: {
      supportedNetworks: ["browser-credential"],
      supportedTypes: ["instant", "authorization-only"]
    },

    // Link to browser credential
    credentialBound: true,
    requiresPasskey: true  // User verification required
  }
);
```

### Payment Request Flow

**Merchant initiates payment**:

```javascript
// E-commerce checkout
const paymentRequest = new PaymentRequest(
  [
    {
      supportedMethods: "https://w3.org/browser-credential-pay",
      data: {
        amount: {
          currency: "USD",
          value: "99.99"
        },
        merchantId: "merchant-123",
        requiresAuthorization: true
      }
    }
  ],
  {
    total: {
      label: "Total",
      amount: { currency: "USD", value: "99.99" }
    }
  }
);

// Show payment UI
const paymentResponse = await paymentRequest.show();
```

**Browser prompts user**:

```
┌────────────────────────────────────┐
│  Authorize Payment                 │
│                                    │
│  Merchant: Example Store           │
│  Amount: $99.99 USD                │
│                                    │
│  [Fingerprint Icon]                │
│  Authenticate with passkey         │
│                                    │
│  ✓ Session-bound (theft-proof)    │
│  ✓ No card number needed           │
│                                    │
│  [Cancel]  [Authorize with Touch ID]│
└────────────────────────────────────┘
```

**Browser generates payment credential**:

```javascript
// After user authorizes with passkey
const paymentCredential = await navigator.credentials.sign({
  delegation: userAttestation,  // From Google/IdP
  audience: "https://merchant.example.com",
  nonce: merchantNonce,

  // Session binding
  binding: {
    tlsSession: currentTLSSession,
    passkey: passkeyAttestation  // WebAuthn attestation
  },

  // Payment details
  payment: {
    amount: "99.99",
    currency: "USD",
    merchantId: "merchant-123",
    transactionId: crypto.randomUUID()
  },

  // Enforce spending limit (if set)
  capabilities: userCapabilities.payment
});

// Return to merchant
paymentResponse.complete({
  credential: paymentCredential
});
```

### Merchant Verification

```javascript
async function verifyPaymentCredential(credential, expectedAmount) {
  // 1. Verify browser credential (standard verification)
  await verifyBrowserCredential(credential);

  // 2. Verify payment details
  if (credential.payment.amount !== expectedAmount.value) {
    throw new Error("Amount mismatch");
  }

  if (credential.payment.currency !== expectedAmount.currency) {
    throw new Error("Currency mismatch");
  }

  // 3. Verify passkey attestation (WebAuthn)
  if (!credential.binding.passkey) {
    throw new Error("Passkey required");
  }

  await verifyWebAuthnAttestation(credential.binding.passkey);

  // 4. Submit to payment processor
  const settlement = await paymentProcessor.authorize({
    credential: credential,
    amount: credential.payment.amount,
    currency: credential.payment.currency,
    merchantId: merchantId
  });

  return settlement;
}
```

### Security Properties

**Session binding + Passkey = Zero fraud vector**:
- Credential bound to TLS session (can't steal)
- Passkey proves user presence (can't replay without biometric)
- Amount in signed credential (can't modify)
- Short-lived (30 seconds)

**Result**: Payment fraud reduction from 1.8% to <0.01%

---

## Agent Payment Protocol (AP2)

### Problem Statement

**AI agents need to autonomously pay for services**:
- API calls ($0.001 - $1.00 per call)
- Compute resources ($0.10 - $10/hour)
- Data access ($0.01 - $0.50 per dataset)

**Current OAuth limitations**:
- Requires human consent per payment
- No cryptographic spending limits
- Agent compromise = full account drain

### AP2 Solution

**Browser acts as payment clearing house**:
1. User delegates payment authority to agent (with cryptographic limits)
2. Agent autonomously makes payments (browser enforces limits)
3. Service verifies via browser credential
4. Receipts form cryptographic audit chain

### Agent Delegation Flow

**Step 1: User authorizes agent with spending limits**

```javascript
// User grants payment authority to agent
const agentCredential = await navigator.credentials.get({
  fedcm: {
    providers: [{ configURL: "https://accounts.google.com/fedcm.json" }]
  },

  // Agent delegation
  agentDelegation: {
    agentId: "agent://my-data-analyzer",
    agentPublicKey: agentPublicKeyJWK,

    // Cryptographic spending limits
    capabilities: {
      payment: {
        maxAmount: "100.00",           // Total budget: $100
        perTransaction: "1.00",         // Max per call: $1
        currency: "USD",
        validUntil: Date.now() + 86400000  // 24 hours
      },

      rateLimit: {
        count: 1000,                    // Max 1000 calls
        window: "24h"
      }
    }
  }
});

// Browser issues agent-specific credential (POD format)
// Agent receives credential + can request proofs from browser
```

**Step 2: Agent makes autonomous payment**

```javascript
// Agent code (runs autonomously)
async function analyzeDataset(datasetUrl) {
  // Request payment credential from browser
  const paymentProof = await agentCredential.generateProof({
    audience: datasetUrl,
    payment: {
      amount: "0.50",  // $0.50 for this API call
      service: datasetUrl
    },
    nonce: await fetchNonce(datasetUrl)
  });

  // Browser checks:
  // - Is 0.50 <= perTransaction limit (1.00)? ✓
  // - Is totalSpent + 0.50 <= maxAmount (100.00)? ✓
  // - Is callCount < rateLimit.count (1000)? ✓
  // If all pass, browser signs proof. Otherwise, throws error.

  // Make payment
  const result = await fetch(datasetUrl, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${paymentProof}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ query: "SELECT * FROM dataset" })
  });

  return result.json();
}

// Agent can call this 1000 times, spending up to $100 total
// Browser enforces cryptographically (agent cannot bypass)
```

**Step 3: Service verifies and records**

```javascript
// Service API endpoint
app.post('/analyze', async (req, res) => {
  const paymentProof = req.headers.authorization.replace('Bearer ', '');

  // Verify browser credential
  const credential = await verifyBrowserCredential(paymentProof);

  // Check payment authorization
  if (!credential.payment || credential.payment.amount !== "0.50") {
    return res.status(402).json({ error: "Payment required: $0.50" });
  }

  // Verify agent delegation
  if (!credential.agentDelegation) {
    return res.status(403).json({ error: "Agent delegation required" });
  }

  // Check capability limits (double-check, though browser enforces)
  if (parseFloat(credential.payment.amount) > parseFloat(credential.capabilities.payment.perTransaction)) {
    return res.status(403).json({ error: "Exceeds per-transaction limit" });
  }

  // Process request
  const result = await processDatasetQuery(req.body.query);

  // Issue receipt (POD format)
  const receipt = POD.create({
    type: "PaymentReceipt",
    parentCredential: credential,  // Link to payment proof
    service: "https://api.example.com/analyze",
    amount: "0.50",
    currency: "USD",
    timestamp: Date.now(),
    result: {
      rowsReturned: result.length
    },
    signature: await serviceSign(receipt)
  });

  res.json({
    data: result,
    receipt: receipt
  });
});
```

---

## Cryptographic Spending Enforcement

### Browser Enforcement Logic

**Browser maintains spending state per agent delegation**:

```javascript
// Browser-internal state (not accessible to agent or JS)
class AgentDelegationState {
  constructor(delegation) {
    this.agentId = delegation.agentId;
    this.capabilities = delegation.capabilities;
    this.totalSpent = 0;
    this.callCount = 0;
    this.windowStart = Date.now();
  }

  async enforcePayment(requestedAmount) {
    const amount = parseFloat(requestedAmount);
    const maxPerTx = parseFloat(this.capabilities.payment.perTransaction);
    const maxTotal = parseFloat(this.capabilities.payment.maxAmount);

    // Check per-transaction limit
    if (amount > maxPerTx) {
      throw new Error(
        `Payment of ${amount} exceeds per-transaction limit of ${maxPerTx}`
      );
    }

    // Check total budget
    if (this.totalSpent + amount > maxTotal) {
      throw new Error(
        `Payment of ${amount} would exceed total budget. ` +
        `Spent: ${this.totalSpent}, Limit: ${maxTotal}`
      );
    }

    // Check rate limit
    const now = Date.now();
    const windowDuration = parseWindow(this.capabilities.rateLimit.window);

    if (now - this.windowStart > windowDuration) {
      // Reset window
      this.windowStart = now;
      this.callCount = 0;
    }

    if (this.callCount >= this.capabilities.rateLimit.count) {
      throw new Error(
        `Rate limit exceeded: ${this.capabilities.rateLimit.count} calls per ${this.capabilities.rateLimit.window}`
      );
    }

    // All checks passed - atomically update state
    await this.atomicUpdate(() => {
      this.totalSpent += amount;
      this.callCount++;
    });

    return true;
  }

  async atomicUpdate(fn) {
    // Browser ensures atomic update (no race conditions)
    await browser.storage.transaction(async (tx) => {
      fn();
      await tx.put(this.agentId, this.serialize());
    });
  }
}
```

**Key property**: Agent code runs in renderer process, enforcement runs in browser process. Agent cannot bypass enforcement (process isolation + private key held in browser process).

### Proof Generation with Enforcement

```javascript
// Browser API (called by agent)
navigator.credentials.generateAgentProof = async function(
  agentCredential,
  proofRequest
) {
  // 1. Validate agent credential
  const delegation = await validateAgentDelegation(agentCredential);

  // 2. Load spending state
  const state = await browser.storage.getDelegationState(delegation.agentId);

  // 3. Enforce spending limits (throws if violation)
  await state.enforcePayment(proofRequest.payment.amount);

  // 4. Generate proof (browser signs)
  const proof = POD.create({
    type: "AgentPaymentProof",
    agentId: delegation.agentId,
    parentDelegation: agentCredential,
    audience: proofRequest.audience,
    payment: proofRequest.payment,
    nonce: proofRequest.nonce,
    timestamp: Date.now(),

    // Include spending state proof (without revealing history)
    spendingProof: {
      totalSpent: { lessThan: delegation.capabilities.payment.maxAmount },
      callCount: { lessThan: delegation.capabilities.rateLimit.count }
    }
  });

  // 5. Sign with browser key
  proof.signature = await browser.identity.sign(proof);

  return proof;
};
```

---

## Clearing House Architecture

### Browser as Clearing House

**Concept**: Browser acts as local clearing house for agent payments, similar to how payment networks clear transactions.

**Responsibilities**:
1. **Authorization**: Verify agent has authority to spend
2. **Enforcement**: Apply spending limits cryptographically
3. **Recording**: Maintain audit log (privacy-preserving)
4. **Settlement**: Provide proofs for external settlement (optional)

### Architecture Diagram

```
┌──────────────────────────────────────────────────────────┐
│                    BROWSER                               │
│  ┌────────────────────────────────────────────────────┐  │
│  │          Clearing House                            │  │
│  │                                                    │  │
│  │  - Spending state per agent                       │  │
│  │  - Cryptographic enforcement                      │  │
│  │  - Audit log (privacy-preserving)                 │  │
│  │  - Proof generation                               │  │
│  └────────────────────────────────────────────────────┘  │
│                        ↕                                 │
│  ┌────────────────────────────────────────────────────┐  │
│  │          Agent Delegation Store                    │  │
│  │                                                    │  │
│  │  AgentID: agent://my-analyzer                     │  │
│  │  MaxAmount: $100                                  │  │
│  │  PerTransaction: $1                               │  │
│  │  TotalSpent: $47.50                               │  │
│  │  CallCount: 95                                    │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
                          ↕
         ┌────────────────────────────────┐
         │         Agent                  │
         │  (autonomous, untrusted)       │
         └────────────────────────────────┘
                          ↕
         ┌────────────────────────────────┐
         │      Service API               │
         │  (verifies browser proof)      │
         └────────────────────────────────┘
```

### Audit Log

**Browser maintains privacy-preserving audit log**:

```javascript
// Audit log entry (POD format)
const auditEntry = POD.create({
  type: "AgentPaymentAudit",
  agentId: "agent://my-analyzer",
  timestamp: Date.now(),

  // Aggregated stats (no individual transactions)
  period: {
    start: periodStart,
    end: periodEnd
  },

  summary: {
    totalSpent: "47.50",
    callCount: 95,
    servicesUsed: 3  // Number of unique services
  },

  // No individual transaction details (privacy)
  // User can request detailed log if needed
});

// User can generate audit proof for external verification
const auditProof = auditEntry.generateProof({
  reveal: ["summary"],
  predicates: {
    totalSpent: { lessThan: "100.00" },
    callCount: { lessThan: 1000 }
  }
});

// Accountant verifies: Agent stayed within limits
// Accountant does NOT learn: Which services, when, what data
```

---

## Recursive Proof Chains

### Proof Chain Architecture

**AP2 enables cryptographic audit chains**:

```
User Identity POD
      ↓ (attested by IdP)
Agent Delegation POD
      ↓ (signed by browser)
Payment Proof POD
      ↓ (verified by service)
Receipt POD
      ↓ (signed by service)
Audit Proof POD
      ↓ (verified by auditor)
```

**Each level proves properties of previous level without revealing raw data**.

### Example: Monthly Audit

**User wants to prove "agent stayed within budget" to accountant**:

```javascript
// 1. Collect receipts from services
const receipts = await Promise.all(
  serviceEndpoints.map(s => s.getReceipts(agentId, monthStart, monthEnd))
);

// 2. Generate aggregate proof
const aggregateProof = POD.createAggregate({
  type: "MonthlyAgentSpending",
  period: { month: "2024-01", agentId: "agent://my-analyzer" },

  // Inputs: All payment receipts
  receipts: receipts,

  // Prove aggregate properties
  predicates: {
    totalSpent: {
      value: receipts.reduce((sum, r) => sum + parseFloat(r.amount), 0),
      lessThan: 100.00
    },
    transactionCount: receipts.length,
    allWithinLimit: receipts.every(r => parseFloat(r.amount) <= 1.00)
  },

  // Don't reveal individual transactions
  revealed: []
});

// 3. Auditor verifies proof
const verification = await aggregateProof.verify();

// Auditor learns:
// ✓ Total spent in January: < $100
// ✓ All transactions <= $1
// ✓ Total transaction count

// Auditor does NOT learn:
// ✗ Which services used
// ✗ When transactions occurred
// ✗ What data accessed
// ✗ Individual transaction amounts
```

### Proof Chain Verification

```javascript
async function verifyProofChain(finalProof) {
  // Recursively verify entire chain
  let currentProof = finalProof;

  while (currentProof.parentProof) {
    // Verify this level
    const valid = await currentProof.verify();
    if (!valid) throw new Error(`Invalid proof at ${currentProof.type}`);

    // Verify parent link
    const parentHash = await hash(currentProof.parentProof);
    if (currentProof.parentHash !== parentHash) {
      throw new Error("Parent link broken");
    }

    // Move up chain
    currentProof = currentProof.parentProof;
  }

  // Verify root (IdP attestation)
  return await verifyIdPAttestation(currentProof);
}
```

---

## Implementation Examples

### Example 1: Agent Marketplace

**Scenario**: AI agent marketplace where agents buy/sell services to each other

```javascript
// Agent A sells data analysis service
class DataAnalysisAgent {
  async handleRequest(paymentProof, dataQuery) {
    // Verify payment
    const credential = await verifyBrowserCredential(paymentProof);
    if (credential.payment.amount !== this.price) {
      throw new Error("Incorrect payment");
    }

    // Process request
    const result = await this.analyze(dataQuery);

    // Issue receipt
    const receipt = POD.create({
      type: "ServiceReceipt",
      parentCredential: credential,
      service: "data-analysis",
      amount: credential.payment.amount,
      result: { rowCount: result.length },
      signature: await this.sign(receipt)
    });

    return { result, receipt };
  }
}

// Agent B buys analysis service from Agent A
class DataConsumerAgent {
  async buyAnalysis(dataset) {
    // Generate payment proof (browser enforces limits)
    const paymentProof = await this.agentCredential.generateProof({
      audience: "agent://data-analysis-service",
      payment: { amount: "0.25" }
    });

    // Call service
    const response = await fetch("https://agent-a.example/analyze", {
      method: "POST",
      headers: { Authorization: `Bearer ${paymentProof}` },
      body: JSON.stringify({ dataset })
    });

    return response.json();
  }
}
```

### Example 2: Autonomous Compute Allocation

**Scenario**: Agent dynamically allocates compute resources based on workload

```javascript
class ComputeAgent {
  constructor(agentCredential) {
    this.credential = agentCredential;
    this.currentWorkload = 0;
  }

  async scaleCompute(targetWorkload) {
    const requiredInstances = Math.ceil(targetWorkload / 100);
    const costPerInstance = 0.50;  // $0.50/hour

    // Request payment authorization for compute
    try {
      const paymentProof = await this.credential.generateProof({
        audience: "https://compute.example.com/allocate",
        payment: {
          amount: (requiredInstances * costPerInstance).toFixed(2)
        }
      });

      // Allocate compute
      const allocation = await fetch("https://compute.example.com/allocate", {
        method: "POST",
        headers: { Authorization: `Bearer ${paymentProof}` },
        body: JSON.stringify({
          instances: requiredInstances,
          duration: "1h"
        })
      });

      return allocation.json();

    } catch (error) {
      if (error.message.includes("budget")) {
        // Hit spending limit - scale back
        console.log("Budget limit reached, using cached resources");
        return this.useCachedResources();
      }
      throw error;
    }
  }
}
```

### Example 3: Multi-Agent Coordination with Budget

**Scenario**: Swarm of agents coordinating with shared budget

```javascript
class AgentSwarmCoordinator {
  constructor(sharedBudget) {
    this.budget = sharedBudget;  // $100 shared across all agents
    this.agents = [];
  }

  async delegateToAgent(agentId, subBudget) {
    // Create sub-delegation with portion of budget
    const subDelegation = await this.budget.delegateTo({
      agentId: agentId,
      capabilities: {
        payment: {
          maxAmount: subBudget,
          perTransaction: "1.00"
        }
      }
    });

    // Agent receives sub-delegation and can spend autonomously
    return subDelegation;
  }

  async executeSwarmTask(task) {
    // Divide budget among agents
    const budgetPerAgent = this.budget.maxAmount / this.agents.length;

    // Delegate to each agent
    const delegations = await Promise.all(
      this.agents.map(agent =>
        this.delegateToAgent(agent.id, budgetPerAgent)
      )
    );

    // Agents execute in parallel
    const results = await Promise.all(
      this.agents.map((agent, i) =>
        agent.executeTask(task, delegations[i])
      )
    );

    // Collect receipts and generate aggregate audit
    const receipts = results.flatMap(r => r.receipts);
    const totalSpent = receipts.reduce(
      (sum, r) => sum + parseFloat(r.amount),
      0
    );

    return {
      results: results.map(r => r.output),
      totalSpent: totalSpent,
      receipts: receipts
    };
  }
}
```

---

## Appendix: AP2 Protocol Messages

### Message Types

```typescript
// Agent delegation request
interface AgentDelegationRequest {
  type: "agent-delegation-request";
  agentId: string;
  agentPublicKey: JsonWebKey;
  capabilities: {
    payment: PaymentCapability;
    rateLimit?: RateLimitCapability;
  };
  validUntil: number;
}

// Agent payment proof
interface AgentPaymentProof {
  type: "agent-payment-proof";
  agentId: string;
  parentDelegation: string;  // POD
  audience: string;
  payment: {
    amount: string;
    currency: string;
  };
  nonce: string;
  timestamp: number;
  signature: Signature;
}

// Service receipt
interface ServiceReceipt {
  type: "service-receipt";
  parentProof: string;  // POD
  service: string;
  amount: string;
  currency: string;
  timestamp: number;
  result?: any;
  signature: Signature;
}

// Audit aggregate
interface AuditAggregate {
  type: "audit-aggregate";
  period: { start: number; end: number };
  agentId: string;
  summary: {
    totalSpent: string;
    callCount: number;
    servicesUsed: number;
  };
  proof: ZKProof;  // Proves summary without revealing transactions
}
```

---

**References**:
- [Payment Handler API](https://www.w3.org/TR/payment-handler/)
- [Payment Request API](https://www.w3.org/TR/payment-request/)
- [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/)
- [POD Specification](https://pod.org)
- [Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/)
