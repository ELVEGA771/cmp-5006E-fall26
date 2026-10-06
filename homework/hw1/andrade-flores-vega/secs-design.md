# SECS — Secure Electronic Contract Signing (Design Document)

Parties: **Alice** (provider) and **Bob** (client). Adversary: **Mallory**, who controls
the network (reads, drops, replays, and modifies messages) but does not hold any party's
private key. A **CA** is the trust anchor.

Goals: non-repudiation of origin, non-repudiation of receipt, integrity, and
confidentiality of the contract terms in transit.

---

## 1. Primitives and why each

| Need | Primitive | Course source | Why this one |
|---|---|---|---|
| Fingerprint of the contract | **SHA-256** | Week 3 (`hashlib`; used in `dh_pki.digest`) | Collision-resistant, so a signature over the digest commits to the whole contract. The week-3 toy `md_hash` is only a break target. |
| Origin + integrity + non-repudiation | **Digital signature, hash-then-sign (RSA)** | Weeks 4–5 (`sign`/`verify`) | Only the holder of the private key can produce the signature, and anyone with the certified public key can verify it. A MAC cannot give non-repudiation, because both sides hold the key. |
| Binding a public key to a person | **Certificates + chain validation against a trust store** | Week 5 (`make_cert`, `validate`) | A raw public key says nothing about who owns it. The CA certifies it, and the verifier checks the chain. |
| Shared session key over a hostile wire | **Diffie–Hellman (MODP group)** | Week 5 | Gives a fresh shared secret without ever sending a key. It is secure against a passive eavesdropper, but a MITM defeats it unless the endpoints are authenticated. |
| Authenticating the DH exchange | **Signatures over the DH values** | Week 5 (the "authenticated DH" fix) | Closes the Mallory-in-the-middle hole shown in the week-5 studio. |
| Deriving session keys | **HMAC-SHA256** as the key-derivation step | Week 3 (`good_mac` uses real HMAC) | Produces separate keys per direction from the DH secret and both nonces. HMAC avoids the `H(secret‖msg)` length-extension flaw. |
| Confidentiality + in-transit integrity | **AEAD: AES-GCM** | Week 3 (named in the studio README) | Encrypts and authenticates in one primitive. Any modification of a ciphertext is rejected. The caveat is that a (key, nonce) pair must never repeat. |
| Secret comparisons | **`hmac.compare_digest`** | Week 4 | Constant-time, so no early-exit timing leak. |

**Parameter note.** The studio code uses teaching sizes (64-bit RSA, 1024-bit MODP). A
real deployment would use RSA ≥ 3072 (or ECDSA), a DH group ≥ 2048 bits, and RSA-PSS
padding rather than the studio's textbook `digest % n`. These are choices *outside* the
studios; the design argument does not change.

**Key separation.** Each party has two distinct secrets: a long-term **signing key**
(certified by the CA) and a per-session **ephemeral DH exponent**. Neither is ever used
for the other's job.

---

## 2. Message flow and trust boundaries

```
 ┌─────────── ALICE DOMAIN ──────────┐   ┌────── CA DOMAIN ──────┐   ┌─────────── BOB DOMAIN ────────────┐
 │ trusts: own sk_A, CA root key     │   │ trusts: own root key  │   │ trusts: own sk_B, CA root key     │
 │ generates sk_A herself (CSPRNG)   │   │ signs pub keys only;  │   │ generates sk_B himself (CSPRNG)   │
 │                                   │   │ never sees sk_A/sk_B  │   │                                   │
 └───────────────┬───────────────────┘   └──────────┬────────────┘   └───────────────┬───────────────────┘
                 │  (0) enrolment: send pk_A, get Cert_A      Cert_B ← pk_B (0)      │
                 │ ◄──────────────────────────────────┴─────────────────────────────►│
 ════════════════╪═════════════════ TRUST BOUNDARY: untrusted network (Mallory) ══════╪════════════════
                 │                                                                   │
  PHASE 1 — authenticated key agreement                                              │
   (1) A → B :  Cert_A, g^a, N_A, Sig_A( g^a ‖ N_A ‖ id_B )                         │
   (2) B → A :  Cert_B, g^b, N_B, Sig_B( g^b ‖ N_B ‖ g^a ‖ N_A ‖ id_A )             │
       Both: validate(Cert chain, trust store) → verify signature → derive           │
             K_AB = HMAC(g^ab, "A→B"‖N_A‖N_B),   K_BA = HMAC(g^ab, "B→A"‖N_A‖N_B)   │
                 │                                                                   │
  PHASE 2 — contract (every message below is AES-GCM under K_dir, nonce = counter)   │
   (3) A → B :  Enc( contract C, contract_id )          H_C = SHA-256(contract_id‖C‖id_A‖id_B‖N_A‖N_B)
   (4) B → A :  Enc( Sig_B(H_C) )                       Bob signs the contract
   (5) A → B :  Enc( Sig_A(H_C) )                       Alice countersigns → final copy F = (C, Sig_A, Sig_B)
  PHASE 3 — receipts (signatures cover H_F = SHA-256(C‖Sig_A‖Sig_B))
   (6) B → A :  Enc( R_B = Sig_B("receipt"‖H_F) )       Bob received the final signed copy
   (7) A → B :  Enc( R_A = Sig_A("receipt"‖H_F) )       Alice received Bob's signature and receipt
```

**Trust boundaries**
- **Network (untrusted).** Everything between the domains is attacker-controlled. Nothing
  on it is trusted until it is verified by a signature, a certificate chain, or an AEAD tag.
- **Each party's domain.** Trusted to hold its own signing key. The key is generated
  locally and never leaves.
- **CA.** Trusted for exactly one thing: the binding of identity to public key. It
  never holds a private key, so it cannot sign in anyone's name.

**Why the evidence stays verifiable.** The signatures in steps 4–7 are over *plaintext
hashes*, not over ciphertext. After the session key is discarded, either party can still
show `C`, `Sig_A`, `Sig_B`, `R_A`, `R_B` and the certificates to a third party, who verifies them
without any session secret.

---

## 3. Control Scorecard (axis 2): each guarantee and its condition

**Non-repudiation of origin.** Neither party can deny having signed `H_C`
**provided** (a) the signer's private key was not compromised or shared, (b) the CA did
not mis-issue a certificate binding that key to the wrong identity, (c) SHA-256 remains
collision-resistant and the signature scheme is unforged, and (d) the certificate was valid
(not expired or revoked) at signing time. Because the signed hash covers both identities
and both nonces, the signature cannot be moved to another contract or session.

**Non-repudiation of receipt.** Neither party can deny having received the final signed
copy **provided** the corresponding receipt (`R_B` for Bob, `R_A` for Alice) was
actually delivered and stored by the other side, plus the same key and CA conditions as
above. This guarantee is **weaker** than origin: whoever sends the last message of the
protocol (Alice, in step 7) could withhold it. That is the classic fair-exchange problem,
which this design does not eliminate; see section 5.

**Integrity.** Any alteration of the contract is detected **provided** (a) SHA-256 is
collision-resistant, so the signed digest pins one contract, (b) the verifier checks the
signatures against a *certified* key, and (c) the AEAD tag check is enforced and the
(key, nonce) pair is never reused. Hash alone is not enough, since a hash anyone can recompute proves
nothing against an active attacker, so integrity rests on the signatures plus the AEAD tag.

**Confidentiality of the terms in transit.** The terms stay secret from an observer
**provided** (a) the DH exchange was authenticated (steps 1–2 verified), so no MITM
sits in the middle, (b) the DH exponents come from a good CSPRNG and the group is large
enough, (c) AES-GCM is used with unique nonces under a fresh per-session, per-direction
key, and (d) the endpoints are not compromised. Confidentiality is *in transit only*: once
decrypted, protection is the endpoint's responsibility. DH without step (a) would give a
private conversation with an impostor.

---

## 4. Which of the six broken deployments' mistakes does this avoid?

| # | Broken deployment | Mistake | How SECS avoids it |
|---|---|---|---|
| 1 | `reused_pad` | One pad/key reused for every message, so `C₁⊕C₂ = P₁⊕P₂` | No pad is used. Each session derives fresh keys from a new DH exchange, with separate keys per direction, so no key encrypts two sessions. |
| 2 | `ecb_store` | ECB: equal plaintext blocks give equal ciphertext blocks, leaking structure | AES-GCM, never ECB. A unique nonce per message makes identical plaintexts produce different ciphertexts. |
| 3 | `ctr_log` | CTR nonce reused across entries (also fatal in GCM) | The nonce is a per-direction counter under a key that is new each session, so a (key, nonce) pair never repeats. A counter that would wrap or repeat aborts the session. |
| 4 | `token_mac` | `SHA256(secret‖data)`, which is length-extendable | No `H(secret‖msg)` anywhere. Integrity comes from signatures and the AEAD tag. Key derivation uses HMAC, which nests the hash. |
| 5 | `keygen_fleet` | Low-entropy keygen produced a shared RSA prime | Each party generates its own key locally from a CSPRNG, instead of by a central authority or a shared seeded PRNG. The CA only certifies public keys, so it never holds a private key. (This is conditional on each device having real entropy; see section 5.) |
| 6 | `timing_compare` | Early-exit comparison leaks the matching prefix | Tag and digest comparisons use `hmac.compare_digest`, and signature verification and the GCM tag check are done by the library in constant time. |

---

## 5. Known limits (carried into Part C)

- **Fair exchange.** The last sender can withhold the final receipt. Mitigations such as a
  trusted timestamp or escrow service add a new trusted party, so we state the limit and do not claim to
  solve it.
- **Trusted CA.** Origin, receipt and confidentiality all inherit the assumption that the CA
  never mis-issues. We also assume revocation (CRL or OCSP) is checked, and we have not specified it.
- **Device entropy.** Avoiding break #5 depends on every party's CSPRNG actually being
  seeded. If it is not, the design fails the same way.
- **Confidentiality vs. auditability.** Signing plaintext hashes makes the evidence portable
  to a third party, but whoever holds the signed contract and the evidence can reveal it. We
  chose provable evidence over secrecy of the contract against a later dispute.
- **Parameters.** The studio sizes are for teaching. The scorecard statements assume
  production-grade sizes and padding.
