# Where our breaks or design might be unfair.
Daniel Andrade - Andrés Vega - Carlos Flores

**1. Did a break rely on an assumption the deployment didn't actually make?**

Yes, for example `reused_pad` relies on the fact that plaintexts are English and that you can guess cribs.

**2. Is your SECS design's guarantee conditional on something you've hand-waved (a trusted CA, a secure channel for key distribution)?**

Yes, we have some assumptions:
- We consider a trusted CA.
- We assume the TTP is trustworthy and available.

**3. Which of the four+ breaks are you least confident are reproducible, and why?**

The timing break (`verify_login`) is the least reproducible: its signal is a
~34 us difference per byte, so it depends on machine load. The notebook recovers
the secret 5/5 times with the interleaved estimator (`time_guesses`, 41 rounds
per candidate), but a sequential median-per-candidate version flapped
repeatedly on the same machine (the instructor's `--check` for `#6` also flapped
here). On a busier machine the margins can shrink and more rounds would be
needed.

**4. Does your design trade one goal for another (e.g. confidentiality vs. auditability)? Name the trade.**
- **Symmetry traded for liveness**. The rule "valid only when both ACKs arrive" keeps the outcome symmetric, so neither party is committed alone. The cost is that a party who withholds their ACK, or a TTP that fails mid-protocol, leaves the contract unconfirmed. The party who already sent their ACK has no recourse inside the protocol.
- **Confidentiality traded for fairness**. The contract is never hidden from the TTP, and the TTP also stores a full copy. It has to because it checks `H(contract)` and builds the final copy.
