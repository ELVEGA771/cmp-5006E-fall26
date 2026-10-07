# AI Log — Homework 1 (Duel 1, Crypto & Protocols)

Per [`resources/ai-policy.md`](../../../resources/ai-policy.md). All data shared with the
assistant was the course's synthetic lab material (`duel1_targets.py`, studios,
notebooks); no real secrets or personal data.

---

## Break 06 — verify_login (timing side channel)

**Date:** 2026-10-06
**Tool:** OpenCode (DeepSeek V4.1 Flash)
**What I asked:** "Necesito que me ayudes rompiendo los deployments 5 y 6" siguiendo el
  formato de los breaks ya resueltos, y que el código reutilice snippets de las clases
  de la semana 4.
**What I got:**
- `breaks/06-verify_login/verify_login.py` — `timing_attack` con `time_guesses` del
  studio (mediciones interleaved) y `__main__` que imprime el artefacto.
- `breaks/06-verify_login/verify_login.ipynb` — ejecutado: recupera `83fabf35`, cinco
  corridas de fiabilidad (5/5) y una celda del fix con `constant_time_equal` /
  `hmac.compare_digest`.
- `breaks/06-verify_login/README.md` — assumption, misuse vs. primitive, artefacto y
  fiabilidad (41 rounds por candidato, ~34 us de separación por byte).
- El asistente señaló que el `--check` del instructor falla en `#6` en esta máquina
  (usa medianas secuenciales); la versión interleaved recupera 5/5.
- Después, a pedido del equipo, simplificó el lenguaje del README.

**What I did with it:** Revisé los archivos generados y pedí ajustes de redacción.

**Did I understand it?** Sí — el tiempo de la comparación depende del prefijo correcto;
  con las mediciones interleaved y la mediana, la señal queda visible.

---

## Break 05 — keygen_fleet (shared RSA prime)

**Date:** 2026-10-06
**Tool:** OpenCode (DeepSeek V4.1 Flash)
**What I asked:** La misma petición (deployments 5 y 6, reutilizando código de clase).
**What I got:**
- `breaks/05-keygen_fleet/keygen_fleet.py` — scan pairwise con `math.gcd` y
  `factor_from_shared` del studio de la semana 4 (`studios/week-04/rsa_lab.py`) para
  recuperar `d` de ambos dispositivos; `__main__` que imprime el artefacto.
- `breaks/05-keygen_fleet/keygen_fleet.ipynb` — ejecutado: moduli → gcd →
  factorización → `d` → round-trip RSA.
- `breaks/05-keygen_fleet/README.md` — assumption, misuse vs. primitive y artefacto.
- Artefacto: `p = 14723961130838400979`,
  `d(device0) = 155006092543738932355592225651672081825`,
  `d(device2) = 101591964428919489627153881052022337249`, confirmados con
  `(m^e)^d mod n == m`.

**What I did with it:** Revisé los archivos generados y pedí ajustes de redacción.

**Did I understand it?** Sí — un gcd entre los moduli revela el primo compartido y la
  clave privada sale de la factorización, sin atacar la matemática de RSA.

---

## Breaks 00, 02 y 04 — bloques `__main__`

**Date:** 2026-10-06
**Tool:** OpenCode (DeepSeek V4.1 Flash)
**What I asked:** Agregar a los scripts existentes un bloque `__main__` que imprima el
  artefacto, como pide el README de `duel-1-crypto`.
**What I got:** Bloques `__main__` en `00-reused_pad/reused_pad.py`,
  `02-token_mac/token_mac.py` y `04-ctr_log/ctr_log.py`; los tres imprimen su artefacto
  al correrlos. Nota del asistente: en `reused_pad` y `ctr_log` el último byte no
  aparece en ningún XOR, así que la salida lo marca con `?` y se infiere por contexto.
**What I did with it:** Revisé las salidas de los cinco scripts.

**Did I understand it?** Sí.

---

## Break 04 — ctr_log (AES-CTR nonce reuse)

**Date:** 2026-10-06
**Tool:** Claude Code (Claude Opus 5.5), inside VS Code
**What I asked:** "Look at how `reused_pad` was implemented in
  `homework/hw1/andrade-flores-vega` and do the same for `ctr_log` and `token_mac`.
  The instructions are in `hw-1-crypto.md` and the `duel-1-crypto` README; the studios
  and notebooks that apply these are in the same repo. In the end I want them to look
  like `reused_pad`, with the 3 files."
**What I got:**
- `breaks/04-ctr_log/ctr_log.py` — the same `crib_drag` as `reused_pad.py`, plus
  `recover_entry(c_known, c_target, known_plaintext)` that computes
  `C_known ⊕ C_target ⊕ P_known`.
- `breaks/04-ctr_log/ctr_log.ipynb` — an executed notebook that crib-drags step by step
  (date → `user=admin` → `user=alice action=login` → full guess of `log0`), recovers
  `log2`, and confirms the guess by decrypting `log1` with the same `log0` guess.
- `breaks/04-ctr_log/README.md` — assumption violated, misuse vs. primitive, and the
  recovered artifact:
  `2025-03-01 12:09 user=admin action=export result=success from=10.0.0.?`
- The assistant pointed out that the last byte of `log2` (last IP digit) cannot be
  recovered: `log2` is 70 bytes and the other entries are 69, so that keystream byte
  never appears in any XOR.

**What I did with it:** Ran the notebook and review if everything is ok.

**Did I understand it?** Yes

---

## Break 02 — token_mac (length extension on `H(secret ‖ data)`)

**Date:** 2026-10-06
**Tool:** Claude Code (Claude Opus 5.5), inside VS Code
**What I asked:** Same request as above (one prompt covered both breaks).
**What I got:**
- `breaks/02-token_mac/token_mac.py` — `forge_token(data, tag, secret_len, extension)`
  (rebuilds the glue padding and resumes `_md_hash` from the observed tag, following
  the week 3 studio `forge_extension`) and `find_secret_len(...)`, which tries secret
  lengths 1–32 and uses the server's `verify_token` as an oracle.
- `breaks/02-token_mac/token_mac.ipynb` — an executed notebook showing that a naive edit
  with the old tag is rejected, then forging an accepted token:
  `data = b'user=alice&role=user\x00\x00\x00&role=admin'`, `tag = 4024164909`.
- `breaks/02-token_mac/README.md` — assumption violated, misuse vs. primitive (fix:
  HMAC), and the forged artifact.
- The assistant noted two limitations: the oracle only reveals the secret length
  mod 4 (lengths 1, 5, 9, … are all accepted), and the escalation to admin assumes
  the application parses repeated parameters as "last value wins".

**What I did with it:** Ran the notebook and review if everything is ok.

**Did I understand it?** Yes
