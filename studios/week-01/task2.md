```
(Internet / External environment you DO NOT control)
                                  |
  [ Web Browser ]                 |
  (User / Attacker)               |
        |                         |
        | 1. HTTP POST (Login)    |  <-- Trust Boundary 1 (Untrusted input)
        v                         |
----------------------------------+-------------------------------------
                                  |
  [ Web Server (DVWA) ]           |  (Internal network / Environment you DO control)
  (Logic, Sessions, Auth)         |
        |                         |
        | 2. SQL Query            |  <-- Trust Boundary 2 (Secrets / Privileges)
        v                         |
  [ Database ]                    |
  (Tables, Passwords)             |
```

## 2 · STRIDE — the six things that go wrong

STRIDE is a checklist so you do not have to be brilliant. Walk each letter against
each component and each arrow.

| Letter | Threat | Plain question | Example |
|---|---|---|---|
| **S** | **Spoofing** | Can someone pretend to be someone else? | Logging in as another user with a guessed session token |
| **T** | **Tampering** | Can someone change data they should not? | Maybe  |
| **R** | **Repudiation** | Can someone deny doing it, with no way to prove otherwise? | No audit log, so a fraudulent transfer cannot be attributed |
| **I** | **Information disclosure** | Can someone read data they should not? | An error page that prints the SQL query, or a database backup on a public URL |
| **D** | **Denial of service** | Can someone make it unavailable? | One expensive search request repeated until the site stalls |
| **E** | **Elevation of privilege** | Can someone do something only an admin should? | Changing `?role=user` to `?role=admin` and being believed |

**The letter is a prompt, not a taxonomy exam.** If a threat plausibly fits two
letters, pick one and move on; nobody is grading the classification.