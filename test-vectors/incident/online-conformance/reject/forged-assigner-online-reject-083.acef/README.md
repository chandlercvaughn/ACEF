# Forged assigner — online REJECT (ACEF-083), offline class PASS

A public incident_card bearing a valid-pattern `AIIC-OPENAI-2026-…` id that was forged by an attacker (signed with an attacker key, not OpenAI's). OFFLINE-deterministic validation checks pattern + JWS self-consistency ONLY and NEVER attributes the id to openai.com — so this card PASSES the offline class BY DESIGN (no ACEF-083 offline). Attribution is the OPTIONAL ONLINE domain-control verifier's job: presented with an attacker proof bound to the WRONG key (a presented-but-invalid proof), the online class returns `reject` → ACEF-083 `class: online-conformance`. A network timeout instead returns `unverified` (an explicit non-result), never a silent pass and never a forgery verdict. The online check runs against INJECTED stubs — no real network. See `tests/conformance/test_incident_vectors.py` (test_forged_assigner_*).

**Expected code(s):** ACEF-083 (online-conformance reject); offline class: pass (none)
