# Multi-profile card missing the binding eu_ai_act member (per-profile ACEF-081)

A PUBLIC incident_card declaring BOTH the EU Art.73 (`eu-ai-act-art73-2026`) and OECD (`oecd-ai-incidents-2025`) profiles, carrying the `oecd` crosswalk member but OMITTING the `eu_ai_act` member that the binding Art.73 profile mandates. The union-requiredness rule (Q16) therefore fails for eu-ai-act-art73 only: a per-profile-attributed ACEF-081 ERROR fires with details.profile_id=eu-ai-act-art73-2026 (the OECD member is present, so OECD does not fail). This is the §6-enumerated multi-profile binding ACEF-081 FAIL bundle.

**Expected code(s):** ACEF-081, ACEF-084
