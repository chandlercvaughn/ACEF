# severity ↔ band() disagreement (ACEF-088)

A public incident_card carrying BOTH `severity` and `severity_vector` where the coarse `severity` (`minor`) disagrees with `band(severity_vector)` (`major`). The consistency check raises ACEF-088.

**Expected code(s):** ACEF-088
