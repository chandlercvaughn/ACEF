# ACEF User Guide

This guide walks compliance teams, developers, and auditors through using the ACEF Reference SDK to build, validate, and manage AI compliance evidence packages.

---

## Table of Contents

1. [Getting Started](#1-getting-started)
2. [Building Evidence Packages](#2-building-evidence-packages)
3. [Validating Against Regulations](#3-validating-against-regulations)
4. [Working with the CLI](#4-working-with-the-cli)
5. [Advanced Features](#5-advanced-features)
6. [Error Codes Reference](#6-error-codes-reference)
7. [v1.1 Agent-Reliability Record Types](#7-v11-agent-reliability-record-types)
8. [Reporting an AI Incident (EU Art. 73)](#8-reporting-an-ai-incident-eu-art-73)

---

## 1. Getting Started

### Installation

```bash
pip install acef
```

For development (includes test and lint dependencies):

```bash
pip install acef[dev]
```

### Your First Bundle

```python
import acef

# Create a package with producer information
pkg = acef.Package(producer={"name": "my-compliance-tool", "version": "1.0"})

# Declare the AI system
system = pkg.add_subject(
    "ai_system",
    name="Loan Approval Model",
    risk_classification="high-risk",
    modalities=["tabular"],
    lifecycle_phase="deployment",
)

# Record a risk assessment
pkg.record(
    "risk_register",
    provisions=["article-9"],
    payload={
        "description": "Model bias against protected demographics",
        "likelihood": "medium",
        "severity": "high",
        "category": "fairness",
    },
    obligation_role="provider",
    entity_refs={"subject_refs": [system.id]},
)

# Export
pkg.export("loan-model-evidence.acef/")
print(f"Bundle created: {pkg.metadata.package_id}")
```

---

## 2. Building Evidence Packages

### Defining Subjects

Every ACEF package documents one or more **subjects** -- the AI systems or models under scrutiny. Use `ai_system` for deployed applications and `ai_model` for standalone models.

```python
import acef

pkg = acef.Package(producer={"name": "acme-tool", "version": "2.0"})

# A deployed AI system (EU AI Act Art. 6 scope)
system = pkg.add_subject(
    "ai_system",
    name="Acme RAG Assistant",
    version="2.1.0",
    provider="Acme AI Corp",
    risk_classification="high-risk",
    modalities=["text"],
    lifecycle_phase="deployment",
    lifecycle_timeline=[
        {"phase": "development", "start_date": "2025-01-15", "end_date": "2025-11-01"},
        {"phase": "testing", "start_date": "2025-11-01", "end_date": "2026-01-15"},
        {"phase": "deployment", "start_date": "2026-01-15"},
    ],
)

# A standalone GPAI model (EU AI Act Art. 53 scope)
model = pkg.add_subject(
    "ai_model",
    name="Acme LLM v3",
    version="3.0.0",
    provider="Acme AI Corp",
    risk_classification="gpai",
    modalities=["text"],
)
```

**Risk classifications** (per EU AI Act):

| Value | Meaning |
|---|---|
| `high-risk` | High-risk AI system (Art. 6) |
| `gpai` | General-purpose AI model (Art. 53) |
| `gpai-systemic` | GPAI with systemic risk (Art. 55) |
| `limited-risk` | Limited-risk system (Art. 50) |
| `minimal-risk` | Minimal-risk system |

### Building the Entity Graph

Entities provide the structural context for evidence records. Define them once, reference them by URN from records.

```python
# Components -- subsystems of the AI system
retriever = pkg.add_component(
    "Vector Retriever",
    type="retriever",
    version="3.1.0",
    subject_refs=[system.id],
)

guardrail = pkg.add_component(
    "Safety Filter",
    type="guardrail",
    version="1.4.0",
    subject_refs=[system.id],
)

# Datasets -- training, validation, and test data
training_data = pkg.add_dataset(
    "Training Conversations",
    source_type="licensed",
    modality="text",
    size={"records": 1000000, "size_gb": 100},
    subject_refs=[model.id],
)

# Actors -- people and organizations involved
lead_engineer = pkg.add_actor(
    name="Jane Smith",
    role="provider",
    organization="Acme AI Corp",
)

auditor = pkg.add_actor(
    name="External Auditor",
    role="auditor",
    organization="TrustCert GmbH",
)

# Relationships -- entity graph edges
pkg.add_relationship(system.id, model.id, "wraps")
pkg.add_relationship(system.id, retriever.id, "calls")
pkg.add_relationship(model.id, training_data.id, "trains_on")
pkg.add_relationship(auditor.id, system.id, "oversees")
```

**Component types**: `model`, `retriever`, `guardrail`, `orchestrator`, `tool`, `database`, `api`

**Dataset source types**: `licensed`, `scraped`, `public_domain`, `synthetic`, `user_generated`

**Relationship types**: `wraps`, `calls`, `fine_tunes`, `deploys`, `trains_on`, `evaluates_with`, `oversees`

### Recording Evidence

Each evidence record has a common envelope plus a type-specific payload. The `record()` method accepts all envelope fields:

```python
# Risk identification (EU AI Act Art. 9)
pkg.record(
    "risk_register",
    provisions=["article-9"],
    payload={
        "description": "Hallucination risk in customer-facing responses",
        "likelihood": "medium",
        "severity": "high",
        "category": "safety",
        "assessment_method": "Expert panel review",
    },
    obligation_role="provider",
    entity_refs={"subject_refs": [system.id]},
    trust_level="peer-reviewed",
    lifecycle_phase="deployment",
    collector={"name": "risk-assessment-tool", "version": "1.2"},
)

# Risk treatment (EU AI Act Art. 9)
pkg.record(
    "risk_treatment",
    provisions=["article-9"],
    payload={
        "treatment_type": "mitigate",
        "description": "Safety filter blocks high-risk outputs",
        "implementation_status": "deployed",
        "effectiveness_score": 0.94,
    },
    obligation_role="provider",
    entity_refs={
        "subject_refs": [system.id],
        "component_refs": [guardrail.id],
    },
)

# Dataset documentation (EU AI Act Art. 10)
pkg.record(
    "dataset_card",
    provisions=["article-10"],
    payload={
        "name": "Training Conversations",
        "description": "Licensed customer support transcripts",
        "representativeness_assessment": "Covers 12 languages, 45 product categories",
        "known_limitations": "Under-represents languages with <1% market share",
    },
    obligation_role="provider",
    entity_refs={"dataset_refs": [training_data.id]},
)

# Data provenance (EU AI Act Art. 10, GPAI, US Copyright)
pkg.record(
    "data_provenance",
    provisions=["article-10"],
    payload={
        "acquisition_method": "licensed",
        "acquisition_date": "2025-09-01",
        "source_uri": "https://data-vendor.example.com/conversations-v3",
        "license_type": "commercial",
    },
    obligation_role="provider",
    entity_refs={"dataset_refs": [training_data.id]},
)

# Evaluation results (EU AI Act Art. 15)
pkg.record(
    "evaluation_report",
    provisions=["article-15"],
    payload={
        "methodology": "Automated benchmark suite",
        "results": {
            "accuracy": 0.95,
            "f1_score": 0.92,
            "hallucination_rate": 0.03,
        },
        "test_conditions": "Production-equivalent environment, 10k test cases",
    },
    obligation_role="provider",
    entity_refs={"subject_refs": [system.id]},
)

# Transparency marking (EU AI Act Art. 50)
pkg.record(
    "transparency_marking",
    provisions=["article-50.2"],
    payload={
        "modality": "text",
        "marking_scheme_id": "c2pa-content-credentials",
        "scheme_version": "2.3",
        "metadata_container": "xmp/c2pa-manifest-store",
        "watermark_applied": True,
    },
    obligation_role="provider",
    entity_refs={"subject_refs": [system.id]},
)

# Event log (EU AI Act Art. 12)
pkg.record(
    "event_log",
    provisions=["article-12"],
    payload={
        "event_type": "inference",
        "correlation_id": "req-12345",
        "inputs_commitment": {"hash_alg": "sha-256", "hash": "a1b2c3d4..."},
        "outputs_commitment": {"hash_alg": "sha-256", "hash": "e5f6a7b8..."},
    },
    obligation_role="provider",
    entity_refs={"subject_refs": [system.id]},
    retention={"min_retention_days": 180, "legal_basis": "eu-ai-act-2024:article-12"},
)

# Evidence gap (when evidence is not yet available)
pkg.record(
    "evidence_gap",
    provisions=["article-15"],
    payload={
        "missing_record_type": "evaluation_report",
        "reason": "testing_scheduled",
        "expected_completion_date": "2026-06-30",
        "remediation_plan": "Comprehensive robustness testing planned for Q2 2026",
    },
    entity_refs={"subject_refs": [system.id]},
)
```

### Declaring Regulatory Profiles

Profiles tell validators which regulation templates to evaluate:

```python
# EU AI Act -- specify applicable provisions
pkg.add_profile(
    "eu-ai-act-2024",
    provisions=["article-9", "article-10", "article-12", "article-15", "article-50.2"],
)

# NIST AI RMF -- all provisions
pkg.add_profile("nist-ai-rmf-1.0")

# China CAC labeling
pkg.add_profile(
    "china-cac-labeling-2025",
    provisions=["cac-explicit-label", "cac-implicit-metadata"],
)
```

If `provisions` is omitted, all provisions in the template are evaluated.

### Adding Attachments

Binary files (PDFs, images, CSVs) are stored in the `artifacts/` directory:

```python
# Read a PDF report
with open("eval-report-v3.pdf", "rb") as f:
    report_content = f.read()

# Add it to the package
pkg.add_attachment("eval-report-v3.pdf", report_content)

# Reference it from a record
pkg.record(
    "evaluation_report",
    provisions=["article-15"],
    payload={"methodology": "Third-party audit"},
    attachments=[{
        "path": "artifacts/eval-report-v3.pdf",
        "media_type": "application/pdf",
        "description": "Independent evaluation report by TrustCert GmbH",
    }],
)
```

### Setting Confidentiality and Access Policies

Different evidence may have different confidentiality levels:

```python
# Public evidence
pkg.record(
    "transparency_disclosure",
    confidentiality="public",
    payload={"description": "Published model card"},
)

# Regulator-only evidence (trade secrets)
pkg.record(
    "copyright_rights_reservation",
    confidentiality="regulator-only",
    access_policy={"roles": ["regulator", "auditor"], "organizations": ["EU AI Office"]},
    payload={
        "opt_out_method": "robots_txt",
        "removal_count": 42,
    },
)

# Hash-committed evidence (provably exists without disclosure)
pkg.record(
    "data_provenance",
    confidentiality="hash-committed",
    payload={"source": "Confidential data source"},
)
```

**Confidentiality levels**:

| Level | Meaning |
|---|---|
| `public` | Visible to all |
| `redacted` | Content replaced with summary |
| `hash-committed` | Payload replaced with SHA-256 hash commitment |
| `regulator-only` | Visible only to regulators and auditors |
| `under-nda` | Restricted by NDA terms |

### Package Chaining (Version History)

Create a chain of evidence packages for audit trails:

```python
import acef

# Create v2 chained to v1
pkg_v2 = acef.chain(
    "v1-evidence.acef/",
    producer={"name": "my-tool", "version": "1.0"},
)

# The prior_package_ref is automatically set to the v1 bundle digest
print(pkg_v2.metadata.prior_package_ref)
# => "sha256:a1b2c3d4..."

# Add updated evidence to v2
pkg_v2.add_subject("ai_system", name="My System", version="2.0.0")
pkg_v2.record("risk_register", payload={"description": "Updated risk assessment"})
pkg_v2.export("v2-evidence.acef/")
```

### Exporting

```python
# Export as a directory bundle
pkg.export("my-evidence.acef/")

# Export as a portable archive
pkg.export("my-evidence.acef.tar.gz")
```

---

## 3. Validating Against Regulations

### Basic Validation

```python
import acef

# Validate an exported bundle (structural checks only)
assessment = acef.validate("my-evidence.acef/")

# Validate against a specific regulation
assessment = acef.validate(
    "my-evidence.acef/",
    profiles=["eu-ai-act-2024"],
)

# Validate a Package object directly (without exporting first)
assessment = acef.validate(pkg, profiles=["eu-ai-act-2024"])

# Validate an archive
assessment = acef.validate("my-evidence.acef.tar.gz", profiles=["eu-ai-act-2024"])
```

### EU AI Act Validation Example

```python
import acef

pkg = acef.Package(producer={"name": "my-tool", "version": "1.0"})

system = pkg.add_subject(
    "ai_system",
    name="Credit Scoring Model",
    risk_classification="high-risk",
    modalities=["tabular"],
    lifecycle_phase="deployment",
)

pkg.add_profile("eu-ai-act-2024", provisions=["article-9", "article-10", "article-15"])

# Add evidence for Article 9
pkg.record("risk_register", provisions=["article-9"],
           payload={"description": "Bias risk", "likelihood": "high", "severity": "high"},
           obligation_role="provider", entity_refs={"subject_refs": [system.id]})
pkg.record("risk_treatment", provisions=["article-9"],
           payload={"treatment_type": "mitigate", "description": "Bias mitigation applied"},
           obligation_role="provider", entity_refs={"subject_refs": [system.id]})

# Add evidence for Article 10
ds = pkg.add_dataset("Training Data", source_type="licensed", modality="tabular",
                     subject_refs=[system.id])
pkg.record("dataset_card", provisions=["article-10"],
           payload={"name": "Training Data", "description": "Licensed financial records"},
           obligation_role="provider", entity_refs={"dataset_refs": [ds.id]})
pkg.record("data_provenance", provisions=["article-10"],
           payload={"acquisition_method": "licensed", "acquisition_date": "2025-06-01"},
           obligation_role="provider", entity_refs={"dataset_refs": [ds.id]})

# Add evidence for Article 15
pkg.record("evaluation_report", provisions=["article-15"],
           payload={"methodology": "benchmark", "results": {"accuracy": 0.97}},
           obligation_role="provider", entity_refs={"subject_refs": [system.id]})

# Validate
assessment = acef.validate(pkg, profiles=["eu-ai-act-2024"])
print(assessment.summary())

# Render a Markdown report
report = acef.render(assessment)
print(report)
```

### NIST AI RMF Validation Example

```python
import acef

pkg = acef.Package(producer={"name": "gov-tool", "version": "1.0"})
system = pkg.add_subject("ai_system", name="Document Classifier",
                         risk_classification="minimal-risk", modalities=["text"])

pkg.add_profile("nist-ai-rmf-1.0")

# GOVERN function evidence
pkg.record("governance_policy", provisions=["govern-1.1"],
           payload={"policy_type": "ai_governance", "title": "AI Governance Framework",
                    "approval_date": "2025-01-15"},
           entity_refs={"subject_refs": [system.id]})

# MAP function evidence
pkg.record("risk_register", provisions=["map-1.1"],
           payload={"description": "Operational risk assessment", "likelihood": "low", "severity": "low"},
           entity_refs={"subject_refs": [system.id]})

# MEASURE function evidence
pkg.record("evaluation_report", provisions=["measure-1.1"],
           payload={"methodology": "NIST TEVV framework", "results": {"accuracy": 0.99}},
           entity_refs={"subject_refs": [system.id]})

# MANAGE function evidence
pkg.record("risk_treatment", provisions=["manage-1.1"],
           payload={"treatment_type": "mitigate", "description": "Monitoring and alerting"},
           entity_refs={"subject_refs": [system.id]})

assessment = acef.validate(pkg, profiles=["nist-ai-rmf-1.0"])
print(assessment.summary())
```

### China CAC Validation Example

```python
import acef

pkg = acef.Package(producer={"name": "cn-tool", "version": "1.0"})
system = pkg.add_subject("ai_system", name="Content Generator",
                         risk_classification="limited-risk", modalities=["text", "image"])

pkg.add_profile("china-cac-labeling-2025")

# Explicit label evidence
pkg.record("transparency_marking", provisions=["cac-explicit-label"],
           payload={
               "modality": "text",
               "marking_scheme_id": "cn-cac-explicit-label-2025",
               "scheme_version": "1.0",
               "metadata_container": "text-superscript",
               "watermark_applied": False,
               "jurisdiction": "CN",
           },
           obligation_role="provider", entity_refs={"subject_refs": [system.id]})

# Implicit metadata evidence
pkg.record("transparency_marking", provisions=["cac-implicit-metadata"],
           payload={
               "modality": "text",
               "marking_scheme_id": "cn-cac-implicit-label-2025",
               "scheme_version": "1.0",
               "metadata_container": "file-header",
               "watermark_applied": False,
               "jurisdiction": "CN",
           },
           obligation_role="provider", entity_refs={"subject_refs": [system.id]})

assessment = acef.validate(pkg, profiles=["china-cac-labeling-2025"])
print(assessment.summary())
```

### Understanding Assessment Results

The `AssessmentBundle` object provides structured access to results:

```python
# Overall summary
print(assessment.summary())

# Provision-level results
for ps in assessment.provision_summary:
    print(f"{ps.provision_id}: {ps.provision_outcome.value} "
          f"(fails={ps.fail_count}, warnings={ps.warning_count})")

# Individual rule results
for result in assessment.results:
    if result.outcome.value == "failed":
        print(f"FAILED: {result.rule_id} [{result.rule_severity.value}] {result.message}")

# Structural errors (schema, integrity, reference issues)
for error in assessment.structural_errors:
    print(f"[{error['code']}] {error['severity']}: {error['message']}")

# Export assessment to file
acef.export_assessment(assessment, "assessment.acef-assessment.json")
```

### The 7-Step Provision Outcome Algorithm

Each provision gets a single outcome computed from its rule results:

1. If any **fail-severity** rule failed: `not-satisfied`
2. If any rule errored: `not-assessed`
3. If all rules were skipped: `skipped`
4. If an evidence gap exists (and no fail-severity failures): `gap-acknowledged`
5. If all fail-severity rules passed but some warnings failed: `partially-satisfied`
6. If all evaluated rules passed: `satisfied`
7. If no rules exist for the provision: `not-assessed`

---

## 4. Working with the CLI

The `acef` CLI is installed automatically with the package. Run `acef --help` for a full command list.

### `acef init` -- Scaffold a New Bundle

Creates a minimal valid bundle directory structure:

```bash
acef init my-system.acef/ \
  --producer-name "my-tool" \
  --producer-version "1.0.0" \
  --subject-name "My AI System" \
  --subject-type ai_system \
  --risk-classification high-risk
```

Output:
```
Created ACEF bundle at: my-system.acef/
Package ID: urn:acef:pkg:550e8400-e29b-41d4-a716-446655440000
```

### `acef validate` -- Run Validation

```bash
# Structural validation only
acef validate my-system.acef/

# Validate against a regulation
acef validate my-system.acef/ -p eu-ai-act-2024

# Multiple profiles
acef validate my-system.acef/ -p eu-ai-act-2024 -p nist-ai-rmf-1.0

# JSON output for CI/CD integration
acef validate my-system.acef/ -p eu-ai-act-2024 --format json

# Markdown report
acef validate my-system.acef/ -p eu-ai-act-2024 --format markdown

# Save assessment to file
acef validate my-system.acef/ -p eu-ai-act-2024 -o assessment.json
```

**Exit codes:**
- `0`: All provisions satisfied (or no profiles evaluated)
- `1`: At least one provision is `not-satisfied`
- `2`: Fatal structural error (invalid bundle)

### `acef inspect` -- Examine Bundle Contents

```bash
# Pretty-printed summary
acef inspect my-system.acef/

# JSON manifest dump
acef inspect my-system.acef/ --format json

# Works with archives too
acef inspect my-system.acef.tar.gz
```

### `acef doctor` -- Diagnose Issues

Runs a comprehensive health check on a bundle:

```bash
acef doctor my-system.acef/
```

Checks performed:
- Directory structure verification
- Manifest JSON validity
- Required metadata fields
- Content hash verification
- Merkle tree presence
- Record file parsing
- Signature discovery

### `acef export` -- Convert Between Formats

```bash
# Directory to archive
acef export my-system.acef/ output.acef.tar.gz

# Archive to directory
acef export input.acef.tar.gz output.acef/

# Export with signing
acef export my-system.acef/ signed.acef.tar.gz --sign private-key.pem
```

### `acef record` -- Add Records from Command Line

```bash
# Inline JSON payload
acef record my-system.acef/ \
  --type risk_register \
  --provision article-9 \
  --payload '{"description": "New risk", "likelihood": "high", "severity": "medium"}' \
  --role provider

# Payload from file
acef record my-system.acef/ \
  --type evaluation_report \
  --provision article-15 \
  --payload @eval-results.json \
  --role provider
```

### `acef scaffold` -- Generate Template Stubs

Shows what evidence a regulation requires:

```bash
acef scaffold eu-ai-act-2024
acef scaffold nist-ai-rmf-1.0
acef scaffold china-cac-labeling-2025
```

---

## 5. Advanced Features

### Signing Bundles

ACEF supports JWS detached signatures with RSA (RS256) and ECDSA (ES256) keys.

#### Generate Keys

```bash
# RSA 2048-bit key
openssl genrsa -out private-key.pem 2048
openssl rsa -in private-key.pem -pubout -out public-key.pem

# ECDSA P-256 key
openssl ecparam -genkey -name prime256v1 -out ec-private.pem
openssl ec -in ec-private.pem -pubout -out ec-public.pem
```

#### Sign via Python API

```python
import acef

# Mark for signing during export
pkg.sign("private-key.pem")
pkg.export("signed-bundle.acef/")

# Or sign an already-exported bundle
acef.sign("bundle.acef/", "private-key.pem", kid="provider-key")
```

#### Sign via CLI

```bash
acef export my-system.acef/ signed.acef.tar.gz --sign private-key.pem
```

#### Verify Signatures

```python
from pathlib import Path
from acef.signing import verify_detached_jws

# Read the signature and content-hashes.json
sig_path = Path("bundle.acef/signatures/provider-key.jws")
hashes_path = Path("bundle.acef/hashes/content-hashes.json")

jws = sig_path.read_text()
payload = hashes_path.read_bytes()

# Verify (public key auto-extracted from JWS header)
header = verify_detached_jws(jws, payload)
print(f"Algorithm: {header['alg']}")
```

### Redacting Sensitive Evidence

Replace payloads with SHA-256 hash commitments while preserving verifiability:

```python
import acef

# Create a package with sensitive evidence
pkg = acef.Package(producer={"name": "my-tool", "version": "1.0"})
pkg.add_subject("ai_system", name="My System")
rec = pkg.record(
    "copyright_rights_reservation",
    confidentiality="regulator-only",
    payload={"opt_out_method": "robots_txt", "removal_count": 42},
)

# Save the original payload for later verification
original_payload = rec.payload.copy()

# Create a redacted copy of the package
redacted = acef.redact(
    pkg,
    record_filter={"confidentiality_levels": ["regulator-only"]},
    access_policy={"roles": ["regulator"], "organizations": ["EU AI Office"]},
)

# The redacted record has a hash commitment instead of the payload
redacted_rec = redacted.records[0]
print(redacted_rec.confidentiality.value)  # "hash-committed"
print(redacted_rec.payload)          # {"_redacted": True, "_commitment": "sha256:..."}

# Later, verify the original payload matches the commitment
from acef.redaction import verify_redaction
assert verify_redaction(redacted_rec, original_payload)  # True
```

### Merging Evidence from Multiple Sources

Combine evidence from different teams or tools:

```python
import acef

# Package from the ML team
ml_pkg = acef.Package(producer={"name": "ml-pipeline", "version": "2.0"})
ml_pkg.add_subject("ai_model", name="Core LLM")
ml_pkg.record("evaluation_report", payload={"methodology": "benchmark"})

# Package from the governance team
gov_pkg = acef.Package(producer={"name": "grc-tool", "version": "1.0"})
gov_pkg.add_subject("ai_system", name="Deployed System")
gov_pkg.record("governance_policy", payload={"policy_type": "ai_governance"})

# Merge
result = acef.merge([ml_pkg, gov_pkg], producer={"name": "acme-merger", "version": "1.0"})

if result.has_conflicts:
    for conflict in result.conflicts:
        print(f"Conflict: {conflict.message}")

merged_pkg = result.package
print(f"Merged: {len(merged_pkg.subjects)} subjects, {len(merged_pkg.records)} records")
```

**Conflict strategies:**

| Strategy | Behavior |
|---|---|
| `keep_latest` | When duplicate records are found, keep the one with the latest timestamp (default) |
| `keep_all` | Keep all records, even if duplicated |
| `fail` | Raise `ACEFMergeError` on any conflict |

### Rendering Compliance Reports

```python
import acef

assessment = acef.validate("bundle.acef/", profiles=["eu-ai-act-2024"])

# Markdown report (suitable for documents and wikis)
markdown = acef.render(assessment)
with open("compliance-report.md", "w") as f:
    f.write(markdown)

# Console summary (suitable for terminal output)
from acef.render import render_console
console_output = render_console(assessment)
print(console_output)
```

---

## 6. Error Codes Reference

ACEF defines a structured error taxonomy with unique codes, severities, and categories. Errors are collected within each validation phase before reporting.

### Schema Errors (ACEF-001 to ACEF-004)

| Code | Severity | Description |
|---|---|---|
| ACEF-001 | Fatal | Incompatible module versions in versioning block |
| ACEF-002 | Fatal | Manifest fails JSON Schema validation |
| ACEF-003 | Error | Unknown record_type -- no schema in registry |
| ACEF-004 | Fatal | Record payload fails record-type JSON Schema validation |

### Integrity Errors (ACEF-010 to ACEF-014)

| Code | Severity | Description |
|---|---|---|
| ACEF-010 | Fatal | File hash mismatch |
| ACEF-011 | Fatal | Merkle root mismatch |
| ACEF-012 | Fatal | Invalid or expired signature |
| ACEF-013 | Fatal | Unsupported JWS algorithm (only RS256 and ES256 allowed) |
| ACEF-014 | Fatal | Hash index completeness failure (file missing from or extra in content-hashes.json) |

### Reference Errors (ACEF-020 to ACEF-027)

| Code | Severity | Description |
|---|---|---|
| ACEF-020 | Error | Dangling entity_refs -- URN references nonexistent entity |
| ACEF-021 | Error | Duplicate URNs within the package |
| ACEF-022 | Error | record_files entry references nonexistent file |
| ACEF-023 | Error | Attachment path references file not in artifacts/ |
| ACEF-025 | Error | Record count mismatch between manifest and actual JSONL |
| ACEF-026 | Error | Duplicate record_id within the package |
| ACEF-027 | Warning | Attachment hash does not match content-hashes.json entry |

### Profile Errors (ACEF-030 to ACEF-033)

| Code | Severity | Description |
|---|---|---|
| ACEF-030 | Error | Unknown profile_id -- no matching template |
| ACEF-031 | Error | Unknown template_version |
| ACEF-032 | Info | Provision not yet effective -- rules produce skipped outcome |
| ACEF-033 | Error | Incompatible module versions between bundle and template |

### Evaluation Errors (ACEF-040 to ACEF-045)

| Code | Severity | Description |
|---|---|---|
| ACEF-040 | Error | Required evidence type missing |
| ACEF-041 | Warning | Evidence freshness exceeded |
| ACEF-042 | Info | evidence_gap acknowledged for provision |
| ACEF-043 | Error | Invalid JSON Pointer in rule field parameter |
| ACEF-044 | Error | Duplicate rule_id in template |
| ACEF-045 | Error | Invalid ECMA-262 regex pattern in rule value |

### Format Errors (ACEF-050 to ACEF-053)

| Code | Severity | Description |
|---|---|---|
| ACEF-050 | Fatal | Malformed JSONL line |
| ACEF-051 | Fatal | JSON not canonicalized per RFC 8785 |
| ACEF-052 | Error | Path contains .. segments or non-UTF-8-NFC characters |
| ACEF-053 | Error | Vendor extension field affects conformance outcome |

### Merge Errors (ACEF-060)

| Code | Severity | Description |
|---|---|---|
| ACEF-060 | Warning | Conflicting records from multiple packages |

### Error Severity Levels

| Severity | Meaning |
|---|---|
| `fatal` | Package is structurally invalid; cannot proceed with validation |
| `error` | Evidence fails binding regulatory requirements |
| `warning` | Evidence fails voluntary or advisory requirements |
| `info` | Informational observation (not a failure) |

---

## 7. v1.1 Agent-Reliability Record Types

ACEF v0.4 introduces five new Evidence record types — each with a typed builder
on `acef.Package` — plus the Assessment-side `coverage_cell` field (constructed
via its Pydantic model, NOT a `Package` builder; see its subsection below). This
section provides one fully-worked example for each. Each example is
self-contained: copy it into a Python file, run with
the ACEF SDK installed, and the bundle constructs cleanly. The version-
gating semantics are described in
[`MIGRATION-v0.3-to-v0.4.md`](MIGRATION-v0.3-to-v0.4.md#version-gating-semantics);
in summary, you must set `core_version: 1.1.0` on the package's `Versioning`
to opt into v1.1 conditional-required enforcement.

The shared preamble below is referenced by every example below; it sets up
a v1.1-opted-in package with a single AI system subject and an authorizing
actor.

```python
from acef.package import Package
from acef.models.metadata import Versioning

pkg = Package(producer={"name": "acef-user-guide", "version": "1.0.0"})
# Opt into v1.1 conditional-required enforcement.
pkg._versioning = Versioning(core_version="1.1.0", profiles_version="1.0.0")

system = pkg.add_subject(
    "ai_system",
    name="Demo Assistant",
    risk_classification="high-risk",
    modalities=["text"],
    lifecycle_phase="deployment",
)
authorizer = pkg.add_actor(name="Acme Customer Admin", role="provider",
                           organization="Acme Corp")
```

### authorized_test_scope

Declares what testing is authorized against an AI system. Required when an
agent-reliability product exercises a third-party AI system; provides
authorized surfaces, identities, side-effect policy, sandbox boundary,
ownership proof, and an optional kill-switch reference.

```python
# (uses preamble above)
scope = pkg.authorize_test_scope(
    scope_id="urn:acef:scope:11111111-1111-1111-1111-111111111111",
    scope_version="1.0.0",
    subject_ref=system.subject_id,
    authorized_surfaces=[
        {
            "surface_type": "chat_endpoint",
            "surface_identifier": "https://api.demo.example.com/v1/chat",
            "authorization_level": "read_only",
        },
    ],
    authorized_identities=[
        {
            "identity_type": "test_account",
            "identity_ref": authorizer.actor_id,
            "scope_constraint": "sandbox-only",
        },
    ],
    side_effect_policy={
        "default_disposition": "default_deny",
        "explicit_allowlist": [],
        "explicit_denylist": ["external_writes", "billing_calls"],
    },
    sandbox_boundary={
        "ownership_ledger_ref": "urn:acef:rec:22222222-2222-2222-2222-222222222222",
        "preflight_method": "preflight_probe",
    },
    ownership_proof={
        "proof_method": "dns_txt",
        "proof_artifact_ref": "urn:acef:rec:33333333-3333-3333-3333-333333333333",
        "verified_at": "2026-05-27T00:00:00Z",
    },
    effective_from="2026-05-27T00:00:00Z",
    authorizing_actor_ref=authorizer.actor_id,
)
print(scope.payload["scope_id"])  # → urn:acef:scope:11111111-...
```

**Notes:**
- When any surface's `authorization_level` is
  `production_capable_owner_authorized`, `ownership_proof.proof_method` MUST
  be one of `dns_txt`, `well_known_file`, or `sso_assertion` (the three
  methods that prove genuine ownership; `github_oauth` and `http_header`
  prove account control but not system ownership).
- `kill_switch_ref` is REQUIRED whenever any surface is
  `production_capable_owner_authorized`.
- The builder enforces both rules BEFORE the record is appended; an invalid
  call raises `ValueError` and the bundle is unmodified.

### scope_boundary_event

A control-plane integrity event: a test attempted an action outside its
authorized scope. Distinct from `event_log` (routine) and `incident_report`
(post-market operational). When `hard_stop_triggered: true`, the event MUST
reference the `harness_attestation` that recorded the stop.

```python
# (uses preamble above)
event = pkg.record_scope_boundary_event(
    scope_ref="urn:acef:scope:11111111-1111-1111-1111-111111111111",
    attempted_action={
        "action_class": "external_write",
        "action_target": "https://prod.example.com/api/v1/users",
        "action_payload_digest": "sha256:" + "a" * 64,
    },
    authorized_scope_snapshot={
        "scope_id": "urn:acef:scope:11111111-1111-1111-1111-111111111111",
        "scope_version": "1.0.0",
    },
    classification="intentional_bypass_attempt",
    hard_stop_triggered=False,  # no stop required for this example
    detected_at="2026-05-27T01:00:00Z",
    detector={
        "detector_class": "side_effect_policy_check",
        "detector_id": "urn:acef:actor:44444444-4444-4444-4444-444444444444",
    },
)
print(event.payload["classification"])  # → intentional_bypass_attempt
```

**Notes:**
- When `hard_stop_triggered=True`, supply `hard_stop_attestation_ref`
  pointing to the `harness_attestation` record that signed off on the stop.
  The builder raises `ValueError` if the pairing is missing.
- `attempted_action.action_payload_digest` MUST match the regex
  `^sha256:[0-9a-f]{64}$`. The raw payload is NEVER embedded — only its
  digest, post-redaction.

### finding_record

A reproducible defect with evidence. Carries a normative `dedupe_key`
computed via the brief Q5 recipe so two findings with byte-equal reproduction
recipes collapse to the same key.

```python
import hashlib

# (uses preamble above)
content_hash = "sha256:" + hashlib.sha256(b"reproduction-steps-content").hexdigest()

finding = pkg.record_finding(
    class_="accuracy_degradation",
    subject_ref=system.subject_id,
    expected_behavior="Model returns factually correct historical dates.",
    reproduction_steps_ref_content_hash=content_hash,
    severity={
        "severity_level": "medium",
        "severity_rationale": "User-facing accuracy regression in known domain.",
    },
    reproduction={
        "expected_behavior": "Model returns factually correct historical dates.",
        "observed_behavior": "Model returned an incorrect year for a known event.",
        "reproduction_steps_ref": "artifacts/repro-2026-05-27.md",
        "evidence_commit_ref": content_hash,
    },
    attribution={
        "persona_ref": "urn:acef:actor:55555555-5555-5555-5555-555555555555",
        "scenario_ref": "urn:acef:rec:66666666-6666-6666-6666-666666666666",
        "scope_ref": "urn:acef:scope:11111111-1111-1111-1111-111111111111",
    },
    discovered_at="2026-05-27T02:00:00Z",
    discovered_in_run_ref="urn:acef:rec:77777777-7777-7777-7777-777777777777",
)
print(finding.payload["dedupe_key"])  # stable across SDK runs
```

**Notes:**
- `class_` is the Python parameter name because `class` is a reserved
  keyword. The JSON-side field name is `finding_class`; the recipe-side
  field name used to compute `dedupe_key` is `class`.
- The builder canonicalizes the recipe `{class, subject_ref,
  expected_behavior, reproduction_steps_ref_content_hash}` via RFC 8785
  (JCS) and computes SHA-256 over the canonical bytes. Two calls with
  identical input parameters produce byte-equal `dedupe_key` (verified by
  VAL-SDK-DETERMINISM-HASH-001).

### delivery_verdict

Records that evidence was shipped to a downstream system AND verified to
have arrived. The `verified_delivered` state requires a `read_back` block,
`read_back.digest_match: true`, byte-equal `read_back.read_back_digest ==
write_attempt.request_digest`, and a paired `harness_attestation_ref`.
Provider acknowledgment alone (HTTP 2xx) is NOT verified delivery.

```python
# (uses preamble above, and finding from the previous example)
request_digest = "sha256:" + "b" * 64
verdict = pkg.record_delivery_verdict(
    finding_ref=finding.payload["finding_id"],
    destination={
        "provider_class": "jira",
        "provider_instance_id": "jira.acme.example.com",
        "provider_object_id": "ACME-1234",
    },
    write_attempt={
        "attempted_at": "2026-05-27T03:00:00Z",
        "request_digest": request_digest,
        "response_status": 201,
        "response_digest": "sha256:" + "c" * 64,
    },
    read_back={
        "read_back_at": "2026-05-27T03:00:30Z",
        "read_back_digest": request_digest,   # MUST byte-equal request_digest
        "digest_match": True,
    },
    delivery_state="verified_delivered",
    harness_attestation_ref="urn:acef:rec:88888888-8888-8888-8888-888888888888",
)
print(verdict.payload["delivery_state"])  # → verified_delivered
```

**Notes:**
- The builder enforces TWO cross-field rules before append. Rule 1: when a
  `read_back` block is present, `read_back.read_back_digest` MUST byte-equal
  `write_attempt.request_digest` (otherwise emits ACEF-072 at validation;
  the builder raises immediately so the bundle never holds a
  self-inconsistent verdict). Rule 2: `delivery_state="verified_delivered"`
  requires all of `read_back` present, `digest_match: true`, and a non-empty
  `harness_attestation_ref` (otherwise emits ACEF-071 at validation; the
  builder raises immediately).
- For non-verified states (`drafted`, `dispatched`, `acknowledged`,
  `failed`, `drifted`), omit `read_back` and `harness_attestation_ref`.

### coverage_cell

An Assessment Bundle field, NOT a standalone record type. Lives inside
`acef-conventions/v1.1/assessment-bundle.schema.json` under the
`coverage_cells` optional array. ACEF v0.4 does not expose a `Package`
builder for it (because it does not belong in an Evidence Bundle); instead
callers construct it directly via the Pydantic model in
`acef.models.agent_reliability`, then attach it to an Assessment Bundle
via the assessment-builder API.

```python
from acef.models.agent_reliability import CoverageCellPayload, CoverageDimensions

cell = CoverageCellPayload(
    cell_id="urn:acef:cell:99999999-9999-9999-9999-999999999999",
    subject_ref=system.subject_id,
    dimensions=CoverageDimensions(
        scenario_class="factuality",
        surface_class="chat_endpoint",
        time_window_start="2026-05-20T00:00:00Z",
        time_window_end="2026-05-27T00:00:00Z",
    ),
    bound_evidence_refs=[finding.record_id],
    freshness_state="fresh",
    freshness_policy_ref="urn:acef:rec:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    # claim_language MUST NOT contain banned tokens (compliant, certified,
    # AI Act-approved, guaranteed) — banned tokens emit ACEF-079.
    claim_language="Coverage measured for factuality scenarios over the past 7 days.",
    coverage_outcome="covered",
)
print(cell.model_dump(mode="json", exclude_none=True)["coverage_outcome"])  # → covered
```

**Notes:**
- `freshness_state="fresh"` requires every URN in `bound_evidence_refs` to
  have a `timestamp` newer than `time_window_start - freshness_policy.max_age`.
  This is a validator-level rule consulting the bundle's record set, not a
  model-level invariant.
- The banned-token check is enforced by the validator (ACEF-079), not by
  the Pydantic model. A `claim_language` containing `"AI Act-compliant"`
  constructs cleanly but fails validation.
- The assessment-bundle builder API for attaching coverage_cell entries is
  outside the scope of this section; see
  `src/acef/assessment.py` for the assessment-side API.

### harness_attestation

A per-state-transition signed attestation. The most important new primitive:
it is the durable proof that a state transition was earned by evidence,
generalizing the bundle-level JWS already in `src/acef/signing.py` to
per-record granularity.

The `Package.attest(...)` builder constructs the attestation; the JWS
signature over the 9 normative fields is produced by
`acef.signing.sign_harness_attestation(...)`. In a production pipeline you
would compute the signature first and pass it into the builder; the example
below shows both the builder call (with a synthetic signature value) and
the real signature computation against a generated RSA key.

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from acef.signing import sign_harness_attestation, HARNESS_ATTESTATION_SIGNED_FIELDS

# (uses preamble above and finding from the finding_record example)

# 1) Build the payload (without the signature) so we can sign over the
#    9 normative fields enumerated by HARNESS_ATTESTATION_SIGNED_FIELDS.
attestation_payload = {
    "attestation_id": "urn:acef:rec:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
    "state_class": "finding",
    "state_transition": {
        "from_state": "open",
        "to_state": "reproduced",
        "transitioned_at": "2026-05-27T04:00:00Z",
    },
    "bound_evidence_refs": [finding.record_id],
    "verifier": {
        "verifier_id": "urn:acef:actor:cccccccc-cccc-cccc-cccc-cccccccccccc",
        "verifier_class": "contract_gate",
        "verifier_version": "1.0",
    },
    "claim": "finding.open.reproduced:reproduction-steps-verified",
    "fake_green_test_ref": "urn:acef:rec:dddddddd-dddd-dddd-dddd-dddddddddddd",
    "signed_at": "2026-05-27T04:00:00Z",
    "signer_kid": "kid-demo-001",
}

# 2) Compute the JWS detached signature over the 9 signed fields.
priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
jws = sign_harness_attestation(attestation_payload, private_key=priv,
                               signer_kid="kid-demo-001")

# 3) Append the harness_attestation via the builder.
attestation_record = pkg.attest(
    state_class="finding",
    state_transition=attestation_payload["state_transition"],
    bound_evidence_refs=attestation_payload["bound_evidence_refs"],
    verifier=attestation_payload["verifier"],
    claim=attestation_payload["claim"],
    fake_green_test_ref=attestation_payload["fake_green_test_ref"],
    attestation_signature={
        "alg": "RS256",
        "value": jws,
        "signed_fields": list(HARNESS_ATTESTATION_SIGNED_FIELDS),
    },
    signed_at=attestation_payload["signed_at"],
    signer_kid=attestation_payload["signer_kid"],
    attestation_id=attestation_payload["attestation_id"],
)
print(attestation_record.payload["state_class"])  # → finding
```

**Notes:**
- The builder enforces FOUR SDK-side pre-flight checks before append:
  (1) `state_class` MUST be one of the seven hard-coded values
  (`step`, `finding`, `coverage_cell`, `regression`, `delivery`, `badge`,
  `attestation`) — otherwise raises (mirrors validator ACEF-076).
  (2) `verifier.verifier_class` MUST NOT be `persona` or `llm` — those
  classes lack determinism and are rejected at load (VAL-LOAD-001/002).
  (3) `bound_evidence_refs` MUST be non-empty (VAL-SDK-005, mirrors
  validator ACEF-070).
  (4) `fake_green_test_ref` MUST be a non-empty string (VAL-SDK-006,
  mirrors validator ACEF-076).
- The JWS signs exactly the 9 fields enumerated by
  `acef.signing.HARNESS_ATTESTATION_SIGNED_FIELDS`:
  `attestation_id`, `state_class`, `state_transition`,
  `bound_evidence_refs`, `verifier`, `claim`, `fake_green_test_ref`,
  `signed_at`, `signer_kid`. Any other fields (added by future versions
  or vendors) are explicitly outside the signature envelope and MUST NOT
  be trusted by verifiers.
- The signature algorithm MUST be `RS256` (RSA-PKCS1-v1_5 over SHA-256)
  or `ES256` (ECDSA over P-256 + SHA-256). Other algorithms emit ACEF-013
  at validation.

---

## 8. Reporting an AI Incident (EU Art. 73)

ACEF RFC-0002 adds the v1.1 incident-reporting profile: a private
`incident_report` (the regulator-only Art. 73 filing surface) and its public
`incident_card` projection, a self-asserted `public_incident_id`, an
`ACEF-SEV:1.0` severity vector, and the Art. 73 reporting clock (death → 10
days; `3.49.b` or widespread → 2 days; otherwise 15 days — the shortest
applicable clock). The migration notes in
[`MIGRATION-v0.4-to-v1.1.md`](MIGRATION-v0.4-to-v1.1.md) cover every new field,
record type, and error code.

This section is a single copy-paste worked example that runs **mint → build →
sign → validate** end-to-end. Copy it into a Python file, run it with the ACEF
SDK installed, and it prints the minted id, the publishable challenge token, and
a clean incident outcome (no `ACEF-08x` diagnostics). The only entropy is the
minted id suffix; the validation verdict does not depend on it.

### Identifier honesty (read this first)

The `public_incident_id` (`AIIC-{ASSIGNER}-{year}-{suffix}`) is a **self-asserted
handle**, not a forgery-resistant credential. `mint_incident_id` stamps every
v1.1 id with `id_grade: self-asserted`. Offline validation checks only the id
*pattern* and the JWS signature *self-consistency* — it never attributes the id
to the assigner domain, so a card minted by anyone with a consistent signature
passes the offline class by design.

The optional online `verify_domain_control` check proves the registrant controls
the assigner domain **at check time** — and only when they have actually
published `minted.challenge_token` at `minted.dns_record_name` (DNS-01 TXT) or
`minted.well_known_url` (`.well-known`). It returns a tri-valued verdict
(`verified` / `unverified` / `reject`); a network timeout returns an explicit
`unverified`, never a silent pass. With the built-in defaults only the
`.well-known` HTTP channel runs against a live host — the default `dns_resolver`
cannot perform a TXT lookup (no stdlib TXT API) and signals cannot-complete, so
the DNS-01 channel requires you to pass a real `dns_resolver=`.

### Worked example: mint → build → sign → validate

```python
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from acef.domain_control import DomainControlVerdict, HttpResponse, verify_domain_control
from acef.package import Package, band, mint_incident_id
from acef.redaction import RedactionPolicy
from acef.validation.engine import validate_bundle

work = Path(tempfile.mkdtemp(prefix="acef-art73-"))

# 1. Generate a throwaway ES256 (P-256) signing key and write it as PEM.
key = ec.generate_private_key(ec.SECP256R1())
key_path = work / "signing-key.pem"
key_path.write_bytes(
    key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
)

# 2. Mint a self-asserted public_incident_id + its domain-control challenge token.
#    `mint_incident_id` returns everything needed in ONE call: the id (id_grade
#    "self-asserted", >=128-bit Crockford-base32 suffix), the public JWK, and the
#    DNS-01 / .well-known challenge token + the exact wire locations to publish it.
minted = mint_incident_id("openai.com", key, year=2026)
print("public_incident_id :", minted.public_incident_id)
print("id_grade           :", minted.id_grade)  # -> self-asserted
print("challenge_token    :", minted.challenge_token)
print("publish DNS TXT at :", minted.dns_record_name)
print("    or .well-known :", minted.well_known_url)

# 3a. Source-backed Art.73 path (the regulatory-filing critical path): a
#     confidential incident_report carrying card_source.eu_ai_act_facts. It
#     validates BEFORE any public card exists (a RESERVED id, no projection).
#     A confidential report is emitted `regulator-only`, so attach a
#     RedactionPolicy and the SDK auto-populates the X1/X2 redaction-envelope
#     fields the validator needs.
pkg = Package(
    producer={"name": "acef-art73-example", "version": "1.1.0"},
    redaction_policy=RedactionPolicy(version="1.0.0"),
)
pkg.add_subject(
    "ai_system",
    name="Demo Assistant",
    risk_classification="high-risk",
    modalities=["text"],
    lifecycle_phase="deployment",
)
harm_core = {
    "realization": "harm_event",
    "causality": {"entity": "ai", "intent": "unintentional", "timing": "post_deployment"},
    "harm_class": "physical_health",
}
pkg.report_incident(
    public_incident_id=minted.public_incident_id,
    harm_core=harm_core,
    incident_type="operational_failure",
    description="Confidential Art.73 serious-incident report.",
    awareness_date="2026-08-01T00:00:00Z",
    eu_ai_act_facts={
        "serious_incident_triggers": ["3.49.a"],
        "widespread": False,
        "death_involved": True,  # -> 10-day Art.73 clock
    },
)

# 4. Sign + export the confidential report bundle.
pkg.sign(str(key_path))
report_dir = work / "report.acef"
pkg.export(str(report_dir))

# 5. Validate against the Art.73 profile and confirm the incident surface is clean.
assessment = validate_bundle(report_dir, profiles=["eu-ai-act-art73-2026"])
codes = [e.get("code") for e in assessment.structural_errors]
incident_codes = [c for c in codes if isinstance(c, str) and c.startswith("ACEF-08")]
print("\nincident codes (ACEF-08x):", incident_codes or "none")
assert not incident_codes, f"unexpected incident diagnostics: {incident_codes}"
assert "ACEF-084" not in codes, "Art.73 clock mismatch (ACEF-084)"
print("source-backed Art.73 report: incident requirements satisfied (no ACEF-08x).")

# 3b. (Optional) the PUBLIC incident_card projection of the same incident.
card_pkg = Package(producer={"name": "acef-art73-example", "version": "1.1.0"})
card_pkg.add_subject(
    "ai_system",
    name="Demo Assistant",
    risk_classification="high-risk",
    modalities=["text"],
    lifecycle_phase="deployment",
)
sev_vector = "ACEF-SEV:1.0/HT:P/HG:H/RV:A/SC:U/BR:I"
print("coarse severity band:", band(sev_vector))  # band() projects the vector
card_pkg.incident_card(
    public_incident_id=minted.public_incident_id,
    harm_core=harm_core,
    severity_vector=sev_vector,
    awareness_date="2026-08-01T00:00:00Z",
    eu_ai_act_facts={
        "serious_incident_triggers": ["3.49.a"],
        "widespread": False,
        "death_involved": False,
    },
)
card_pkg.sign(str(key_path))
card_dir = work / "card.acef"
card_pkg.export(str(card_dir))
card_assessment = validate_bundle(card_dir, profiles=["eu-ai-act-art73-2026"])
card_codes = [e.get("code") for e in card_assessment.structural_errors]
card_incident_codes = [c for c in card_codes if isinstance(c, str) and c.startswith("ACEF-08")]
print("public card incident codes (ACEF-08x):", card_incident_codes or "none")
assert not card_incident_codes, f"unexpected card diagnostics: {card_incident_codes}"

# 6. (Optional, online) prove domain control AT CHECK TIME. The id is only a
#    SELF-ASSERTED handle offline; the verifier reaches `verified` ONLY when the
#    registrant actually publishes minted.challenge_token at minted.dns_record_name
#    (DNS-01 TXT) or serves it at minted.well_known_url (.well-known HTTP).
#
#    `verify_domain_control` evaluates BOTH channels. To keep this example fully
#    offline (NO live network), we inject BOTH dependencies:
#      * dns_resolver — a stub that returns the published challenge for the DNS-01
#        channel (this is the channel that yields `verified`);
#      * http_fetcher — a stub that returns an empty 404 so the .well-known channel
#        touches no network. Without this stub, verify_domain_control would call the
#        DEFAULT fetcher and make a REAL HTTPS GET to minted.well_known_url
#        (openai.com here). The 404 stub is ABSENT (no proof on that channel), so the
#        verdict stays `verified` via the DNS-01 channel.
#
#    NOTE: the DEFAULT dns_resolver CANNOT perform a real TXT lookup (the Python
#    stdlib has no TXT API) — it signals cannot-complete → `unverified`. Running the
#    DNS-01 channel against live DNS therefore REQUIRES passing a real dns_resolver
#    (e.g. a dnspython wrapper). The no-injected-resolver default path is
#    `.well-known` HTTP only.
def _dns_resolver(name: str) -> list[str]:
    if name == minted.dns_record_name:
        return [minted.challenge_token]
    return []


def _http_fetcher(url: str) -> HttpResponse:
    # Offline stub: no proof on the .well-known channel (404). Keeps the verdict
    # `verified` via the DNS-01 channel above while making zero network requests.
    return HttpResponse(status=404, content_type="", body="")


result = verify_domain_control(
    minted.public_incident_id,
    minted.jwk,
    dns_resolver=_dns_resolver,
    http_fetcher=_http_fetcher,
)
print("\ndomain-control verdict:", result.verdict.value)
assert result.verdict is DomainControlVerdict.VERIFIED

print("\nOK: mint -> build -> sign -> validate completed; incident requirements satisfied.")
```

Expected output (the id suffix differs on every run):

```text
public_incident_id : AIIC-OPENAI-2026-1DANY48VT5CKP3FWVFMFXE1MQ0
id_grade           : self-asserted
challenge_token    : acef-domain-control=OPENAI:BXRT3eM44rZScHSCyjSNEXqwsKs8vUETSx-BDJrKtyw
publish DNS TXT at : _acef-incident-challenge.openai.com
    or .well-known : https://openai.com/.well-known/acef-incident-challenge

incident codes (ACEF-08x): none
source-backed Art.73 report: incident requirements satisfied (no ACEF-08x).
coarse severity band: major
public card incident codes (ACEF-08x): none

domain-control verdict: verified

OK: mint -> build -> sign -> validate completed; incident requirements satisfied.
```

**Notes:**
- The example asserts on the **incident** surface (no `ACEF-08x`, no
  `ACEF-084`) — the requirements RFC-0002 introduces. It does **not** claim
  "zero structural errors": a vanilla SDK-built package's initial-creation
  `audit_trail[0].actor_ref` is empty and surfaces a pre-existing structural
  diagnostic (`ACEF-002` at `/audit_trail/0/actor_ref`) shared by the reference
  golden bundles. That diagnostic is orthogonal to the incident content and is
  filtered out of the assertions above; populating the audit trail with a
  concrete `actor_ref` removes it.
- `mint_incident_id` requires a domain whose registrable label round-trips
  through the default `LABEL → "<label>.com"` mapper (e.g. `openai.com`,
  `api.openai.com`). The v1.1 default mapper has no public-suffix list, so a
  multi-label public suffix (`co.uk`) or a non-`.com` eTLD (`.ai`) is rejected
  with a clear `ValueError` rather than emitting a wrong challenge location.
- The source-backed `report_incident(...)` path is the EU Art. 73
  regulatory-filing critical path: the confidential report validates from
  `card_source.eu_ai_act_facts` with a RESERVED id and **no** public card. The
  `incident_card(...)` projection is the separate publishable surface.
- To reach `verified` against a real domain you publish the printed
  `challenge_token` and run the check with the matching channel's dependency:
  - **`.well-known` HTTP** works with the defaults. Serve the `challenge_token` as
    `text/plain` at `minted.well_known_url` and call `verify_domain_control(...)`
    with NO injected `http_fetcher` — the default stdlib `urllib` fetcher performs
    the real HTTPS GET. (For safety it follows no redirect, requires HTTPS to a
    non-IP registrable-domain host, and reads a bounded body.)
  - **DNS-01 TXT** does **not** work with the defaults. The default `dns_resolver`
    CANNOT perform a TXT lookup (the Python stdlib has no TXT-record API), so it
    signals cannot-complete → `unverified`. To run the DNS-01 channel against live
    DNS you MUST pass a real `dns_resolver=` (e.g. a `dnspython` wrapper that
    returns the TXT values at `minted.dns_record_name`).
  Until a presented proof validates on at least one channel, the verdict is the
  honest `unverified` — never a silent pass.
