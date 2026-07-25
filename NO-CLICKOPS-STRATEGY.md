# No-ClickOps Enforcement Strategy

> **Companion to:** [`RBAC-PIPELINE-DESIGN.md`](RBAC-PIPELINE-DESIGN.md)
> **Goal:** Reach a state where **nothing** is created, modified, or deleted via the HCS console or ADO UI \u2014 every change is a reviewed, audited git commit applied by a pipeline SPN.

## Phased migration

### Phase A

**Goal:** Know what currently happens in the console.

- Enable HCS Cloud Trace Service (CTS) / equivalent audit logging across the dev tenant if not already on.
- Enable ADO audit log streaming.
- Export 30 days of write events from both surfaces. Categorise by:
  - Identity (human vs service vs unknown)
  - Resource class (IAM, VPC, ECS, RDS, OBS)
  - Operation (create / modify / delete)
- Produce a **console-write inventory**: who does what, how often, why.

---

### Phase B

**Goal:** For every recurring console workflow, provide a pipeline / PR equivalent.

For each resource class:
1. Confirm Terraform coverage exists for the resource class (e.g. `rds`, `obs-bucket`, `vpc` modules already exist in this repo).
2. Write a short "how to do X via PR" runbook for each common workflow surfaced in Phase A.
3. Iterate until pilot users prefer PR to console.

---

### Phase C

**Goal:** Drift detection is loud and accurate.

- Nightly `terraform plan -detailed-exitcode` per stack (already in RBAC design); extend to **all** infrastructure stacks not just IAM.
- Drift events:
  - Routed to a single dedicated channel
  - Tagged with the identity that made the change (from CTS log correlation)
  - Auto-create a work item with the diff attached
- Soft enforcement: drift = work item + email to the offending identity. **No permission changes yet.**

---

### Phase D

**Goal:** Hard enforcement console writes physically blocked.

For each resource class that has cleared Phase B:

1. Reduce the persona's HCS role from `*FullAccess` to `*ReadOnlyAccess` for that class.
2. Grant the pipeline apply SPN the previously-human write permissions (least-privilege scoped).
3. Verify: a human attempt to write via console returns 403.
4. Verify: the pipeline still applies normally.

**Order of classes** (least-risk first, most-risk last):
1. OBS buckets
2. ECS (compute is recreatable)
3. VPC / networking
4. RDS / data
5. IAM

---

### Phase E

**Approach:**
- Break-glass account retains IAM console write (this is its sole purpose).
- All other humans lose IAM console write.
- A documented manual runbook (printed + vaulted) describes how to recover
  if both pipeline AND break-glass fail (worst-case scenario).

---

### Phase F

- Quarterly review of console-write attempts (should be zero from non-pipeline identities; non-zero = investigate).
- Quarterly break-glass dry run.
- Annual review of this strategy doc.
