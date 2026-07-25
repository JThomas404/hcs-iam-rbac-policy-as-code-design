# RBAC Pipeline — Design Overview (DEV)

## 1. Guiding principles

**P1 — Least privilege, by default.**
Every identity (human, service, pipeline) starts with zero permissions. Access
is granted only by explicit, reviewed change.

**P2 — Identity is not authorisation.**
Authentication (who you are, from AD) is separate from authorisation (what you
can do, from HCS IAM). The pipeline only manages the _mapping_ between the two.

**P3 — No standing privilege in production.**
Human admin access to prod is time-bound (JIT) and break-glass-only. No user
holds a permanent prod admin role. This is out of scope for dev, but the
design must not block it later.

**P4 — Everything as code, nothing in the console.**
Console/click-ops changes are drift and must be detected & rejected. The
pipeline is the only sanctioned write path to IAM.

**P5 — Separation of duties.**
The identity that _plans_ a change is not the same identity that _applies_ it.
The reviewer of a PR is not the author. The pipeline that grants roles cannot
modify its own role.

**P6 — Auditable & reversible.**
Every assignment traceable to: a git commit, a PR, an approver, a CAB/ticket
reference (later), and a Terraform state object. Every change reversible by
reverting the commit.

**P7 — Fail closed.**
If the pipeline can't authenticate, can't read state, or detects drift — it
_does not_ proceed. No silent fallbacks.

**P8 — Respect the identity boundary.**
Company AD is owned by the Company IAM team. This pipeline **never** creates,
renames, deletes, or modifies AD users or AD groups. It only **references**
AD group names that already exist. If a referenced AD group is missing, the
pipeline fails the plan — it does not attempt to create one.

---

## 2. Threat model (dev scope, abbreviated STRIDE)

| #   | Threat                                                 | Vector                                   | Mitigation in this design                                                             |
| --- | ------------------------------------------------------ | ---------------------------------------- | ------------------------------------------------------------------------------------- |
| T1  | Compromised pipeline SPN escalates to admin            | Stolen AK/SK in ADO variable group       | Scoped SPN, no `Tenant Administrator`, AK/SK rotation, secret in restricted var group |
| T2  | Developer self-grants prod access via PR               | Author = approver                        | Branch protection: at least one reviewer from a different team, CODEOWNERS on `rbac/` |
| T3  | Console drift (someone adds a user in the UI)          | Manual change outside pipeline           | `terraform plan` runs nightly on `main`; drift = pipeline failure + alert             |
| T4  | Group used for app workload also used for human access | Role confusion                           | Naming convention enforces `human-` vs `svc-` prefix and lint check                   |
| T5  | AD group deleted upstream → orphan role assignments    | AD sync lag / mistake                    | Pipeline treats missing group as `plan` failure, never silently removes               |
| T6  | Break-glass account abused                             | Permanent admin standing                 | Dev: documented account only. Prod (later): JIT + alerting on any use                 |
| T7  | Pipeline modifies its own permissions                  | Self-escalation                          | Pipeline SPN explicitly denied write on its own role bindings                         |
| T8  | Secret leaks via pipeline logs                         | `terraform plan` echoes sensitive output | `TF_LOG` off in CI, secrets marked `sensitive = true`, log scrubbing                  |

---

## 3. Architecture overview

```
  ┌──────────────────────────┐
  │  Company AD (EXTERNAL)   │   ← managed by Company IAM team, NOT us
  │  users + groups          │     We consume group names only (ticket-driven)
  └──────────┬───────────────┘
             │ federation (SAML/OIDC IdP config = managed by THIS pipeline)
             ▼
  ┌──────────────────────────────────────────────────────────────┐
  │  HCS Tenant — managed end-to-end by this pipeline            │
  │                                                              │
  │  ┌─────────────┐  ┌─────────────┐  ┌──────────────────────┐  │
  │  │ Identity    │  │ Local users │  │ HCS-native groups    │  │
  │  │ Provider    │  │ (svc + b/g) │  │ (e.g. mappings for   │  │
  │  │ (federation)│  │             │  │  federated AD users) │  │
  │  └─────────────┘  └─────────────┘  └──────────┬───────────┘  │
  │                                                │             │
  │                                                ▼             │
  │                              ┌────────────────────────────┐  │
  │                              │ Custom policies & roles    │  │
  │                              └──────────┬─────────────────┘  │
  │                                         ▼                    │
  │                              ┌────────────────────────────┐  │
  │                              │ Assignments at project /   │  │
  │                              │ resource scope (RDS/OBS/…) │  │
  │                              └────────────────────────────┘  │
  └──────────────────────────────────────────────────────────────┘
             ▲
             │ Terraform apply (HCS provider)
             │
  ┌──────────┴────────────────┐
  │  Azure DevOps             │
  │  ─ HCS RBAC pipeline      │  ← stack: 0-dev/iam/
  │  ─ ADO RBAC pipeline      │  ← stack: 0-dev/ado-rbac/
  │  ─ Permissions on ADO     │
  │    itself = also as code  │
  └───────────────────────────┘
```

**Stacks:**

1. `0-vdc-guardrails/0-dev/iam/` — **HCS IAM as code, using VDC primitives.** Manages:
   - HCS local users (`hcs_vdc_user`) — **only** service accounts (`auth_type = MACHINE_USER`, `access_mode = programmatic`) and break-glass (`LOCAL_AUTH`, `console`). Human staff are `auth_type = SAML_AUTH` and authenticate via Company AD federation — we declare the user-stub but the IdP itself is **not** manageable in this provider (see Pushback #7).
   - VDC groups (`hcs_vdc_group`) — the federation target & role-assignment subject
   - Group membership (`hcs_vdc_group_membership`) — for local users; federated users are added by IdP mapping rules (out of TF scope)
   - Custom roles (`hcs_vdc_role`) — JSON policy documents; type `AX` (global services) or `XA` (regional services)
   - Group → role → scope assignments (`hcs_vdc_group_role_assignment`) at one of three scopes: `domain_id` (tenant-wide), `project_id` (resource space, or `"all"`), or `enterprise_project_id`
   - Agencies (`hcs_vdc_agency`) — the apply pipeline assumes a more-privileged agency only at apply time
   - Resource spaces (`hcs_vdc_project`) if new spaces are needed
   - Enterprise projects (`hcs_enterprise_project`) for cross-cutting billing/access scope
2. `0-vdc-guardrails/0-dev/ado-rbac/` — **Azure DevOps permissions as code.**
   Manages project security, repo perms, branch policies, pipeline perms,
   variable groups, service connections, agent-pool perms. Uses the
   `microsoft/azuredevops` Terraform provider (separate from HCS).
3. _(removed)_ `0-vdc-guardrails/0-dev/active-directory/` — was going to
   create HCS groups mirroring AD. **No longer needed** because (a) AD is
   external and (b) HCS-native group resources live in stack 1 above. The
   empty folder should be **deleted** in Phase 1.

---

## 4. Naming conventions

**Principle:** Names encode environment, purpose, scope, and identity-type
so that a glance at any binding tells you what it is.
**AD group names are NOT ours to define.** Company IAM owns AD naming. We
only enforce naming on objects this pipeline creates: HCS-native groups,
HCS local users, custom policies/roles, and ADO security groups.

**HCS-native groups (created by this pipeline, mapped to AD groups via federation):**

```
abs-{env}-{domain}-{persona}-{role}
```

Examples:

- `abs-dev-dbaas-human-dbadmin` (federated → maps from an AD group)
- `abs-dev-dbaas-human-readonly`
- `abs-dev-dbaas-svc-pipeline-apply` (HCS local svc account, no AD mapping)
- `abs-dev-dbaas-svc-app-rds-writer`

**HCS local users (rare — service accts + break-glass only):**

```
svc-{purpose}-{env}      e.g. svc-rbac-apply-dev
bg-{env}                 e.g. bg-dev                  (break-glass)
```

**Required tokens:**

- `human-` vs `svc-` vs `bg-` — controls whether MFA & break-glass policies apply
- `{env}` matches repo folder (`dev`, `test`, `uat`, `nonprod`, `prod`)

**Roles (custom, when built-in insufficient):**

```
abs-role-{domain}-{verb}-{resource}
```

Example: `abs-role-dbaas-read-rds`, `abs-role-dbaas-rotate-secrets`
**Pushback #2:** Do **not** create a custom role until you have proven the
built-in HCS role is insufficient. Document the gap in the PR description.
Custom roles are the #1 source of accidental privilege creep.

---

## 5. Pipeline identity (least privilege)

You asked for a recommendation. Here it is.

**Use three distinct HCS service accounts**, not one. The HCS provider exposes
these as `hcs_vdc_user` (`auth_type = MACHINE_USER`, `access_mode = programmatic`),
each issued an AK/SK pair and bound to a dedicated VDC group via
`hcs_vdc_group_membership`:

| SPN                  | Purpose                                      | Permissions (via `hcs_vdc_group_role_assignment`)                                  | Where stored                                                         |
| -------------------- | -------------------------------------------- | ---------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| `svc-rbac-plan-dev`  | Read-only; runs `terraform plan` on every PR | Built-in `VDC ReadOnly` at `project_id = dev-project` + OBS read on tfstate bucket | ADO variable group `rbac-plan-dev` (or `hcs_csms_secret`)            |
| `svc-rbac-apply-dev` | Applies merged changes to dev IAM only       | Custom `hcs_vdc_role` with self-modification denied; scoped to dev project         | ADO variable group `rbac-apply-dev` (restricted; approver-list lock) |
| `svc-rbac-state-dev` | Manages tfstate bucket lifecycle             | OBS read/write on the one tfstate prefix only                                      | Used by both above; never by humans                                  |

### Decision D-5.1 — single shared group for SPNs

**Context.** The existing tenant convention is one pipeline group per
environment: `DBaaSHCS-{ENV}-ZA-pipeline-SVC`. All
pipeline SPNs — RBAC, infra, monitoring — sit in this single group.

**Decision.** Adopt the existing convention: all three RBAC SPNs (and the
infra/monitoring SPNs created in Phase 3) live in
`DBaaSHCS-NONPROD-ZA-pipeline-SVC` for dev/test/uat/nonprod.

**Trade-off accepted.** HCS role bindings attach to groups, not users.
Therefore all SPNs in this group share the union of the group's role
assignments. Separation-of-duties between plan / apply / state is
degraded from "HCS-enforced" to "pipeline-enforced". A bug in the YAML
that uses the wrong SPN's AK/SK in the wrong stage is not stopped by
HCS — it is stopped only by code review, lint, and variable-group
scoping in ADO. Equally, an attacker who exfiltrates _any_ one SPN's
AK/SK from a compromised CI runner gets the group's full permission
union, not just that SPN's nominal scope.

**Compensating controls (mandatory for this decision to hold).**

1. **One variable group per stage.** `rbac-plan-dev` linked only to plan
   jobs; `rbac-apply-dev` linked only to apply jobs; `rbac-state-dev`
   linked only to backend-init jobs. Never two in the same job context.
2. **ADO environment-gated apply.** The apply variable group is bound to
   an ADO environment (`hcs-dev-rbac-apply`) with a manual approver list.
   The apply SPN's AK/SK cannot reach an agent until the approver clicks.
3. **YAML lint rule.** A CI check rejects any pipeline file where the
   apply variable group is linked to a stage other than the named apply
   stage. Failing-closed by default.
4. **AK/SK rotation.** 90 days or less for dev / test / uat; 30 days or less for prod (see D-5.2).
   Rotation is scripted (HCS console + ADO variable-group update) and
   never bypassed.
5. **Drift detection runs daily.** Operation Logs are compared against
   Terraform state; any write attributed to plan-SPN or state-SPN raises
   an alert immediately (these SPNs should never appear as the operator
   of an IAM/VDC write).

### Decision D-5.2 — environment-gated apply SPN is NON-NEGOTIABLE for prod

**Context.** The compromised-CI-runner threat (` attacker exfiltrates AK/SK
→ apply-grade power`) is not closed by ADO approval gates: gates control
what the pipeline does, not what someone outside the pipeline does with
the credential. The HCS-side compensating control we still have available
is **network-conditional credentials** via `hcs_vdc_role` policy
`Condition: { "iam:SourceIp": [...] }`.

**Decision.** For prod, the apply-stage variable group MUST be bound to an
ADO environment AND the apply SPN's policy MUST include a `SourceIp`
restriction matching the prod ADO agent pool's egress NAT IP(s). Either
control alone is insufficient.

For dev / test / uat, the environment gate is required; the `SourceIp`
restriction is recommended but not blocking. This gives prod two
independent controls (gate + IP), and dev one (gate).

**Why two controls in prod.** The gate stops insider misuse (manual run of
apply without approval). The IP restriction stops external misuse
(stolen AK/SK from a non-agent network location). These are different
threat actors; one control does not subsume the other.

**Implementation milestone.** D-5.2 is part of the Phase 5 gate (prod
onboarding). It does NOT block Phase 1 (dev SPN provisioning).

---

### Where this stack lives — layered guardrails pattern

The RBAC pipeline lives at `0-vdc-guardrails/0-dev/rbac/`. This is
deliberate: the numbered directory prefix encodes execution-order priority.
The relationship between RBAC and consumer pipelines (infra, monitoring,
data) is a **gate**, not a **trigger**:

| Approach                                                                                                           | What it means                                                                             | Verdict                                   |
| ------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------- | ----------------------------------------- |
| Trigger (`RBAC succeeds → infra runs`)                                                                             | Every RBAC apply re-runs all consumers                                                    | Reject. Noisy and creates false coupling. |
| **Gate / precondition** (`infra cannot run unless RBAC's last-applied state is green AND its outputs are present`) | Each pipeline runs on its own schedule, but each consumer fails fast if RBAC is unhealthy | Adopt.                                    |
| **Output consumption** (`infra reads SPN IDs from RBAC's tfstate via terraform_remote_state`)                      | Infra never hard-codes SPN IDs; pulls from RBAC outputs                                   | Adopt.                                    |

**Contract between RBAC and consumers.** RBAC publishes (via its
`1-outputs.tf`):

- SPN names + user IDs (for reference / audit)
- Group ID (`DBaaSHCS-NONPROD-ZA-pipeline-SVC`)
- The list of ADO variable group names it manages

Consumers read these via `data "terraform_remote_state" "rbac"` if they
need the IDs, but the _credentials_ themselves flow via ADO variable
groups, not Terraform outputs.

**Bootstrap-day sequence** (one-time, when migrating off `<original-operator>`):

1. Manual apply of `0-vdc-guardrails/0-dev/rbac/` using bootstrap creds.
2. Bootstrap operator mints AK/SK per SPN via console.
3. AK/SK pairs written into `rbac-{plan,apply,state}-dev` + `infra-{plan,apply}-dev` + `monitoring-{plan,apply}-dev` variable groups.
4. RBAC pipeline runs in CI with `svc-rbac-apply-dev` (its own creds); confirms idempotent no-op.
5. Each consumer pipeline re-points from `dbaas-hcs-secrets` to its dedicated `*-apply-dev` group; runs; should be a Terraform no-op (same end-state, new identity).
6. `MOVDC_USERNAME` / `MOVDC_PASSWORD` / `HCS_ACCESS_KEY` / `HCS_SECRET_KEY` removed from `dbaas-hcs-secrets`. `<original-operator>`'s VDC write permissions stripped.

After bootstrap, the only sequencing relationship is **read-time**: a
consumer apply job checks RBAC's outputs at the start and fails fast if
missing or stale.
**P5 enforcement (concrete policy):** the `apply` SPN's custom role's JSON
policy explicitly **denies** (HCS policy language `"Effect": "Deny"`,
evaluated before `Allow`):

- `iam:users:update` and `iam:groups:update` targeting its own user/group ID
- `iam:permissions:grantRoleToGroup` where the target group is its own
- `iam:users:create` (no new IAM users — humans must federate)
- Any action outside the dev project / dev enterprise-project scope
  **Optional elevation pattern (assume-role):** Instead of giving
  `svc-rbac-apply-dev` standing write permission, declare an `hcs_vdc_agency`
  that grants write only when assumed. Configure the provider with:

```hcl
provider "hcs" {
  # … base credentials = read-only plan SPN
  assume_role {
    agency_name = "agency-rbac-apply-dev"
    domain_name = "<delegating-tenant>"
  }
}
```

This gives **short-lived** write tokens that expire automatically and are
audit-trail-distinct from the base AK/SK — closer to AWS STS / Azure
workload-identity behaviour. Cost: more moving parts in bootstrap.
**Pushback #3 (HCS reality check):** HCS does **not** offer OIDC workload
identity federation with Azure DevOps the way Azure does. The base credential
you store in ADO will be an AK/SK pair regardless of whether you layer
agency-assumption on top.

This means you **must**:

1. Rotate AK/SK on a defined schedule (recommended: 90 days or less for dev, 30 days or less for prod).
2. Store secrets in a _restricted_ variable group with approver-list lock —
   or use `hcs_csms_secret` as the source of truth and pull at job start.
3. Never echo `HCS_ACCESS_KEY` / `HCS_SECRET_KEY` in pipeline output (your
   repo memory already documents the `env:` mapping pattern — reuse it).
4. Log AK/SK use via CTS (Cloud Trace Service) so a leaked key shows
   anomalous source IPs. **CTS is not a Terraform resource in this provider**
   — enable it manually as a one-time bootstrap.

---

## 6. Repository layout

Slot into the existing structure — do not invent new top-level folders:

```
dbaas-infra-live/
  0-vdc-guardrails/
    RBAC-PIPELINE-DESIGN.md          ← this doc
    NO-CLICKOPS-STRATEGY.md          ← migration plan to eliminate console writes
    0-dev/
      iam/                            ← STACK 1: HCS IAM as code
        0-main.tf                     ← IdP, users (svc+bg), groups, policies, assignments
        1-outputs.tf
        2-variables.tf                ← group catalog, role catalog, AD-group references
        3-versions.tf
        4-providers.tf                ← huaweicloud provider
        5-backend.tf
        dev.auto.tfvars
      ado-rbac/                       ← STACK 2: Azure DevOps permissions as code
        0-main.tf                     ← project security, repo, branch, pipeline, varGroup, svcConn
        1-outputs.tf
        2-variables.tf
        3-versions.tf
        4-providers.tf                ← azuredevops provider
        5-backend.tf
        dev.auto.tfvars
      _legacy/                        ← (temp) holds the empty pre-existing YAMLs
        dev-dbaas-rbac-pipeline.yaml  ← repurpose → ADO pipeline that drives ado-rbac/
        dev-hcs-rbac-pipeline.yaml    ← repurpose → ADO pipeline that drives iam/
  pipelines/
    templates/
      rbac-stage.yml                  ← reusable plan + apply stage template
      ado-rbac-stage.yml              ← variant for ADO provider (different SPN, different state)
```

**Mapping of the two pre-existing YAMLs (resolves v0.1 open question):**

| File                           | Purpose                                                              | Drives stack      | Auth                       |
| ------------------------------ | -------------------------------------------------------------------- | ----------------- | -------------------------- |
| `dev-hcs-rbac-pipeline.yaml`   | HCS IAM lifecycle (users, groups, policies, federation, assignments) | `0-dev/iam/`      | HCS AK/SK                  |
| `dev-dbaas-rbac-pipeline.yaml` | Azure DevOps permissions for the dbaas-lz project                    | `0-dev/ado-rbac/` | ADO PAT / managed identity |

The two-pipeline split mirrors the two-stack split and keeps blast radius
contained: a broken HCS apply can't lock you out of the ADO pipeline that would
fix it, and vice-versa.

---

## 7. Pipeline stages

```
┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│  validate   │──▶│    plan     │──▶│   review    │──▶│    apply    │
│ (PR trigger)│   │ (PR trigger)│   │ (gate)      │   │ (main only) │
└─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘
```

**Stage 1 — validate** _(runs on every PR commit; plan SPN)_

- `terraform fmt -check`
- `terraform validate`
- Lint: enforce naming convention (regex over `dev.auto.tfvars`)
- Lint: reject any new `huaweicloud_identity_user` that is not `svc-*` or `bg-*` (no human local users — humans must federate via AD)
- Lint: reject any role assignment outside `0-dev/` scope
- Lint (P8): reject any attempt to _create_ an AD-side resource — we only reference

**Stage 2 — plan** _(runs on every PR commit; plan SPN)_

- `terraform plan -out=tfplan -lock-timeout=60s`
- Post plan summary as PR comment
- Fail if plan shows `destroy` on any group with active members (safety brake)
- Fail if drift detected (state diff with no code diff)

**Stage 3 — review gate**

- Dev (now): branch protection — 1 reviewer required, CODEOWNERS on `rbac/`
- Non-prod (later, pushback #1): + manual ADO approval, + CAB ticket field
- Prod (later): + dual approval from security AND platform team

**Stage 4 — apply** _(runs on `main` only; apply SPN)_

- `terraform apply tfplan` (use the **same** plan artifact from stage 2 — do
  not re-plan; that breaks separation between review-time and apply-time state)
- Post-apply: emit assignment diff to audit log sink
- Post-apply: tag git commit with `rbac-applied-{timestamp}`

**Agent pinning (applies to every stage above).** Every job in both
`rbac-stage.yml` and `ado-rbac-stage.yml` must pin to a single, known-good
agent in the pool via a `demands:` clause. The reason is the same one that
bit the infra pipelines: `terraform`, `tflint` and `tfsec` are only
guaranteed to be on `PATH` on the ECS bastion (`<ECS Bastion>`) under
the agent user's shell. A job that schedules onto any other agent in
`hcs-dbaas-nonprod-agents` fails at `terraform init` with exit code 127
(`command not found`). Mirror the pattern already used by
`pipelines/templates/terraform-stages.yml` and
`pipelines/0-dev-monitoring.yml`:

```yaml
pool:
  name: hcs-dbaas-nonprod-agents
  demands:
    - agent.name -equals <ECS Bastion>
```
