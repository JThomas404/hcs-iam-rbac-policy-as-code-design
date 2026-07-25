# IAM & Access Governance as Code: RBAC, Policy-as-Code and a No-ClickOps Migration Strategy

## Table of Contents

- [Overview](#overview)
- [Real-World Business Value](#real-world-business-value)
- [Prerequisites](#prerequisites)
- [Project Folder Structure](#project-folder-structure)
- [Tasks and Implementation Steps](#tasks-and-implementation-steps)
- [Core Implementation Breakdown](#core-implementation-breakdown)
  - [Guiding Principles and Threat Model](#guiding-principles-and-threat-model)
  - [Two-Stack Architecture: HCS IAM and Azure DevOps Permissions](#two-stack-architecture-hcs-iam-and-azure-devops-permissions)
  - [The Three-SPN Pipeline Identity Model](#the-three-spn-pipeline-identity-model)
  - [The Policy-as-Code Custom Role Catalogue](#the-policy-as-code-custom-role-catalogue)
  - [Naming Conventions as a Control](#naming-conventions-as-a-control)
  - [Pipeline Stages: Validate, Plan, Review, Apply](#pipeline-stages-validate-plan-review-apply)
  - [The No-ClickOps Migration Strategy](#the-no-clickops-migration-strategy)
- [Local Testing and Debugging](#local-testing-and-debugging)
- [IAM Role and Permissions](#iam-role-and-permissions)
- [Design Decisions and Highlights](#design-decisions-and-highlights)
- [Errors Encountered and Resolved](#errors-encountered-and-resolved)
- [Skills Demonstrated](#skills-demonstrated)
- [Conclusion](#conclusion)

---

## Overview

This repository documents the design and phased implementation of an identity, role-based access control (RBAC) and policy-as-code architecture for a private-cloud platform running on Huawei Cloud Stack (HCS), governed through Azure DevOps.

The work spans three related documents, each answering a different question:

- [`RBAC-PIPELINE-DESIGN.md`](https://github.com/JThomas404/hcs-iam-rbac-policy-as-code-design/blob/main/RBAC-PIPELINE-DESIGN.md) answers **what the target architecture is**: a two-stack Terraform design covering HCS-native IAM (users, groups, custom roles, role assignments) and Azure DevOps permissions, built around a least-privilege, separation-of-duties pipeline identity model, grounded in verified capabilities and gaps of the actual HCS Terraform provider rather than assumptions carried over from AWS or Azure.
- [`RBAC-PAC-IMPLEMENTATION-PLAN.md`](https://github.com/JThomas404/hcs-iam-rbac-policy-as-code-design/blob/main/RBAC-PAC-IMPLEMENTATION-PLAN.md) answers **where the implementation actually stands today**: a seven-phase plan tracking the current dev-environment baseline (three pipeline service accounts, a working policy-as-code catalogue) through to a compliance-enforcing, multi-environment rollout.
- [`NO-CLICKOPS-STRATEGY.md`](https://github.com/JThomas404/hcs-iam-rbac-policy-as-code-design/blob/main/NO-CLICKOPS-STRATEGY.md) answers **how console write access gets eliminated without locking anyone out**: a six-phase, resource-class-by-resource-class migration from today's mixed console/pipeline access model to a state where every infrastructure change is a reviewed, audited git commit.

The central engineering problem this work addresses is not "write some Terraform for IAM" — it is that identity and access control changes are the highest-blast-radius category of infrastructure change that exists: a mistake can lock out the very people and pipelines needed to fix the mistake. Every design decision in this repository is built around that constraint.

## Real-World Business Value

Before this work, infrastructure and access changes on the platform were made through a mix of console clicks and ad hoc pipeline runs, with a small number of individuals holding standing administrative credentials as the practical path to getting things done. That model has real, specific costs:

- **No audit trail for access changes.** A console-granted permission has no reviewer, no commit history, and no reversible record — only a person's memory of why it was granted.
- **Single points of failure in personnel.** Standing broad credentials held by one or two individuals mean platform continuity depends on those specific people being available.
- **No separation of duties.** The same identity that requests a change can often approve and apply it, which is both a security gap and, in a regulated banking environment, a control the business would be asked to evidence during an audit.
- **No way to detect drift.** A change made in the console silently diverges from what Terraform believes the infrastructure looks like, with no automated way to notice until something breaks.

This architecture is designed to close each of those gaps concretely: every access grant becomes a reviewed pull request with a named approver; the identity that plans a change is never the identity that applies it; a documented, tested break-glass procedure replaces informal standing access; and nightly drift detection turns "did someone change something in the console" from an unanswerable question into an automated, alerted one. The phased, resource-class-by-resource-class rollout in the no-clickops strategy exists specifically so that this transition happens without ever leaving an on-call engineer locked out mid-incident, which is the single biggest risk in any project of this kind.

## Prerequisites

Implementing this architecture assumes:

- An Azure DevOps project with branch protection enabled on the default branch, and the ability to configure CODEOWNERS and Environment-based manual approval gates.
- A private-cloud tenant on Huawei Cloud Stack (or an equivalent platform) with the Terraform provider for that platform installed and its actual resource coverage verified against the provider's changelog, rather than assumed from a public-cloud equivalent.
- An external identity provider (in this implementation, an existing corporate Active Directory) that will remain the system of record for human identity; this architecture consumes group names from it but never creates or modifies them.
- An object-storage-compatible Terraform state backend with versioning enabled.
- A small number of individuals with existing console administrative access, since every phase of this migration begins by delegating access away from standing human credentials and toward pipeline service accounts, which requires an initial human-performed bootstrap step.
- Executive or platform-lead sign-off on the design document itself before any Terraform is written — this architecture is explicitly structured so that implementation cannot begin until every open decision in the design document has been recorded and reviewed.

## Project Folder Structure

```
infra-live/
  0-vdc-guardrails/
    RBAC-PIPELINE-DESIGN.md                  # Target architecture and design decisions
    NO-CLICKOPS-STRATEGY.md                  # Phased console-write elimination plan
    RBAC-PAC-IMPLEMENTATION-PLAN.md          # Phase-by-phase tracking of actual progress against the design
    0-dev/
      rbac/                                  # Pipeline identity bootstrap — plan/apply/state service accounts
        0-main.tf
        1-outputs.tf
        2-variables.tf
        3-versions.tf
        4-providers.tf
        5-backend.tf
        dev.auto.tfvars
      policy-as-code/                        # Authorisation — roles, groups, users, memberships, assignments
        0-main.tf
        1-outputs.tf
        2-variables.tf
        3-versions.tf
        4-providers.tf
        5-backend.tf
        dba-drs-admin.json                   # Custom role policy — DRS, admin scope
        dba-ecs-readonly.json                # Custom role policy — ECS + EVS, read-only scope
        dba-monitoring-readonly.json         # Custom role policy — monitoring stack, read-only scope
        dba-obs-migration.json               # Custom role policy — OBS, migration-scoped access
        dba-rds-admin.json                   # Custom role policy — RDS, admin scope
        dba-vpc-readonly.json                # Custom role policy — VPC, read-only scope
        dev.auto.tfvars
        tools/
          export_hcs_rbac_pac_inventory.py   # Read-only exporter — raw HCS identity/access snapshot
          parse_hcs_rbac_pac_exports.py      # Normalises raw exports into the inventory model
      security-groups/                       # Network-layer access guardrails, managed alongside IAM
        0-main.tf
        1-outputs.tf
        2-variables.tf
        3-versions.tf
        4-providers.tf
        5-backend.tf
        dev.auto.tfvars
```

The dev implementation splits the original design's single `iam/` stack into two folders, `rbac/` and `policy-as-code/`, matching the ownership split recorded in the implementation plan: `rbac/` owns pipeline identity bootstrap, `policy-as-code/` owns authorisation. A `security-groups/` stack was added alongside them as a third guardrail.

## Tasks and Implementation Steps

1. **Establish the guiding principles before writing any Terraform.** Eight non-negotiable rules (least privilege by default, identity separate from authorisation, no standing production privilege, everything as code, separation of duties, auditability, fail-closed behaviour, and respect for the external identity provider's ownership boundary) were recorded first, and every subsequent design decision was checked against them.
2. **Verify actual Terraform provider capability rather than assuming parity with AWS or Azure.** Every resource referenced in the design was checked against the real HCS Terraform provider, surfacing several genuine, permanent click-ops gaps (identity-provider federation configuration, tenant-wide deny policies, MFA and password-policy enforcement, and audit-log configuration) that could not be wished away with more Terraform.
3. **Split the architecture into two independently governed stacks.** HCS-native IAM and Azure DevOps permissions use different providers, different state, and different blast radius, so they were deliberately kept as two stacks with two pipelines, specifically so a broken apply in one cannot lock an operator out of the pipeline that would fix it.
4. **Design a three-service-account pipeline identity model with a documented trade-off.** A plan identity, an apply identity, and a state identity were defined with distinct intended scopes, and the constraint imposed by the platform's existing convention of sharing one group per environment across all pipeline identities was recorded explicitly, along with the compensating controls adopted to hold that trade-off safely.
5. **Define naming conventions that encode security-relevant metadata.** Every group, user and role name encodes environment, purpose and identity type, so that whether an identity is human, a service account, or a break-glass account is visible from its name alone, and lint rules can enforce the distinction automatically.
6. **Design a four-stage pipeline enforcing separation of duties structurally.** Validate and plan run on every pull request under a read-only identity; a review gate requires an approver who is not the author; apply runs only on the default branch under a separate, more privileged identity, executing the exact plan artifact that was reviewed rather than a freshly regenerated one.
7. **Build an initial least-privilege role catalogue and require justification for every custom role.** Built-in platform roles are preferred by default, and a custom role is only introduced once a documented gap analysis shows the built-in role is insufficient, specifically to prevent the accumulation of unreviewed bespoke permissions over time.
8. **Author a separate, phased strategy for eliminating console write access.** Because stripping console access from every human on day one would remove the only working path for anyone whose workflow does not yet have a pipeline equivalent, the migration was deliberately sequenced: observe current console usage first, build a pipeline equivalent for every recurring workflow, only then restrict access, and always resource-class by resource-class rather than as a single cutover.
9. **Track real implementation progress against the design in a living plan.** A separate implementation-tracking document records what is actually running in dev today (three service accounts, a working policy-as-code catalogue, guardrail pipeline stages) against the seven phases still required to reach a compliance-enforcing, multi-environment rollout.
10. **Record every unresolved question as an explicit, named decision point.** Rather than letting ambiguity be implicitly resolved by whoever implements a section first, every open question (rotation cadence, approver lists, break-glass account ownership, naming prefix approval) is captured as a line item requiring a named answer before implementation of that section proceeds.

## Core Implementation Breakdown

### Guiding Principles and Threat Model

The architecture opens with eight guiding principles, each treated as a non-negotiable constraint rather than a preference: least privilege by default; identity (authentication) kept separate from authorisation; no standing administrative access in production; everything managed as code with console changes treated as drift; separation of duties between the identity that plans a change and the identity that applies it; full auditability and reversibility of every access grant; fail-closed behaviour when the pipeline cannot verify its own state; and strict respect for the boundary of the external identity provider, which this architecture consumes from but never writes to.

Those principles are then tested against an explicit threat model covering eight concrete threats, from a compromised pipeline credential escalating to administrative access, through a developer approving their own access-granting pull request, to a pipeline being able to modify its own permissions. Each threat is paired with a specific mitigation already reflected in the design, for example:

| Threat                                                                    | Mitigation                                                                                                                                             |
| ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| A developer authors and approves their own access-granting change         | Branch protection requiring a reviewer from a different team, enforced via CODEOWNERS on the IAM stack                                                 |
| The pipeline's apply identity modifies its own permissions                | The apply identity's custom role explicitly denies write actions targeting its own user or group, evaluated before any allow statement                 |
| A change is made directly in the console rather than through the pipeline | A nightly scheduled `terraform plan` detects any state drift with no corresponding code change and raises an alert rather than silently reconciling it |

### Two-Stack Architecture: HCS IAM and Azure DevOps Permissions

The architecture is deliberately split into two independently governed Terraform stacks rather than one combined stack, because HCS-native identity and Azure DevOps permissions use entirely different providers, different state backends, and carry different blast radius:

```
  External Active Directory (managed by the organisation's identity team)
  users + groups
             │ federation (identity-provider config = managed manually, see below)
             ▼
  HCS Tenant — managed end-to-end by this architecture
    Identity Provider (federation) │ Local users (service + break-glass) │ HCS-native groups
                                                    │
                                                    ▼
                              Custom policies & roles
                                          │
                                          ▼
                    Group → role → scope assignments (project / domain / enterprise-project)
             ▲
             │ Terraform apply
  Azure DevOps
    HCS IAM pipeline  ──▶ drives 0-dev/iam/
    ADO-permissions pipeline ──▶ drives 0-dev/ado-rbac/  (planned)
    Permissions on Azure DevOps itself = also managed as code
```

A misconfigured apply against the HCS IAM stack must never be able to lock an operator out of the Azure DevOps pipeline that would be needed to fix it, and vice versa — that single requirement is the reason the two stacks exist separately rather than as one.

One deliberate and explicitly documented limitation sits inside this design: verification against the actual HCS Terraform provider confirmed that identity-provider federation configuration (the SAML/OIDC metadata and claim-to-group mapping that lets externally managed users authenticate at all) has no corresponding Terraform resource. This is recorded as a permanent, not a temporary, click-ops gap — it is quarantined with named owners and audit logging rather than left as an open item awaiting a future provider release.

### The Three-SPN Pipeline Identity Model

Rather than a single pipeline credential with broad standing permissions, the design specifies three distinct service accounts, each with a narrower intended purpose:

| Service account | Purpose                                      | Intended permission                                                                                  |
| --------------- | -------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Plan identity   | Runs `terraform plan` on every pull request  | Read-only access to the dev project, plus read access to the Terraform state bucket                  |
| Apply identity  | Applies merged changes to dev IAM            | A custom role that explicitly denies modifying its own user or group, scoped to the dev project only |
| State identity  | Manages the Terraform state bucket lifecycle | Read/write access limited to the one state-bucket prefix in use                                      |

A trade-off in this model is documented rather than hidden: the platform's existing convention places every pipeline service account for an environment into a single shared group, because role bindings in this provider attach to groups rather than individual users. That means, in practice, separation between the three identities is enforced by pipeline configuration and code review rather than by the platform itself. The design records this explicitly as an accepted trade-off and pairs it with compensating controls: one Azure DevOps variable group per pipeline stage (never two credentials reachable from the same job), an environment-gated approval check in front of the apply identity's credentials, a lint rule that fails the pipeline if the apply credential is ever wired into a non-apply stage, and a defined credential rotation cadence.

### The Policy-as-Code Custom Role Catalogue

The design principle that a custom role is only introduced once a built-in platform role is proven insufficient is implemented, not just documented: the `policy-as-code/` stack currently maintains six persona-scoped custom role policies for the database administrator persona, each named by resource family and access level (`dba-rds-admin.json`, `dba-ecs-readonly.json`, `dba-vpc-readonly.json`, `dba-monitoring-readonly.json`, `dba-obs-migration.json`, `dba-drs-admin.json`) and version-controlled as standalone JSON documents alongside the Terraform that references them.

The read-only compute policy is a representative example of the least-privilege pattern applied throughout the catalogue — scoped to exactly the two resource families a database administrator needs to inspect, and to read-only verbs only:

```json
{
  "Version": "1.1",
  "Depends": [],
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["ecs:*:get*", "ecs:*:list*", "evs:*:get*", "evs:*:list*"]
    }
  ]
}
```

No `Allow` statement in this policy reaches beyond `get` and `list` verbs, and no resource family beyond compute (ECS) and its attached block storage (EVS) is referenced — a deliberately narrow grant rather than a convenient `ReadOnlyAccess` role covering the whole tenant. Naming every policy by persona, resource family and access level (`dba-<resource>-<level>.json`) keeps the catalogue self-documenting: a reviewer can tell what a policy grants from its filename alone, before opening the file.

Two supporting scripts under `policy-as-code/tools/` implement the read-only inventory exporter described in the implementation plan: `export_hcs_rbac_pac_inventory.py` pulls a raw snapshot of users, groups, memberships, roles and assignments directly from the platform, and `parse_hcs_rbac_pac_exports.py` normalises that raw export into the inventory model the compliance stage validates against. Producing both raw and normalised output, rather than normalising in place, keeps an unmodified audit copy of exactly what the platform returned alongside the derived, human-readable structure used for day-to-day validation.

In the dev pipeline, the `rbac` and `policy_as_code` stacks run as early guardrail stages ahead of every downstream stack, with dependency ordering ensuring nothing else deploys until they succeed — the same DAG-ordered execution model documented in the companion [reusable Terraform pipeline template repository](https://github.com/JThomas404/azure-devops-terraform-stages-pipeline).

### Naming Conventions as a Control

Every object this architecture creates encodes its environment, purpose and identity type directly in its name, specifically so that a reviewer can determine what an object is and whether it should exist without needing to open its Terraform definition:

```
abs-{env}-{domain}-{persona}-{role}

Examples:
abs-dev-dbaas-human-dbadmin        # federated — maps from an existing AD group
abs-dev-dbaas-human-readonly
abs-dev-dbaas-svc-pipeline-apply   # local service account, no AD mapping
abs-dev-dbaas-svc-app-rds-writer
```

The `human-`, `svc-` and `bg-` (break-glass) prefixes are load-bearing rather than cosmetic: a lint rule in the validate stage rejects any newly created local user that is not explicitly a service account or a break-glass account, since human users are required to authenticate through the external identity provider rather than through a locally managed credential.

### Pipeline Stages: Validate, Plan, Review, Apply

The pipeline enforces separation of duties structurally, not just procedurally, across four stages:

```
validate (every PR, plan identity) → plan (every PR, plan identity) → review gate (human approver) → apply (default branch only, apply identity)
```

The validate stage checks formatting, runs `terraform validate`, enforces the naming convention by regex, and rejects any role assignment scoped outside the intended environment. The plan stage posts a summary of the proposed change as a pull request comment and fails outright if the plan would destroy a group that still has active members, or if it detects drift with no corresponding code change. The review gate, in dev, requires one reviewer distinct from the author via branch protection and CODEOWNERS, implemented as two stacked required checks rather than a single generic rule — one making a review from the platform lead mandatory on every pull request, the second listing the wider engineering team as optional approvers — so the mandatory reviewer is never the pull request's own author. The design explicitly records that this must be strengthened further, with a manual approval gate and change-ticket reference, before any non-development environment is onboarded. The apply stage, restricted to the default branch, applies the exact plan artifact published by the plan stage rather than regenerating it, which closes the same drift-between-review-and-execution gap addressed in the companion Terraform infrastructure pipeline for this platform.

### The No-ClickOps Migration Strategy

The most distinctive piece of this architecture is the recognition that removing console write access is not a permissions change — it is a change-management problem with real operational risk if sequenced incorrectly. The migration strategy is deliberately kept as a separate document from the RBAC pipeline design, because it touches every existing human with console access, every workflow that currently depends on the console, and every emergency recovery path, and mixing that scope into the pipeline design would create an unsafe temptation to strip access before a working alternative exists.

The migration proceeds through six phases, moving from detection to enforcement, one resource class at a time:

| Phase              | Goal                                                                                        | Exit criteria                                                                    |
| ------------------ | ------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| Observe            | Establish what currently happens in the console, by identity and resource class             | A signed-off inventory with a named owner for every recurring console workflow   |
| Substitute         | Provide a pipeline or pull-request equivalent for every recurring console workflow          | Zero pilot users requesting console write in that resource class for a full week |
| Detect             | Make drift detection loud and accurate, in report-only mode, with no permission changes yet | Drift alerts are actionable and answered within an agreed response time          |
| Restrict           | Physically block console write for a resource class, once its pipeline equivalent is proven | Zero successful console writes in that class for two consecutive weeks           |
| IAM self-bootstrap | Handle the identity resource class last, since the pipeline itself manages identity         | A quarterly break-glass dry run succeeds                                         |
| Maintain           | Ongoing quarterly review of console-write attempts and break-glass testing                  | Sustained zero non-pipeline console writes                                       |

Resource classes are deliberately restricted in a specific, least-risk-first order — object storage first, then compute, then networking, then the managed database layer, with identity itself handled last and separately, precisely because the pipeline that would need to fix a broken identity configuration is itself governed by that same identity configuration. A single named break-glass account, excluded from pipeline management for exactly this reason, is preserved throughout as the documented recovery path if both the pipeline and the primary access model fail simultaneously.

## Local Testing and Debugging

Because this repository is currently a security architecture and a partially implemented dev baseline rather than a fully deployed system, validation activity to date has focused on structural and provider-capability verification rather than production traffic testing:

- **Provider capability verification.** Every Terraform resource referenced in the design was checked directly against the actual HCS Terraform provider version in use, rather than assumed from documentation for a different cloud platform. This is what surfaced the permanent click-ops gaps (identity-provider federation, tenant-wide deny policies, MFA and password-policy enforcement) recorded explicitly in the design rather than discovered later during implementation.
- **Dev baseline verification.** The three pipeline service accounts and the initial policy-as-code catalogue were confirmed running in the dev environment, including verifying two to three consecutive clean, no-diff Terraform runs, to establish a stable baseline before layering further phases on top of it.
- **Negative testing of the self-modification deny rule.** Before this rule is considered complete, the design requires a documented, deliberate attempt by the apply service account to modify its own permissions, with the expected and required outcome being an explicit denial.
- **Drift detection dry run.** The nightly drift-detection job is validated by deliberately introducing a manual console change, confirming the alert fires, and then reverting the change, rather than assuming the detection logic works from its configuration alone.
- **Break-glass dry run.** The design requires a documented, tested break-glass procedure before the first production-affecting apply, on the basis that an untested recovery procedure is not a recovery procedure.

## IAM Role and Permissions

This project's core subject matter is IAM design, so the permission model is described here in more depth than a typical "credentials used by this pipeline" section:

- **Three distinct pipeline identities with different intended scopes.** A read-only plan identity, a write-scoped apply identity, and a state-management identity, rather than one broad standing credential — see [The Three-SPN Pipeline Identity Model](#the-three-spn-pipeline-identity-model) above for the accepted trade-off and its compensating controls.
- **A working, version-controlled custom role catalogue, not just a design proposal.** Six persona-scoped JSON policy documents exist today, each scoped to a single resource family and a single access level (read-only or admin) — see [The Policy-as-Code Custom Role Catalogue](#the-policy-as-code-custom-role-catalogue) above for a concrete example and the reasoning behind the per-policy naming convention.
- **Explicit self-modification denial.** The apply identity's custom role policy explicitly denies actions that would modify its own user or group, or create new local users, evaluated as an explicit deny before any allow statement, which directly prevents a compromised or misconfigured pipeline credential from silently escalating its own access.
- **Built-in roles preferred over custom roles by default.** A custom role is only introduced once a documented gap analysis shows a built-in platform role is insufficient for the persona in question, specifically to prevent the slow accumulation of unreviewed bespoke permissions that is a common source of privilege creep.
- **Human identity kept structurally separate from service identity.** Human users authenticate exclusively through the external identity provider and are never created as local platform users; only service accounts and a single named break-glass account exist as local identities, and a lint rule enforces this distinction automatically.
- **Least-privilege scope arguments, not blanket tenant access.** Every role assignment is bound to the narrowest of three available scopes (a specific resource project, a tenant-wide domain, or an enterprise project) rather than defaulting to the broadest available scope.
- **Time-bound elevation considered for the apply identity.** The design records an optional pattern where the apply identity holds only a base read-only credential and assumes a more privileged, short-lived role only at apply time, closer in behaviour to temporary security tokens on other cloud platforms, and records the additional bootstrap complexity that pattern would introduce as an explicit, deliberate trade-off rather than an oversight.
- **Documented, permanent exceptions where the platform provides no Terraform-manageable control.** Multi-factor authentication enforcement, password policy, session timeout, and the audit-log service itself are all confirmed to be console-only configuration in this provider. Rather than pretending these will eventually become infrastructure-as-code, each is documented as a named, owned, permanent exception with compensating audit controls.

## Design Decisions and Highlights

| Decision                                                                                                                | Alternatives Considered                                             | Rationale                                                                                                                                                                                                                                                  |
| ----------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Two independently governed Terraform stacks (HCS IAM and Azure DevOps permissions)                                      | A single combined stack                                             | A broken apply in one stack must never be able to lock an operator out of the pipeline needed to fix the other                                                                                                                                             |
| Three pipeline service accounts (plan, apply, state)                                                                    | A single shared pipeline credential                                 | Separates read-only, write, and state-management concerns, even though the platform's shared-group convention means the separation is pipeline-enforced rather than platform-enforced — an accepted, documented trade-off with named compensating controls |
| Explicit self-modification deny rule on the apply identity                                                              | Trusting scope restriction alone to prevent self-escalation         | A scope restriction can be misconfigured; an explicit deny evaluated before any allow is a stronger, defence-in-depth guarantee against the pipeline escalating its own access                                                                             |
| Plan-artifact pattern reused from the companion infrastructure pipeline                                                 | Re-planning at apply time                                           | Guarantees the reviewed plan is the applied plan, consistent with the same integrity guarantee already adopted for infrastructure changes elsewhere in this platform                                                                                       |
| Built-in roles required by default; custom roles need a documented gap analysis                                         | Allowing custom roles freely where built-in roles seem close enough | Prevents the single most common source of privilege creep: unreviewed, bespoke permission sets that accumulate silently over time                                                                                                                          |
| No-clickops migration kept as a separate document from the RBAC pipeline design                                         | Combining both into a single design document                        | Console-write elimination is a change-management and personnel-risk problem, not a permissions problem, and deserves its own phased, resource-class-scoped rollout rather than being rushed alongside the pipeline's initial build                         |
| Resource-class-by-resource-class restriction order (storage, then compute, then network, then data, then identity last) | Restricting all resource classes simultaneously                     | Contains the blast radius of a sequencing mistake to a single resource class, and defers the highest-risk class (identity) until the pipeline governing it has already proven itself on lower-risk classes                                                 |
| Identity provider federation explicitly documented as a permanent, not temporary, click-ops gap                         | Treating it as a "to be automated later" item                       | Verified directly against the provider's actual resource coverage; documenting it as permanent (with named owners and audit logging) is more honest and more actionable than an open item that never gets prioritised                                      |
| A single named, pipeline-excluded break-glass account                                                                   | Making break-glass another pipeline-managed identity                | If the pipeline itself is broken, a break-glass account that the pipeline also manages is not a recovery path — it is the same single point of failure restated                                                                                            |

## Errors Encountered and Resolved

This project is architecture and design work validated primarily through provider-capability checks and structured review rather than incident response, so the entries below reflect assumptions corrected during design rather than production failures:

| Issue                                                                                                                                                      | Root Cause                                                                                                                                                                       | Resolution                                                                                                                                                                                                                                                               |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Early drafts assumed the HCS provider would offer AWS-style workload identity federation for pipeline credentials                                          | The platform's actual Terraform provider capabilities were not verified before that assumption was written into the design                                                       | Verified directly against the provider; recorded explicitly that the platform issues long-lived access-key credentials regardless of any elevation pattern layered on top, and required a defined rotation cadence and audit logging as compensating controls instead    |
| Early drafts assumed a tenant-wide deny policy, equivalent to a cloud-provider service control policy, could enforce "no human can write to IAM" centrally | No such resource exists in the platform's Terraform provider                                                                                                                     | Substituted persona-level custom roles combined with drift detection as the enforcement mechanism, and recorded the absence of a top-down deny capability as an explicit design constraint rather than a temporary gap                                                   |
| Early drafts assumed identity-provider federation configuration would eventually be manageable as Terraform                                                | Verification against the provider showed no such resource exists, and this is a platform limitation rather than a missing feature likely to ship soon                            | Reclassified as a permanent click-ops gap with named owners and audit-log monitoring, rather than an open item that implicitly signals it will be automated later                                                                                                        |
| A design draft proposed stripping console write access from every resource class in a single coordinated change                                            | This would remove the only working access path for any workflow that did not yet have a proven pipeline equivalent, with high risk of locking out on-call engineers mid-incident | Replaced with the phased, resource-class-by-resource-class migration in the no-clickops strategy, with an explicit rule that a class does not progress to restriction until pilot users actively prefer the pipeline path over the console                               |
| An early version of the pipeline identity model proposed a single shared credential for plan, apply and state operations                                   | This offered no separation of duties and meant a single leaked credential carried the full combined permission set                                                               | Split into three distinct service accounts with narrower intended scopes, and where the platform's existing group convention still forces some permission sharing, documented that trade-off explicitly with named compensating controls rather than leaving it implicit |

## Skills Demonstrated

- **Security architecture and threat modelling**: authored a structured threat model covering pipeline credential compromise, self-approval, self-escalation, and identity-provider desynchronisation, with a named mitigation already reflected in the design for each threat.
- **IAM and least-privilege design**: designed a three-identity pipeline model with explicit self-modification denial, scope-minimised role assignments, and a documented, justified escalation path for a custom-role catalogue.
- **Infrastructure-as-code provider verification**: confirmed actual Terraform resource coverage against a real cloud provider rather than assuming feature parity with better-documented platforms, surfacing several genuine, permanent architectural constraints before implementation began.
- **Change-management and migration sequencing**: designed a six-phase, resource-class-scoped migration to eliminate console write access without a single-point cutover, explicitly prioritising continuity of on-call and incident-response access throughout.
- **Governance and audit-readiness thinking**: structured every access decision to be traceable to a git commit, a reviewed pull request, and a named approver, directly addressing the audit and separation-of-duties evidence expected in a regulated environment.
- **Technical writing for phased, high-risk change**: authored design documentation using an explicit "decision required" convention, forcing every ambiguous point to a recorded, owned answer before implementation could proceed on that section.
- **Pragmatic trade-off documentation**: where the platform's existing conventions constrained the ideal design (the shared pipeline-identity group, the permanent click-ops gaps), recorded the trade-off and its compensating controls explicitly rather than either forcing an unrealistic ideal or silently accepting a weaker design.

## Conclusion

This repository represents architecture and governance work rather than a single deployed artefact, and that distinction is deliberate: identity and access control is the one category of infrastructure where moving fast and fixing mistakes later is not an acceptable trade-off, because a mistake in this domain can remove the ability to fix itself. The value demonstrated here is in the discipline applied before implementation — verifying what the underlying platform can actually enforce rather than assuming it, designing pipeline identities around an explicit threat model rather than convenience, and sequencing a genuinely high-risk migration so that no phase can proceed until the previous one has proven the next step is safe. The dev-environment baseline already running today, and the phased plans that carry it toward full enforcement, are the concrete evidence that this architecture is not just a document but a system being built the way it was designed.
