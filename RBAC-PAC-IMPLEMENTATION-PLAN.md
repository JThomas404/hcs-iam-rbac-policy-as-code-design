# RBAC and PAC Implementation Plan

## Current State

### RBAC

Implemented in dev:
- Creates three pipeline SPN-style local users:
  - `plan_spn`
  - `apply_spn`
  - `state_spn`
- Adds those users to the shared pipeline group.
- Is already wired into the dev pipeline as an early guardrail stage.

Current purpose of the RBAC SPN users:
- `plan_spn`: plan and read-oriented pipeline operations
- `apply_spn`: apply and write-oriented pipeline operations
- `state_spn`: remote state and backend access operations

### Policy as Code

Implemented in dev:
- Supports policy catalog and role mapping
- Supports role assignment to policy groups
- Supports local user catalog
- Supports two user onboarding patterns:
  - PAC-managed dedicated group plus policy assignment
  - existing built-in group membership by explicit group ID
- Exposes outputs showing effective user to group to policy bindings

### Pipeline

Implemented in dev:
- `rbac` stage
- `policy_as_code` stage
- dependency ordering so downstream stacks wait for guardrails

## Target Operating Model

### RBAC Responsibilities

`rbac/` remains responsible for:
- creation of pipeline local identities
- membership of those identities in the pipeline group
- future password rotation and SPN lifecycle management

`rbac/` does not own:
- business user onboarding
- application user onboarding
- custom role definitions
- policy group lifecycle
- business authorisation mappings

### PAC Responsibilities

`policy-as-code/` owns:
- custom role definitions and mappings
- PAC-managed groups
- imported built-in groups and imported built-in roles where required
- local user inventory and onboarding
- memberships
- group to role assignments
- policy and access intent documentation in code comments and descriptions
- future compliance validation

## Phases

### Phase 1: Stabilise Current Dev Baseline

Goals:
- keep current dev implementation consistent and deterministic
- remove sources of accidental drift or recreation

Tasks:
1. Keep `user_catalog` map keys stable and document key naming rules.
2. Import built-in groups and roles that are used repeatedly, starting with `VDC Admin`.
3. Standardise use of `existing_group_id` for built-in groups.
4. Confirm all dev PAC outputs are stable and human-readable.
5. Confirm 2 to 3 consecutive clean PAC runs in dev.

Deliverables:
- stable dev RBAC stage
- stable dev PAC stage
- stable imported references for built-in admin constructs

### Phase 2: Build Authoritative Inventory Model

Goals:
- make Terraform the authoritative inventory for existing HCS local users, groups, and assignments
- define a consistent source-of-truth schema

Tasks:
1. Expand Terraform input model to represent:
   - existing users
   - new users
   - existing groups by ID
   - PAC-managed groups
   - built-in admin groups
   - imported roles
   - imported memberships
   - imported assignments
   - managed versus imported versus lookup status
2. Add descriptive comments and descriptions for each group and role mapping.
3. Normalise current HCS exports into Terraform-ready inventory structures.
4. Decide resource-by-resource whether each object should be:
   - imported into state
   - managed directly
   - temporarily lookup-only

Deliverables:
- canonical inventory model in Terraform inputs
- user to group to role mapping clarity
- clear ownership per object

### Phase 3: Exporter and Inventory Snapshot Foundation

Goals:
- establish a repeatable, read-only JSON export of HCS identity and access state
- support compliance and onboarding using machine-readable snapshots

Tasks:
1. Create a read-only exporter script to run on the `<ECS Bastion>`.
2. Use existing HCS access key and secret context for authentication.
3. Export at minimum:
   - users
   - groups
   - memberships
   - roles
   - group-role assignments
   - access policies
4. Produce both raw and normalised JSON outputs.
5. Store timestamped exports for traceability.

Recommended output structure:
- `raw/users.json`
- `raw/groups.json`
- `raw/roles.json`
- `raw/memberships.json`
- `raw/group_role_assignments.json`
- `raw/access_policies.json`
- `normalised/inventory.json`
- `normalised/users_by_group.json`
- `normalised/groups_by_role.json`

Deliverables:
- reproducible exporter script
- initial normalised inventory snapshot

### Phase 4: Onboard Existing HCS Users and Groups into Terraform

Goals:
- represent the current real HCS user and group landscape in Terraform
- stop relying on ad hoc console-only knowledge

Tasks:
1. Import existing local HCS users into Terraform state where Terraform should own lifecycle.
2. Import existing built-in groups and built-in roles used by PAC.
3. Import or map existing custom groups and assignments.
4. Preserve console-only exceptions only where unavoidable and document them.
5. Validate that imported state matches normalised exporter output.

Deliverables:
- imported dev user inventory
- imported dev group inventory
- imported role and assignment references

### Phase 5: Replace Broad Drift Check with RBAC and PAC Compliance Stage

Goals:
- validate identity and authorisation correctness only
- avoid broad infra drift noise when the objective is IAM and access compliance

Tasks:
1. Remove the current broad multi-stack drift stage from `pipelines/0-dev.yml`.
2. Add a dedicated compliance stage that validates only RBAC and PAC concerns.
3. Validate the following in report-only mode first:
   - expected SPN users exist
   - expected PAC users exist
   - expected PAC groups exist
   - expected memberships exist
   - expected role assignments exist
   - expected imported built-in group memberships exist
4. Separate compliance mismatches from Terraform or backend execution errors.
5. Publish a readable compliance summary artifact.

Deliverables:
- report-only compliance stage
- mismatch summary output
- clear path to fail-on-mismatch later

### Phase 6: Move to Enforcement Mode

Goals:
- convert compliance from observation to control
- fail pipeline when inventory mismatches are real and agreed

Tasks:
1. Clean up all known inventory mismatches.
2. Enable fail-on-mismatch mode for high-confidence checks.
3. Define and document exception handling rules.
4. Add approval requirements for any policy or group changes with high blast radius.

Deliverables:
- fail-on-mismatch compliance mode
- controlled exception process

### Phase 7: Promote to Additional Environments

Goals:
- replicate the working dev model safely
- avoid environment-specific guesswork

Tasks:
1. Copy stack structure to next environment.
2. Populate environment-specific IDs and imported built-in groups.
3. Re-run exporter and normalised inventory process in that environment.
4. Start in report-only compliance mode.
5. Promote to enforcement only after clean baseline is confirmed.

Deliverables:
- repeatable environment rollout procedure
- reusable PAC and RBAC model beyond dev

## Source of Truth Model

### Terraform Owns
- pipeline SPN users
- PAC-managed local users
- PAC-managed custom groups
- PAC-managed group memberships
- PAC-managed group-role assignments
- imported built-in groups and built-in roles used by the model
- imported existing local users where lifecycle is intentionally brought under Terraform

### Terraform Validates
- expected built-in group memberships
- expected effective user to group to role mappings
- access-policy settings exported from HCS
