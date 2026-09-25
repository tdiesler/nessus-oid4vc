# Repository instructions

## Specification context

This project works on the basis of
https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

## Working agreement

### Collaboration and verification

- Discuss proposed changes before modifying files.
- Treat user suggestions as hypotheses to evaluate, not decisions to affirm
  automatically. Check them against the stated objective, current evidence,
  repository invariants, costs, risks, and plausible alternatives. If a
  suggestion is weak, unnecessary, internally inconsistent, or materially
  inferior to another approach, say so directly, explain why, and recommend
  the stronger option. When a suggestion is reasonable, state the supporting
  rationale and relevant tradeoffs rather than merely agreeing. Optimize for
  correctness and outcomes rather than consensus: respectful disagreement and
  proving either side wrong with evidence are welcome. Do not manufacture
  objections when the evidence supports the proposal.
- Ask the user to run relevant tests.
- Generally use the lowest reasoning effort appropriate to the task to obtain
  good value for the cost. If the active effort is insufficient for reliable
  analysis, implementation, or verification, flag that before proceeding and
  recommend the lowest higher effort that is appropriate.

### Git and commits

- Do not fetch, pull, or push unsolicited. Run these only when explicitly asked.
- Create commits only when explicitly requested. Use the configured user as the
  author and add a trailer in the exact form
  `Co-Authored-By: Claude <model id> <noreply@anthropic.com>`
  (for example, `Claude Opus 4.6`). Resolve both the exact
  model identifier and reasoning-effort suffix dynamically from the current
  session.
  Start commit subjects with a capital letter and include the relevant GitHub
  issue reference, for example `(#35)`. Include a commit body with bullet-point
  details summarizing material changes and relevant operational commands.

### Code conventions

- Reuse established variable names consistently when possible. In particular,
  name values implementing `Strategy` `strat` rather than `strategy`.
- Sort methods alphabetically unless logical grouping or lifecycle order is
  clearer for the specific code.

### Keycloak interaction

**CLI implementation** — the `oid4vc` CLI delegates to:

1. Keycloak Admin Client Java API (`keycloak-admin-client`) when the required
   functionality is available there (e.g., realm, client, user, key,
   client-scope management).
2. Direct Keycloak REST API calls (`httpPost`/`httpGet`) only for functionality
   not exposed by the admin client (e.g., OID4VCI credential endpoints, VC
   scope assignment).

All use cases must be completable end-to-end using the `oid4vc` CLI alone,
without requiring alternative tools.

**CLI naming convention** — when an `oid4vc` command mirrors or extends an
existing `kcadm.sh` command, inherit `kcadm` parameter and option names rather
than inventing new ones. This keeps the CLI familiar to Keycloak users and
avoids gratuitous divergence.

**Development and debugging** — preferred order for inspecting Keycloak state:

1. `oid4vc` CLI (`bin/oid4vc`)
2. `kcadm.sh` (Keycloak's built-in admin CLI)
3. Direct REST API calls (curl)

## Instruction currency

- `AGENTS.md` must describe the current repository state and working agreement.
- Before completing a change, inspect whether it makes information in
  `AGENTS.md` inaccurate or obsolete. If it does, update `AGENTS.md` in the same
  change and flag the update to the user.
- When `AGENTS.md` disagrees with current configuration, executable test
  fixtures, or implementation, flag the discrepancy immediately and correct
  `AGENTS.md` as part of the current work.
- Keep historical experiments, results, conclusions, and completed work in the
  associated GitHub issues. Do not duplicate them in `AGENTS.md`.
- Keep only durable rules, current invariants, tracking entry points, and
  startup-discovery instructions here. Obtain dynamic work-item status from
  GitHub.

## Keycloak source reference

A local Keycloak checkout at `../keycloak` is available for inspecting SPI
interfaces. Key locations for OID4VCI mapper work:

- Mapper base class: `services/src/main/java/org/keycloak/protocol/oid4vc/issuance/mappers/OID4VCMapper.java`
- Built-in mappers (same package): `OID4VCUserAttributeMapper`, `OID4VCStaticClaimMapper`, etc.
- Feature gate: `OID4VCEnvironmentProviderFactory` — requires `Profile.Feature.OID4VC_VCI`
- SPI registration: `META-INF/services/org.keycloak.protocol.ProtocolMapper`

## Session startup and sources of truth

- Record commit identities for experiments only when the commit is on `main`.
  Feature-branch commit identities are unstable because integration squashes
  them.
- Before reporting operational facts or estimating runtime, inspect the current
  configuration, relevant fixtures, and implementation rather than relying on
  earlier session context or completed experiment results.

## Project tracking

Project repository and issue tracker is `https://github.com/tdiesler/nessus-oid4vc`. 
Normal issue and milestone management for this repository is authorized; destructive repository, account,
release, or branch operations still require explicit approval.

Use milestones and issues to discover active work. Issue bodies and
comments are the canonical location for experiment definitions, commands,
stable `main` commit identities, effective configuration, time ranges, results,
conclusions, and follow-up decisions. Verify implementation claims against the
current checkout.

Do not add issue comments unsolicited. Prepare proposed comment text locally
for user review and post it only when explicitly requested or approved.