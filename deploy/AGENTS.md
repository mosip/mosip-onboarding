# AGENTS.md — deploy/

Parent guide: [`../AGENTS.md`](../AGENTS.md)

## Purpose

Interactive shell scripts and `values.yaml` that install/delete the
`mosip/partner-onboarder` Helm release (backed by `../helm/partner-onboarder/`)
into the `onboarder` namespace, running the Docker image's onboarding
flow as a Kubernetes Job.

## Layout

```text
deploy/
├── README.md         # overview, install steps, post-onboarding config steps
├── install.sh           # interactive first-time install — see below
├── copy_cm.sh              # copies ConfigMaps (global, keycloak-env-vars, keycloak-host) into onboarder
├── copy_secrets.sh           # copies Secrets (s3, keycloak, keycloak-client-secrets) into onboarder
├── delete.sh                    # interactive helm uninstall (prompts Y/n)
└── values.yaml                     # which onboarding modules are enabled — see below
```

## Script details

- **`install.sh`** — the most involved script in this repo. In order:
  prompts (Y/n) whether you have a public domain + valid SSL cert
  (**this exact prompt block is duplicated twice in a row** near the
  top of the file — a pre-existing repo quirk, not something to "fix"
  by deleting the second copy without checking it isn't relied on by
  something else); creates the `onboarder` namespace; asks for
  confirmation that `values.yaml` is set correctly; labels the
  namespace `istio-injection=disabled` (note: `disabled`, not
  `enabled` — differs from some other MOSIP repos, don't assume a
  repo-wide convention); deletes and recreates the `s3`/
  `onboarder-namespace` ConfigMaps via `copy_cm.sh`; runs
  `copy_secrets.sh`; interactively prompts for the S3 bucket
  name/region/URL (rejecting values with spaces or special
  characters); reads `s3-user-key` from the `s3` namespace's `s3`
  ConfigMap; `helm install`s `mosip/partner-onboarder` pinned to
  `CHART_VERSION=0.0.1-develop`; then prints a link to
  `mosip-infra`'s `partner-onboarder/README.md#configuration` for the
  manual post-onboarding mimoto-keybinding steps, built from the
  **current git branch name** (`git symbolic-ref --short HEAD`) — if
  you're on a branch that doesn't exist in `mosip-infra`, that link
  will 404; don't assume it always resolves.
  `set -e`/`set -o nounset`/`set -o pipefail` are only enabled at the
  very bottom of the file, right before `installing_onboarder` is
  called — namespace creation and all the interactive prompts run
  without those options active.
- **`copy_cm.sh`** / **`copy_secrets.sh`** — both independently
  download `copy_cm_func.sh` from the **mutable `master` branch** of
  `mosip/mosip-infra` at runtime with no integrity check, then use it
  to copy the ConfigMaps/Secrets listed above. See root `AGENTS.md`'s
  Configuration section for why this is a supply-chain risk, not just
  a reliability one — the same pattern is duplicated in both scripts
  rather than shared.
- **`delete.sh`** — interactive-only (no non-interactive/CI-safe flag);
  loops prompting "Are you sure you want to delete all
  partner-onboarder? (Y/n)" until `Y` is entered, then runs
  `helm -n onboarder delete partner-onboarder`.

## Configuration

`values.yaml` toggles which onboarding modules run
(`onboarding.modules[].{name,enabled}`): `ida`, `print`, `abis`,
`resident`, `mobileid` are enabled by default; `digitalcard`, `esignet`,
`demo-oidc`, `resident-oidc`, `mimoto-keybinding` are not (see
`../AGENTS.md`'s Configuration section for the full list). Edit this
file, not `../helm/partner-onboarder/values.yaml`, to control which
modules an install run actually onboards — `install.sh` passes
`-f values.yaml` explicitly.

## Agent rules

### Do

1. Read `README.md`'s post-onboarding "Configurational steps" section
   before assuming `install.sh` alone completes onboarding — the
   mimoto-keybinding partner step requires a manual follow-up outside
   this script.
2. Keep `copy_cm.sh` and `copy_secrets.sh`'s `copy_cm_func.sh` fetch
   logic in sync if you change one — they're independent copies of the
   same pattern, not a shared function.

### Do not

1. Do not assume the printed `mosip-infra` documentation link in
   `install.sh` always resolves — it's built from the current git
   branch name, which may not exist in that other repo.
2. Do not remove the duplicated Y/n prompt block in `install.sh`
   without confirming it's actually redundant — it may be a bug, but
   verify before "fixing" it as a drive-by change.
3. Do not add a non-interactive flag to `delete.sh` without discussing
   it — the confirmation loop is the only guard against an accidental
   delete.
