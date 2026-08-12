# AGENTS.md

## Repository Overview

`mosip-onboarding` (also called **partner-onboarder**) is a shell-script and
Postman-collection based utility that onboards default MOSIP partners into a
running MOSIP environment. It is not an application with source code to
compile — it is an automation/config repo. It:

- Creates Keycloak partner users and uploads partner/root certificates for
  modules such as IDA, Print, ABIS, Resident, Mobile-ID, Digital Card,
  eSignet, Demo-OIDC, Resident-OIDC, and Mimoto keybinding.
- Runs its API calls through a Postman collection
  (`onboarding.postman_collection.json`) driven by `newman` (the Postman CLI
  runner).
- Generates HTML onboarding reports and optionally uploads them to a MinIO/S3
  bucket.
- Ships a Docker image and a Helm chart so onboarding can run as a
  Kubernetes Job.

See `README.md` for the human-facing overview and prerequisites.

## Technology Stack

- **Shell scripts** (`bash`/`sh`) — the actual onboarding logic
  (`default.sh`, `run-onboarding.sh`, `entrypoint.sh`, `upload-reports.sh`,
  `deploy/*.sh`, `certs/*.sh`).
- **Newman** (Postman CLI) with the `newman-reporter-htmlextra` reporter —
  executes `onboarding.postman_collection.json` against
  `onboarding.postman_environment.json`.
- **Docker** — base image `node:lts-alpine3.17`, with `newman`,
  `newman-reporter-htmlextra`, and `pem-jwk` installed globally via `npm`,
  plus `curl`, `openssl`, `jq`, the MinIO client (`mc`), and `kubectl`
  installed via `apk`/`curl` (see `Dockerfile`).
- **Helm** — chart at `helm/partner-onboarder` for running onboarding as a
  Kubernetes Job.
- **jq** — used throughout the shell scripts to patch the Postman
  environment JSON file in place.

There is no `pom.xml`, `package.json` (application-level), or Java/Maven
build in this repo — do not assume a JVM build process here.

## Build & Test Commands

Build the Docker image:

```shell
./docker-build.sh
```

This runs `docker build -t mosipdev/partner-onboarder:develop .`.

Run the image locally (example from `docker-run.sh` — replace the
placeholder value before running):

```shell
CERT_MANAGER_PASSWORD="your-mosip-deployment-client-password"
docker run --rm --name partner-onboarder -p 8080:8080 \
  -v "$PWD/reports:/home/mosip/reports" \
  -e URL=https://api-internal.soil.mosip.net \
  -e CERT_MANAGER_PASSWORD="$CERT_MANAGER_PASSWORD" \
  mosipdev/partner-onboarder:develop
```

Mounting `./reports` is required — `default.sh` writes reports to a
relative `./reports/...` path (i.e. under the Dockerfile's
`WORKDIR /home/${container_user}`, `mosip` by default), and `--rm`
deletes the container (and anything not mounted out of it) once it
exits.

Run onboarding directly with the shell script (outside Docker), after
exporting the required environment variables:

```shell
export URL="https://api-internal.example.mosip.net"
export CERT_MANAGER_PASSWORD="your-mosip-deployment-client-secret"
./default.sh
```

There is no automated unit/integration test suite in this repo. Validation
happens by running the onboarding flow against a real (or sandbox) MOSIP
environment and inspecting the generated HTML reports under `./reports`.

## Configuration

- `onboarding.properties` — template of partner/module properties (Keycloak
  URLs, admin/partner credentials, policy names, certificate subject fields,
  etc.). All values are left blank in the tracked file; they must be filled
  in per-environment before running `run-onboarding.sh`. **Never commit a
  filled-in copy of this file** — it holds Keycloak admin and partner
  passwords.
- `onboarding.postman_environment.json` — Postman environment consumed by
  `newman`; `default.sh`/`run-onboarding.sh` patch values into a **copy**
  of this file with `jq` at runtime (see `default.sh`'s `update_props`
  function). Do not commit a version of this file populated with real
  secrets.
- `deploy/values.yaml` — controls which modules are enabled for a Helm-chart
  onboarding run (`ida`, `print`, `abis`, `resident`, `mobileid`,
  `digitalcard`, `esignet`, `demo-oidc`, `resident-oidc`,
  `mimoto-keybinding`).
- `helm/partner-onboarder/values.yaml` — the chart's default values,
  overridden by `deploy/values.yaml` and by `--set` flags in
  `deploy/install.sh`.
- Docker environment variables consumed by `entrypoint.sh`/`default.sh`
  include `URL`, `CERT_MANAGER_PASSWORD`, `ENABLE_INSECURE`, `MODULE`,
  the `s3-*` variables (S3/MinIO host, region, key, secret, bucket) and
  `ns_mimoto` / `ns_esignet` (see `Dockerfile` `ENV` block).
- `deploy/copy_cm.sh` and `deploy/copy_secrets.sh` download a helper script
  (`copy_cm_func.sh`) from the **mutable `master` branch** of
  `mosip-infra` at runtime, with no checksum/signature verification, and
  execute it to copy Kubernetes ConfigMaps/Secrets (`s3`, `keycloak`,
  `keycloak-client-secrets`, `global`, `keycloak-env-vars`,
  `keycloak-host`) into the `onboarder` namespace. This is a real
  supply-chain risk, not just a reliability concern: a compromised or
  rewritten `mosip-infra` `master` would have its script executed
  against the target cluster's Secrets/ConfigMaps on the next run,
  unpinned and unverified. Do not hand-copy these values into files in
  this repo, and don't propagate the same fetch-and-exec-from-mutable-
  branch pattern into any new script.
- `certs/` holds sample/default root and client certificates per module
  (`abis`, `mpartner-default-mobile`, `print`); each `*-inline.pem` is the
  same certificate as its sibling `.pem` but flattened to a single line —
  per `certs/README.md`, if you change one you must regenerate the other
  (see `certs/convert.sh`).

## Project Structure Notes

```text
.
├── default.sh                     # main onboarding driver, calls newman per module/cert
├── run-onboarding.sh               # reads onboarding.properties, patches the postman env, invokes newman
├── entrypoint.sh                   # Docker ENTRYPOINT: runs default.sh then upload-reports.sh
├── upload-reports.sh               # optionally pushes ./reports to MinIO/S3 via `mc`
├── docker-build.sh / docker-run.sh # local Docker build/run helpers
├── Dockerfile                      # node:lts-alpine3.17 based image with newman, kubectl, mc, jq
├── onboarding.postman_collection.json   # Postman collection with all onboarding API calls
├── onboarding.postman_environment.json  # Postman environment (patched at runtime)
├── onboarding.properties           # blank template of per-environment/partner values
├── default-*-policy.json           # default auth/datashare/oidc/misp policy documents
├── certs/                          # default root/client certs per module + cert helper scripts
├── deploy/                         # cluster install helpers (install.sh, copy_cm.sh, copy_secrets.sh, values.yaml)
├── helm/partner-onboarder/         # Helm chart that runs onboarding as a Kubernetes Job
└── .github/workflows/              # CI: docker build, chart lint/publish, tag/release
```

This is a flat, single-purpose repo — there is no separate frontend/backend
split and no module that warrants its own `AGENTS.md`. `deploy/README.md`
and `helm/partner-onboarder/README.md` already document their own
directories; this root file is the single source of truth for agents.

## Development Workflow

1. Fork and clone the repo, add `upstream` pointing at
   `mosip/mosip-onboarding`, fetch `upstream/develop`, then create a
   feature branch from `upstream/develop` — not a stale local `develop`
   or your fork's `develop` (this repo develops on `develop`, not the
   reported default branch).
2. Make changes to the shell scripts, Postman collection, policy JSON
   files, or Helm chart as needed.
3. If you change `onboarding.postman_collection.json`, validate it opens
   correctly in Postman/Newman and that folder names referenced by
   `default.sh` (e.g. `authenticate-as-cert-manager`,
   `download-ida-certificate`, `upload-ca-certificate`) still exist — those
   folder names are called out explicitly by `--folder` flags in the shell
   scripts and a rename will silently break onboarding.
4. If you change the Helm chart under `helm/partner-onboarder/`, keep
   `Chart.yaml`'s version in sync with expectations of
   `.github/workflows/chart-lint-publish.yml`. It **lints** charts under
   `helm/**` on PRs; actual publishing to the `gh-pages` branch only
   happens via a manual `workflow_dispatch` run with
   `CHART_PUBLISH=YES` (or on a published release), not automatically
   on every PR or push.
5. Test locally by building the Docker image (`./docker-build.sh`) and
   running it against a sandbox MOSIP environment, or by exporting `URL`
   and `CERT_MANAGER_PASSWORD` and running `./default.sh` directly, then
   inspect the HTML reports under `./reports`.
6. Do not commit real credentials, filled-in `onboarding.properties`, or a
   populated `onboarding.postman_environment.json`.

## Pull Request Guidelines

- Target the `develop` branch (this repo's real integration branch — GitHub
  reports `master` as the default branch, but active development happens on
  `develop`).
- Keep commits scoped to one logical change (a module's onboarding flow,
  the Helm chart, the Docker image, etc.).
- CI (`.github/workflows/push-trigger.yml`) **builds** the
  `partner-onboarder` Docker image (via the shared `mosip/kattu`
  reusable workflow) on pushes to `develop`, `release*`, `1.*`,
  `master`, `MOSIP*` branches and on PR open/reopen/sync — make sure
  the Docker build (`docker-build.sh`/`Dockerfile`) still succeeds. Do
  not assume a PR also **publishes** the image; that reusable workflow
  is not documented in this repo, so don't state its publish behavior
  without checking `mosip/kattu` directly.
- If you touch anything under `helm/`, expect
  `.github/workflows/chart-lint-publish.yml` to **lint** the chart on
  your PR — it does not publish from a PR (see Development Workflow
  above).
- Reference the tracking issue number in the PR title/description when one
  exists.

## Repository-Specific Considerations

- Almost all "logic" here is bash string/JSON manipulation with `jq` against
  Postman JSON files — small formatting mistakes (missing `mv` of the temp
  file, mismatched `--env-var` names) will silently break a downstream
  `newman` call rather than fail loudly. Check that every `jq ... > tmp &&
  mv tmp <file>` pattern is preserved when editing `run-onboarding.sh` or
  `default.sh`.
- `deploy/copy_cm.sh` and `deploy/copy_secrets.sh` fetch
  `copy_cm_func.sh` from the mutable `master` branch of
  `mosip/mosip-infra` at runtime with no integrity check — see the
  Configuration section above for why this is a supply-chain risk, not
  just a reliability one.
- `deploy/install.sh` and `default.sh`/`run-onboarding.sh` are interactive
  (they use `read -p` prompts) — they are not meant to run unattended in
  CI; only the Docker image path (`entrypoint.sh` → `default.sh` →
  `upload-reports.sh`) is meant for non-interactive/automated execution.
- The `ENABLE_INSECURE` flag exists specifically for servers without a
  public domain/valid SSL certificate (self-signed cert scenarios); it is
  documented as **not** recommended outside development environments.
- `onboarding.postman_environment.json` and `onboarding.properties` are
  templates checked into the repo with blank secret fields — treat any
  filled-in version as a secret file and keep it out of commits (`.gitignore`
  already excludes the `tmp` and `reports` working directories that scripts
  generate at runtime).

## Agent rules

### Do

1. Verify any shell script or workflow behavior against the actual file in
   this repo before describing or relying on it — this repo has many
   near-duplicate `default-*.sh`/`upload_*` functions in `default.sh`; check
   the specific one you're touching.
2. Preserve the `jq ... > $(prop 'tmp_dir')/tmp.json && mv ...` pattern when
   editing property-patching logic in `run-onboarding.sh` or `default.sh`.
3. Target the `develop` branch for PRs and branch from `upstream/develop`.
4. Keep `onboarding.properties` and `onboarding.postman_environment.json`
   free of real credentials in any commit.
5. Update `certs/*-inline.pem` alongside its corresponding `certs/*.pem`
   whenever you change a certificate (per `certs/README.md`).
6. Run `./docker-build.sh` (an actual build, not just a static read of
   the `Dockerfile`) after changing any `*.sh` or `*.json` file copied
   into the image, since the `Dockerfile` copies scripts and JSON files
   explicitly (`COPY *.json`, `COPY *.sh`) — static inspection won't
   catch a missing copied file, a dependency-install failure, or an
   entrypoint error. Validate the actual onboarding flow too where
   practical, since it depends on the target environment.

### Do not

1. Do not assume this repo has a Java/Maven or Node application build —
   there isn't one; the Docker image only installs `newman` and CLI tools
   globally.
2. Do not rename or restructure Postman collection folders
   (`authenticate-as-cert-manager`, `download-ida-certificate`,
   `upload-ca-certificate`, `upload-leaf-certificate`,
   `upload-signed-leaf-certificate`, etc.) without updating every `--folder`
   reference to them in `default.sh`.
3. Do not commit filled-in secrets/credentials into `onboarding.properties`,
   `onboarding.postman_environment.json`, or any new config file.
4. Do not add automated tests or CI test steps that assume a live MOSIP
   environment is reachable — none of the current workflows do this, and
   onboarding scripts are interactive and environment-dependent by design.
5. Do not push branches to the `upstream` MOSIP remote — push to your own
   fork (`origin`) and open a PR from there.
