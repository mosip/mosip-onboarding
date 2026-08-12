# AGENTS.md — helm/

Parent guide: [`../AGENTS.md`](../AGENTS.md)

## Purpose

The `partner-onboarder` Helm chart — runs the Docker image
(`../Dockerfile`) as one Kubernetes Job per enabled onboarding module.
Installed by `../deploy/install.sh`.

## Layout

```text
helm/partner-onboarder/
├── Chart.yaml       # name "partner-onboarder", depends on Bitnami common
├── README.md          # generic chart-starter boilerplate — see caveat below
├── values.yaml           # chart defaults — see below for the module-list caveat
├── .helmignore
└── templates/               # not fully explored here; jobs.yaml and pvc.yaml both
                              # `range` over .Values.onboarding.modules (see below)
```

## `values.yaml` — the module-list override caveat

`values.yaml`'s own `onboarding.modules` list (12 entries, all
`enabled: false` by default, including `mimoto`, `mock-rp-oidc`,
`mimoto-oidc`, `signup-oidc`) uses **different module names** than
`../deploy/values.yaml`'s list (10 entries, including `mobileid` and
`demo-oidc` instead). This looks like a mismatch, but it isn't a bug in
practice: `../deploy/install.sh` always passes `-f values.yaml`
(deploy's file), and Helm's default `-f` merge behavior **replaces a
YAML list wholesale** rather than merging entries by name — so
`../deploy/values.yaml`'s module list is what actually gets used; this
chart's own `values.yaml` module list is effectively just a
placeholder/example that a plain `helm install` without `-f` would fall
back to. When changing which modules run, edit `../deploy/values.yaml`,
not this file — see `../deploy/AGENTS.md`.

`templates/jobs.yaml` and `templates/pvc.yaml` both
`range $module := $.Values.onboarding.modules`, creating one Job/PVC
entry per module in whichever list actually won the merge. If you add a
new module, add it to **both** `values.yaml` files' `onboarding.modules`
lists (with matching `name` values) to keep the chart's own defaults
usable standalone.

Other `values.yaml` sections: `image.repository`/`.tag`
(`mosipqa/partner-onboarder:develop`), an `os-shell` init-container
image (`mosipid/os-shell:12-debian-12-r46`), `onboarding.configmaps`
(S3 host/user-key/region defaults, `onboarder-namespace` mappings for
`ns_mimoto`/`ns_esignet`/`ns_signup`), `onboarding.secrets.s3.s3-user-secret`,
and `onboarding.volumes.reports` (an `nfs-csi` `ReadWriteMany` PVC
mounted at `/home/mosip/reports` — this is where the container's
`./reports` output actually lands in a cluster deployment, versus the
local `-v` bind mount used in the root `AGENTS.md`'s `docker run`
example).

## `README.md` caveat

The chart's `README.md` TL;DR (`helm repo add mosip
https://mosip.github.io` then `helm install my-release
mosip/partner-onboarder`) is unverified generic chart-starter
boilerplate — other MOSIP repos' actual install scripts use
`https://mosip.github.io/mosip-helm` as the repo URL, not the bare
`https://mosip.github.io`. Don't copy this README's `helm repo add`
command as-is without checking the real repo URL; `../deploy/install.sh`
doesn't run `helm repo add` at all (it assumes the `mosip` repo is
already added and just runs `helm repo update`).

## Agent rules

### Do

1. Edit `../deploy/values.yaml` to change which onboarding modules run
   — not this chart's own `values.yaml`, which only matters for a
   standalone `helm install` without `-f`.
2. Add a new module's `name`/`enabled` entry to both `values.yaml`
   files if you want the chart usable both standalone and via
   `../deploy/install.sh`.

### Do not

1. Do not assume `values.yaml`'s module list here is what actually runs
   when installed via `../deploy/install.sh` — that script's own
   `values.yaml` replaces it entirely.
2. Do not copy `README.md`'s `helm repo add https://mosip.github.io`
   command without verifying the actual repo URL first.
