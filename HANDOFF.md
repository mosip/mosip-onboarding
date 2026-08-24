# MISP / mock-rp-oidc sandbox onboarding — handoff

Properties-driven partner onboarding (replaces the old hardcoded `default.sh` values) is
ready to test end-to-end on the sandbox. This doc is everything you need to pick it up.

## 1. Repos & branches

All three repos use branch **`moupdate`**, already pushed to Mahesh's forks:

| Repo | Branch | What it contains |
|---|---|---|
| [mosip-onboarding](https://github.com/Mahesh-Binayak/mosip-onboarding/tree/moupdate) | `moupdate` | Properties-file-driven onboarding logic, `default.sh`, Postman collection, Helm chart (`helm/partner-onboarder`) with the new `propertiesOverride` mechanism |
| [esignet](https://github.com/Mahesh-Binayak/esignet/tree/moupdate) | `moupdate` | `partner-onboarder/install.sh` + `values.yaml`, wired to install the MISP onboarder Job from the local chart above |
| [esignet-mock-services](https://github.com/Mahesh-Binayak/esignet-mock-services/tree/moupdate) | `moupdate` | Same, for the `mock-rp-oidc` onboarding flow |

Clone all three. Read access is enough to run this; ask Mahesh to add you as a
collaborator if you need push access too.

## 2. Docker image

The onboarder Job runs a custom image built from `mosip-onboarding`'s `moupdate` branch
(the published `mosipdev/partner-onboarder` image does NOT have these changes yet):

```
docker.io/rakshitharakshu/partner-onboarder:MOSIP-esignet-sandbox-test
```

Public image, no pull secret needed.

## 3. Important: set `ONBOARDER_CHART_DIR` yourself

`esignet/partner-onboarder/install.sh` and `esignet-mock-services/partner-onboarder/install.sh`
both install the Helm chart from a **local** `mosip-onboarding` checkout (not the published
chart repo, since the `propertiesOverride` feature isn't published there). The default path
they fall back to assumes a specific folder layout that's unlikely to match your machine.

**Before running either script, always export this explicitly:**

```bash
export ONBOARDER_CHART_DIR="/absolute/path/to/your/mosip-onboarding/helm/partner-onboarder"
```

## 4. Credentials — get these from Mahesh directly, NOT via this doc or git

- Sandbox kubeconfig file (points at the `rancher.mosip.net` cluster)
- Keycloak admin username/password for the sandbox that hosts auth/IDA/PMS ("released" sandbox)
- The PMS client secret (`mosip_pms_client_secret`) for that sandbox
- Confirm the PMS domain (e.g. `api-internal.<env>.mosip.net`) — some sandboxes split PMS onto
  its own subdomain (e.g. `pmp-*.mosip.net`); check before running.

## 5. Step-by-step

```bash
# 1. Point kubectl/helm at the sandbox
export KUBECONFIG=/path/to/sandbox-kubeconfig.yaml
kubectl cluster-info                 # confirm it connects
kubectl get ns esignet                # confirm the namespace exists
helm -n esignet list                  # confirm no esignet-misp-onboarder /
                                       # esignet-mock-rp-onboarder release already exists
                                       # (fail-fast design — a name collision aborts the run)

# 2. Resolve chart dependencies once
export ONBOARDER_CHART_DIR="/absolute/path/to/mosip-onboarding/helm/partner-onboarder"
helm dependency update "$ONBOARDER_CHART_DIR"

# 3. Run the MISP onboarder
cd esignet/partner-onboarder
sh install.sh
```

`install.sh` will prompt interactively:
- **"Do you have public domain & valid SSL?"** → answer based on the sandbox's actual setup.
- **"Do you have S3 details for storing Onboarder reports?"** → `n` is fine for a first test
  (falls through to the NFS prompt, which you can also skip if you don't need report storage).
- **"Are you using an external Keycloak instance?"** → **Y** (auth/IDA/PMS live on the
  separate "released" sandbox, not in this namespace) — then it asks for
  `KEYCLOAK_EXTERNAL_URL`, `KEYCLOAK_ADMIN_USER`, `KEYCLOAK_ADMIN_PASSWORD`, `PMS_DOMAIN`,
  `PMS_CLIENT_SECRET` (from section 4 above).

Repeat the same for `mock-rp-oidc`:
```bash
cd esignet-mock-services/partner-onboarder
sh install.sh
```

## 6. If a run fails partway (fail-fast by design)

No auto-recovery — a duplicate partner/policy/client name aborts immediately with the real
PMS/Keycloak error. To retry:

1. Open the relevant `values.yaml` (`esignet/partner-onboarder/values.yaml` or
   `esignet-mock-services/partner-onboarder/values.yaml`).
2. Under `onboarding.propertiesOverride.<module>`, bump the colliding name(s)
   (`POLICY_NAME`, `POLICY_GROUP_NAME`, `PARTNER_KC_USERNAME`, etc. — whatever the error names).
3. Delete the failed Helm release (`helm -n esignet uninstall esignet-misp-onboarder`, or the
   mock-rp equivalent) and rerun `install.sh`.

## 7. Known pre-existing, unrelated issue

`helm -n esignet list` shows `esignet-config-server` as `failed` — that predates this work,
unrelated to the onboarder Job, safe to ignore for this test.
