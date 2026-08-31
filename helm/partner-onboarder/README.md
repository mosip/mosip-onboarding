# Partner Onboarder
Helm chart for installing MOSIP Partner onboarder.
## TL;DR
```console
$ helm repo add mosip https://mosip.github.io
$ helm install my-release mosip/partner-onboarder
```
## Prerequisites

- Kubernetes 1.12+
- Helm 3.1.0
- PV provisioner support in the underlying infrastructure
- ReadWriteMany volumes for deployment scaling
## Installing the Chart
To install the chart with the release name `partner-onboarder`.
```console
helm install my-release mosip/partner-onboarder
```
**Tip**: List all releases using `helm list`

## Customizing business config with propertiesOverride

The onboarder image ships with baked-in default business config per module (partner/policy
names, OIDC client fields, etc. - see `../../properties/`). To change any of those values
without rebuilding the image, set `onboarding.propertiesOverride.<module>.<KEY>` in your
values:

```yaml
onboarding:
  modules:
    - name: mock-rp-oidc
      enabled: true
  propertiesOverride:
    mock-rp-oidc:
      POLICY_NAME: mpolicy-default-mock-rp-oidc
      PARTNER_KC_USERNAME: mpartner-default-mock-rp-oidc
      OIDC_CLIENT_NAME: "Health service OIDC Client"
```

This renders a ConfigMap mounted at `/home/mosip/properties/overrides/<module>.properties`
inside the Job pod; `default.sh` sources it after the image's baked-in defaults, so only the
keys you list here change. Values can be plain YAML strings or come from `--set` (including
`--set key=false`/`--set key=123`, which Helm treats as real booleans/numbers) - either way
they're coerced to a string and safely quoted before being written into the properties file.
See `../../properties/README.md` for the full list of keys each module accepts.

Don't put URLs, Keycloak admin credentials, or client secrets here - `propertiesOverride`
renders into a plain ConfigMap, not a Secret. Those are cluster/environment-specific and
should come from your own existing ConfigMaps/Secrets instead, referenced via
`extraEnvVarsCM`/`extraEnvVarsSecret` (lists of ConfigMap/Secret names to load into the Job
pod's environment via `envFrom`) - see how `esignet`'s and `esignet-mock-services`'
`partner-onboarder/install.sh` wire these up for their Keycloak/PMS credentials.

## Uninstalling the Chart
To uninstall/delete the `my-release` deployment:
```console
helm delete my-release
```
