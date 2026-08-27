# Per-module onboarding properties

`default.sh` sources `properties/<MODULE>.properties` (this directory) for the "esignet and
onward" modules: `esignet`, `mock-rp-oidc`, `resident-oidc`, `mimoto-keybinding`,
`mimoto-oidc`, `signup-oidc`. Everything that used to be a hardcoded shell
variable for these modules (partner name, org name, partner type, policy name/group name,
OIDC client name/id, logo/redirect URIs, credential-type, policy data file, etc.) now comes
from these files instead.

Modules before esignet (`ida`, `print`, `resident`, `abis`, `mobileid`, `digitalcard`) are
unchanged and have no properties file — `default.sh` still configures those inline.

## How to use this on a failed run

There is no automatic duplicate/error recovery any more. If a Job run fails - "policy group
already exists", "partner already registered", a network/connection error to `url`/
`keycloak-url`/`external-url`, a certificate upload failure, whatever it is - the newman
report/Job logs will show exactly which request failed and why. Fix the relevant value in
`properties/<MODULE>.properties` (e.g. pick a new `PARTNER_KC_USERNAME`/`POLICY_NAME` if it
was a duplicate, or double check the URL/cert values if it was a network/cert error) and
rerun the Job. Nothing tries to guess or silently work around a bad value for you.

## Overriding without editing the checked-in file

The default values here ship baked into the `partner-onboarder` image. To override
individual keys without rebuilding the image, set them under `onboarding.propertiesOverride`
in the `partner-onboarder` Helm chart's values (see `helm/partner-onboarder/values.yaml`) -
the chart renders those into a ConfigMap and mounts it at
`/home/mosip/properties/overrides/<MODULE>.properties` inside the Job pod. `default.sh`
sources the baked-in file first, then this override file second, so only the keys you list
there change - everything else keeps its baked-in default. This works identically regardless
of which repo installs the chart (mosip-infra, esignet's `partner-onboarder/`, mimoto's
`partner-onboarder/`) since they all install the same chart.

## File format

These are `sh`-sourced (`. properties/<MODULE>.properties`), so they're plain shell
assignments, not a generic key=value format:

- **Quote any value containing spaces**, e.g. `OIDC_CLIENT_NAME="Health service OIDC Client"`.
  An unquoted value with spaces only assigns the first word - everything after the first
  space gets executed as a separate shell command, which normally just fails loudly with
  "command not found" (harmless, since `sh` doesn't abort on that), but silently truncates
  the variable's actual value. If a value looks like it "didn't take" after editing a
  properties file, check for this first.
- **Wrap raw JSON values in single quotes**, e.g.
  `ADDITIONAL_CONFIG='{"consent_expire_in_mins":20160}'` (used for `CLIENT_NAME_LANG_MAP`/
  `ADDITIONAL_CONFIG` on the OIDC-client-creation modules). Left unquoted or wrapped in
  double quotes, the shell's own quote-removal strips the inner `"` characters, silently
  turning valid JSON into invalid JSON (`{"a":"b"}` becomes `{a:b}`) - verified this exact
  failure mode directly before settling on single-quoting as the fix.

## Values intentionally NOT in these files

URLs (`url`, `keycloak-url`, `external-url`), Keycloak admin credentials, and
client secrets (`mosip_pms_client_secret`, `mosip_deployment_client_secret`) stay sourced
from Kubernetes env vars/secrets exactly as before - they're cluster/environment-specific
and shouldn't live in a properties file that ships with the repo.
