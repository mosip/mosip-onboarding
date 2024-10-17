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
## Uninstalling the Chart
To uninstall/delete the `my-release` deployment:
```console
helm delete my-release
```
