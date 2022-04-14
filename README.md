# Partner Onboarding Utils

## Overview
This repository contains Postman collection to onboard partners on to MOSIP. 

* `run-onboard.sh`:  On board any partner.
* `default.sh`: On board default partners that are required to run a sandbox.  

## Docker
Docker to run `default.sh` is created to facilitate easy onboarding during installion. Refer `docker-build.sh` and `docker-run.sh`.  The scripts assume a Keycloak client `mosip-deployment-client` with necessary roles. Use this docker while install MOSIP on Kubernetes. The docker runs an HTTP server to view the reports. The docker has long sleep time set to keep it alive to review reports. If you restart the docker it will run the onboarding again.

## License
This project is licensed under the terms of [Mozilla Public License 2.0](LICENSE).
