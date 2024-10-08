# Partner Onboarding Utils

## Overview
This repository contains Postman collection to onboard partners on to MOSIP.
* `run-onboard.sh`:  Onboard any partner.
* `default.sh`: Onboard default partners that are required to run a sandbox.  
## Docker
* Docker to run `default.sh` is created to facilitate easy onboarding during installion. Refer `docker-build.sh` and `docker-run.sh`. Use this docker while installing MOSIP on Kubernetes. The docker runs an HTTP server to view the reports. Although this is a one-time job, the docker is run as Kubernetes Deployment with long sleep time set to review reports. If you restart the docker it will run the onboarding again.
* The scripts assume a Keycloak client `mosip-deployment-client` with roles `GLOBAL_ADMIN`, `ID_AUTHENTICATION`, `PARTNER_ADMIN` is already created. 
* If the `ENABLE_INSECURE` environment variable is set to `true`, the script will proceed with downloading an SSL certificate and subsequently provide it for utilization in **Newman** collections and **curl** API calls during execution. This functionality is designed for scenarios where the script is required to be used on a server that possesses self-signed SSL certificates.
## License
This project is licensed under the terms of [Mozilla Public License 2.0](LICENSE).

