# Partner Onboarding Utils

## Overview
This repository contains Postman collection to onboard partners on to MOSIP. 

* `run-onboard.sh`:  Onboard any partner.
* `default.sh`: Onboard default partners that are required to run a sandbox.  

## Docker
Docker to run `default.sh` is created to facilitate easy onboarding during installion. Refer `docker-build.sh` and `docker-run.sh`. Use this docker while installing MOSIP on Kubernetes. The docker runs an HTTP server to view the reports. Although this is a one-time job, the docker is run as Kubernetes Deployment with long sleep time set to review reports. If you restart the docker it will run the onboarding again.

The scripts assume a Keycloak client `mosip-deployment-client` with roles `GLOBAL_ADMIN`, `ID_AUTHENTICATION`, `PARTNER_ADMIN` is already created. 

Now with the use of extra parameters such as " -bail " ,the newman requests will stop running ,even with a single test case failure and we will have less overhead.Similarly with the " -cli " parameters all the logs,test case failures,status codes and such will be printed on the log directly.

This will help us target errors faster and provide a crisp report for review as well.

## License
This project is licensed under the terms of [Mozilla Public License 2.0](LICENSE).

