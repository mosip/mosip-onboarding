# Partner Onboarding Utility

## Overview
This repository contains Postman collection to onboard partners on to MOSIP. 

* `run-onboard.sh`:  Onboard any partner.
* `default.sh`: Onboard default partners that are required to run a sandbox.  

## Docker
Docker to run `default.sh` is created to facilitate easy onboarding during installion. Refer `docker-build.sh` and `docker-run.sh`. Use this docker while installing MOSIP on Kubernetes. The docker runs an HTTP server to view the reports. Although this is a one-time job, the docker is run as Kubernetes Deployment with long sleep time set to review reports. If you restart the docker it will run the onboarding again.

The scripts assume a Keycloak client `mosip-deployment-client` with roles `GLOBAL_ADMIN`, `ID_AUTHENTICATION`, `PARTNER_ADMIN` is already created. 

To resolve any such issues while using the script,kindly go to the troubleshooting zone.

## TROUBLESHOOTING

1.After completion of the job either successfully or unsuccessfully,a very detailed html report is prepared and stored at https://onboarder.{sandbox_base_url}/mosip.net
 the user can go and checkout the same ,for more info or response messages .

2.Some of the commonly found errors are 
 a)KER-ATH-401: Authentication Failed 
   Resolution :You need to provide correct secretkey for mosip-deployment-client.
 b)certificate dates are not valid
   Resolution:Check with admin regarding adding grace period in configuration.
 c)Upload of certificate will not be allowed to update other domain certificate
   Resolution:This is expected when you try to upload ida-cred certificate twice.It should only run once and if you see this error while uploading a second        time it can be ignored as the cert is already present.


## License
This project is licensed under the terms of [Mozilla Public License 2.0](LICENSE).

