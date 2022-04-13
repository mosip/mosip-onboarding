#!/bin/sh
# Example:

#docker run --rm --name partner-onboarder -p 8080:8080 -e URL=https://api-internal.soil.mosip.net -e CERT_MANAGER_PASSWORD=<mosip-deployment-client password>  mosipdev/partner-onboarder:develop
docker run --rm --name partner-onboarder -p 8080:8080 -e URL=https://api-internal.soil.mosip.net -e CERT_MANAGER_PASSWORD=$CERT_MANAGER_PASSWORD  mosipdev/partner-onboarder:develop

