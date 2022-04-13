#!/bin/sh
# Script to upload all default certificates for a sandbox setup. The following are uploaded:
# - Upload of IDA ROOT cert
# - Upload of IDA cert 
# - Upload of mpartner-default-auth and user creation in keycloak.
# - ..

mydir=`pwd`
DATE=`date -u +%FT%T.%3NZ`
ENV_URL=
KEYCLOAK_URL=
KEYCLOAK_ADMIN_USERNAME=admin
CERT_MANAGER=mosip-deployment-client
# Export these on command line
#KEYCLOAK_ADMIN_PASSWORD=
#CERT_MANAGER_PASSWORD=

echo "Uploading ida root cert" 
newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json \
--env-var cert-application-id=ROOT \
--env-var cert-reference-id=  \
--env-var request-time=$DATE \
--env-var cert-manager-username=$CERT_MANAGER \
--env-var cert-manager-password=$CERT_MANAGER_PASSWORD \
--env-var partner-domain=AUTH \
--folder authenticate-to-download-certs \
--folder download-ida-certificate \
--folder upload-ca-certificate \
-r htmlextra --reporter-htmlextra-export ./reports/ida-root.html

echo "Uploading ida cert"
newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json \
--env-var cert-application-id=IDA \
--env-var cert-reference-id=  \
--env-var request-time=$DATE \
--env-var cert-manager-username=$CERT_MANAGER \
--env-var cert-manager-password=$CERT_MANAGER_PASSWORD \
--env-var partner-domain=AUTH \
--folder authenticate-to-download-certs \
--folder download-ida-certificate \
--folder upload-ca-certificate \
-r htmlextra --reporter-htmlextra-export ./reports/ida-ca.html

echo "Uploading mpartner-default-auth cert"
newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json \
--env-var request-time=$DATE \
--env-var cert-application-id=IDA \
--env-var cert-reference-id=mpartner-default-auth \
--env-var cert-manager-username=$CERT_MANAGER \
--env-var cert-manager-password=$CERT_MANAGER_PASSWORD \
--env-var keycloak-admin-username=$KEYCLOAK_ADMIN_USER \
--env-var keycloak-admin-password=$KEYCLOAK_ADMIN_PASSWORD \
--env-var partner-kc-username=mpartner-default-auth \
--env-var partner-domain=AUTH \
--folder authenticate-to-download-certs \
--folder download-ida-certificate \
--folder upload-leaf-certificate \
--folder upload-other-domain-certificate-to-keymanager \
-r htmlextra --reporter-htmlextra-export ./reports/ida-leaf.html --reporter-htmlextra-showEnvironmentData 

exit
echo "Uploading  ida cred cert to keymanager"
newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json \
--env-var request-time=$DATE \
--env-var cert-application-id=IDA \
--env-var cert-reference-id=CRED_SERVICE \
--env-var cert-manager-username=$CERT_MANAGER \
--env-var cert-manager-password=$CERT_MANAGER_PASSWORD \
--env-var keycloak-admin-username=$KEYCLOAK_ADMIN_USER \
--env-var keycloak-admin-password=$KEYCLOAK_ADMIN_PASSWORD \
--env-var partner-kc-username=mpartner-default-auth \
--env-var partner-domain=AUTH \
--folder authenticate-to-download-certs \
--folder download-ida-certificate \
--folder upload-ida-cred-cert-to-keymanager \
-r htmlextra --reporter-htmlextra-export ./reports/ida-cred.html --reporter-htmlextra-showEnvironmentData 

echo "Uploading mpartner-default-resident cert"
newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json \
--env-var request-time=$DATE \
--env-var cert-application-id=RESIDENT \
--env-var cert-reference-id=mpartner-default-resident \
--env-var cert-manager-username=$CERT_MANAGER \
--env-var cert-manager-password=$CERT_MANAGER_PASSWORD \
--env-var keycloak-admin-username=$KEYCLOAK_ADMIN_USER \
--env-var keycloak-admin-password=$KEYCLOAK_ADMIN_PASSWORD \
--env-var partner-kc-username=mpartner-default-resident \
--env-var partner-domain=AUTH \
--folder authenticate-to-download-certs \
--folder download-ca-certificate-from-keymanager \
--folder download-leaf-certificate-from-keymanager \
--folder upload-ca-certificate \
--folder upload-leaf-certificate \
--folder upload-signed-leaf-certifcate-to-keymanager \
-r htmlextra --reporter-htmlextra-export ./reports/resident.html --reporter-htmlextra-showEnvironmentData 

echo "Uploading mpartner-default-print cert"
root_cert_path="$mydir/certs/print/RootCA.pem"
client_cert_path="$mydir/certs/print/Client.pem"
RootCACert=`awk 'NF {sub(/\r/, ""); printf "%s\\r\\n",$0;}' $root_cert_path`
PartnerCert=`awk 'NF {sub(/\r/, ""); printf "%s\\r\\n",$0;}' $client_cert_path`
newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json \
--env-var request-time=$DATE \
--env-var partner-manager-username=$CERT_MANAGER \
--env-var partner-manager-password=$CERT_MANAGER_PASSWORD \
--env-var keycloak-admin-username=$KEYCLOAK_ADMIN_USER \
--env-var keycloak-admin-password=$KEYCLOAK_ADMIN_PASSWORD \
--env-var partner-kc-username=mpartner-default-print \
--env-var application-id=ida \
--env-var partner-domain=AUTH \
--env-var ca-certificate="$RootCACert" \
--env-var leaf-certificate="$PartnerCert" \
--folder authenticate-to-upload-certs \
--folder upload-ca-certificate \
--folder upload-leaf-certificate \
--folder upload-signed-leaf-certifcate-to-keymanager \
-r htmlextra --reporter-htmlextra-export ./reports/print.html --reporter-htmlextra-showEnvironmentData 

#echo "uploading mpartner default print cert" $'\n'
#root_cert_path="$mydir/certs/print/RootCA.pem"
#client_cert_path="$mydir/certs/print/Client.pem"
#RootCACert=$(awk 'NF {sub(/\r/, ""); printf "%s\\r\\n",$0;}' $root_cert_path)
#PartnerCert=$(awk 'NF {sub(/\r/, ""); printf "%s\\r\\n",$0;}' $client_cert_path)
#jq '.values |= map(if .key=="partner-kc-username" then (.value="mpartner-default-print") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
#newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --export-environment $env_temp_file/onboarding.postman_environment.json \
#--folder authenticate-to-upload-certs \
#--env-var ca-certificate="$RootCACert" \
#--env-var leaf-certificate="$PartnerCert" \
#--folder upload-ca-certificate \
#--folder upload-leaf-certificate \
#-r htmlextra --reporter-htmlextra-export $(prop 'report_dir')/mapartner-default-print.html
#rm $env_temp_file/*
#
#echo "uploading mpartner default abis cert" $'\n'
#root_cert_path="$mydir/certs/abis/RootCA.pem"
#client_cert_path="$mydir/certs/abis/Client.pem"
#RootCACert=$(awk 'NF {sub(/\r/, ""); printf "%s\\r\\n",$0;}' $root_cert_path)
#PartnerCert=$(awk 'NF {sub(/\r/, ""); printf "%s\\r\\n",$0;}' $client_cert_path)
#jq '.values |= map(if .key=="partner-kc-username" then (.value="mpartner-default-abis") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
#newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --export-environment $env_temp_file/onboarding.postman_environment.json \
#--folder authenticate-to-upload-certs \
#--env-var ca-certificate="$RootCACert" \
#--env-var leaf-certificate="$PartnerCert" \
#--folder upload-ca-certificate \
#--folder upload-leaf-certificate \
#-r htmlextra --reporter-htmlextra-export $(prop 'report_dir')/mapartner-default-abis.html
#rm $env_temp_file/*
#;;
