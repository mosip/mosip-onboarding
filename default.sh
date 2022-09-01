#!/bin/sh
# Script to upload all default certificates for a sandbox setup. The following are uploaded:
# Export these environment variables on command line
#URL={{base_url of the environment}}
#CERT_MANAGER_PASSWORD={{secretkey of mosip-deployment-client}}
# Usage: ./default.sh
# See HTML reports under ./reports folder

MYDIR=`pwd`
DATE=`date -u +%FT%T.%3NZ`
CERT_MANAGER=mosip-deployment-client
#URL=<export this env variable on command line>
#CERT_MANAGER_PASSWORD=<export this env variable on command line>

upload_ida_root_cert() {
    echo "Uploading ida root cert" 
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json \
    --env-var url=$URL \
    --env-var cert-application-id=ROOT \
    --env-var cert-reference-id=  \
    --env-var request-time=$DATE \
    --env-var cert-manager-username=$CERT_MANAGER \
    --env-var cert-manager-password=$CERT_MANAGER_PASSWORD \
    --env-var partner-domain=AUTH \
    --folder authenticate-as-cert-manager \
    --folder download-ida-certificate \
    --folder upload-ca-certificate \
    -r htmlextra --reporter-htmlextra-export ./reports/ida-root.html
}

upload_ida_cert() {
    echo "Uploading ida cert"
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json \
    --env-var url=$URL \
    --env-var cert-application-id=IDA \
    --env-var cert-reference-id=  \
    --env-var request-time=$DATE \
    --env-var cert-manager-username=$CERT_MANAGER \
    --env-var cert-manager-password=$CERT_MANAGER_PASSWORD \
    --env-var partner-domain=AUTH \
    --folder authenticate-as-cert-manager \
    --folder download-ida-certificate \
    --folder upload-ca-certificate \
    -r htmlextra --reporter-htmlextra-export ./reports/ida-ca.html
}
    
upload_ida_partner_cert () {
    echo "Uploading mpartner-default-auth cert"
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json \
    --env-var url=$URL \
    --env-var request-time=$DATE \
    --env-var cert-application-id=IDA \
    --env-var cert-reference-id=mpartner-default-auth \
    --env-var cert-manager-username=$CERT_MANAGER \
    --env-var cert-manager-password=$CERT_MANAGER_PASSWORD \
    --env-var keycloak-admin-username=$KEYCLOAK_ADMIN_USER \
    --env-var keycloak-admin-password=$KEYCLOAK_ADMIN_PASSWORD \
    --env-var partner-kc-username=mpartner-default-auth \
    --env-var partner-domain=AUTH \
    --folder authenticate-as-cert-manager \
    --folder download-ida-certificate \
    --folder upload-leaf-certificate \
    --folder upload-signed-leaf-certificate \
    -r htmlextra --reporter-htmlextra-export ./reports/ida-partner.html --reporter-htmlextra-showEnvironmentData 
}
    
upload_ida_cred_cert () {
    echo "Uploading ida cred cert to keymanager for zero knowledge encryption"
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json \
    --env-var url=$URL \
    --env-var request-time=$DATE \
    --env-var cert-application-id=IDA \
    --env-var cert-reference-id=CRED_SERVICE \
    --env-var cert-manager-username=$CERT_MANAGER \
    --env-var cert-manager-password=$CERT_MANAGER_PASSWORD \
    --env-var partner-kc-username=mpartner-default-auth \
    --env-var partner-domain=AUTH \
    --folder authenticate-as-cert-manager \
    --folder download-ida-certificate \
    --folder upload-ida-cred-cert-to-keymanager \
    -r htmlextra --reporter-htmlextra-export ./reports/ida-cred.html --reporter-htmlextra-showEnvironmentData 
} 

upload_resident_cert() {
    echo "Uploading mpartner-default-resident cert"
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json \
    --env-var url=$URL \
    --env-var request-time=$DATE \
    --env-var cert-application-id=RESIDENT \
    --env-var cert-reference-id=mpartner-default-resident \
    --env-var cert-manager-username=$CERT_MANAGER \
    --env-var cert-manager-password=$CERT_MANAGER_PASSWORD \
    --env-var keycloak-admin-username=$KEYCLOAK_ADMIN_USER \
    --env-var keycloak-admin-password=$KEYCLOAK_ADMIN_PASSWORD \
    --env-var partner-kc-username=mpartner-default-resident \
    --env-var partner-domain=AUTH \
    --folder authenticate-as-cert-manager \
    --folder download-ca-certificate-from-keymanager \
    --folder download-leaf-certificate-from-keymanager \
    --folder upload-ca-certificate \
    --folder upload-leaf-certificate \
    --folder upload-signed-leaf-certifcate-to-keymanager \
    -r htmlextra --reporter-htmlextra-export ./reports/resident.html --reporter-htmlextra-showEnvironmentData 
}
upload_print_cert() {
    echo "Uploading mpartner-default-print cert"
    root_cert_path="$MYDIR/certs/print/root-ca-inline.pem"
    partner_cert_path="$MYDIR/certs/print/client-inline.pem"
    root_ca_cert=`awk '{ print $0 }' $root_cert_path`
    partner_cert=`awk '{ print $0 }' $partner_cert_path`
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json \
    --env-var url=$URL \
    --env-var request-time=$DATE \
    --env-var cert-manager-username=$CERT_MANAGER \
    --env-var cert-manager-password=$CERT_MANAGER_PASSWORD \
    --env-var partner-kc-username=mpartner-default-print \
    --env-var application-id=ida \
    --env-var partner-domain=AUTH \
    --env-var ca-certificate="$root_ca_cert" \
    --env-var leaf-certificate="$partner_cert" \
    --folder authenticate-as-cert-manager \
    --folder upload-ca-certificate \
    --folder upload-leaf-certificate \
    -r htmlextra --reporter-htmlextra-export ./reports/print.html --reporter-htmlextra-showEnvironmentData 
}

upload_abis_cert () {
    echo "Uploading mpartner-default-abis cert"
    root_cert_path="$MYDIR/certs/abis/root-ca-inline.pem"
    partner_cert_path="$MYDIR/certs/abis/client-inline.pem"
    root_ca_cert=`awk '{ print $0 }' $root_cert_path`
    partner_cert=`awk '{ print $0 }' $partner_cert_path`
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json \
    --env-var url=$URL \
    --env-var request-time=$DATE \
    --env-var cert-manager-username=$CERT_MANAGER \
    --env-var cert-manager-password=$CERT_MANAGER_PASSWORD \
    --env-var partner-kc-username=mpartner-default-abis \
    --env-var application-id=ida \
    --env-var partner-domain=AUTH \
    --env-var ca-certificate="$root_ca_cert" \
    --env-var leaf-certificate="$partner_cert" \
    --folder authenticate-as-cert-manager \
    --folder upload-ca-certificate \
    --folder upload-leaf-certificate \
    -r htmlextra --reporter-htmlextra-export ./reports/abis.html --reporter-htmlextra-showEnvironmentData 
}

upload_mpartner_default_mobile_cert() {
    echo "Uploading mpartner-default-mobile cert"
    root_cert_path="$MYDIR/certs/mpartner-default-mobile/root-ca-inline.pem"
    partner_cert_path="$MYDIR/certs/mpartner-default-mobile/client-inline.pem"
    root_ca_cert=`awk '{ print $0 }' $root_cert_path`
    partner_cert=`awk '{ print $0 }' $partner_cert_path`
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json \
    --env-var url=$URL \
    --env-var request-time=$DATE \
    --env-var cert-manager-username=$CERT_MANAGER \
    --env-var cert-manager-password=$CERT_MANAGER_PASSWORD \
    --env-var partner-kc-username=mpartner-default-mobile \
    --env-var application-id=ida \
    --env-var partner-domain=AUTH \
    --env-var policy-name=mpolicy-default-mobile \
    --env-var credential-type=vercred \
    --env-var ca-certificate="$root_ca_cert" \
    --env-var leaf-certificate="$partner_cert" \
    --folder authenticate-as-cert-manager \
    --folder upload-ca-certificate \
    --folder upload-leaf-certificate \
    --folder mapping-partner-to-policy-credential-type \
    -r htmlextra --reporter-htmlextra-export ./reports/mpartner-default-mobile.html --reporter-htmlextra-showEnvironmentData
}
upload_mpartner-default-digitalcard_cert() {
    echo "Uploading mpartner-default-digitalcard cert"
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json \
    --env-var url=$URL \
    --env-var request-time=$DATE \
    --env-var cert-application-id=DIGITAL_CARD \
    --env-var cert-reference-id=mpartner-default-digitalcard \
    --env-var cert-manager-username=$CERT_MANAGER \
    --env-var cert-manager-password=$CERT_MANAGER_PASSWORD \
    --env-var keycloak-admin-username=$KEYCLOAK_ADMIN_USER \
    --env-var keycloak-admin-password=$KEYCLOAK_ADMIN_PASSWORD \
    --env-var partner-kc-username=mpartner-default-digitalcard \
    --env-var partner-domain=AUTH \
    --folder authenticate-as-cert-manager \
    --folder download-ca-certificate-from-keymanager \
    --folder download-leaf-certificate-from-keymanager \
    --folder upload-ca-certificate \
    --folder upload-leaf-certificate \
    --folder upload-signed-leaf-certifcate-to-keymanager \
    -r htmlextra --reporter-htmlextra-export ./reports/digitalcard.html --reporter-htmlextra-showEnvironmentData
}


 upload_ida_root_cert
 upload_ida_cert
 upload_ida_partner_cert
 upload_ida_cred_cert
 upload_resident_cert
 upload_print_cert
 upload_abis_cert
 upload_mpartner_default_mobile_cert
 upload_mpartner-default-digitalcard_cert

