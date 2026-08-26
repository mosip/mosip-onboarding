#!/bin/sh
# Script to upload all default certificates for a sandbox setup. The following are uploaded:
# Export these environment variables on command line
#URL={{base_url of the environment}}
#CERT_MANAGER_PASSWORD={{secretkey of mosip-deployment-client}}
# Usage: ./default.sh
# See HTML reports under ./reports folder

# Standalone (no newman/postman dependency) cleanup for the throwaway Keycloak user this
# script creates to approve/onboard things. Deliberately independent of the main newman
# run: the esignet-onward flows also delete this user as their own last folder
# (login-to-keycloak-as-admin/delete-user) when everything succeeds, but --bail means
# newman never reaches that folder if an EARLIER request fails - which would otherwise
# leave a privileged, unattended Keycloak user behind indefinitely. This function is
# registered via `trap ... EXIT` right after the user's name is known, so it always runs
# when the script exits, regardless of why - success, an API/network failure partway
# through, or an explicit `exit` call. (It cannot survive a SIGKILL - nothing can trap
# that - but covers every other exit path.)
delete_keycloak_user_if_exists() {
    username="$1"
    kc_url="$2"
    admin_user="$3"
    admin_pass="$4"

    if [ -z "$username" ] || [ -z "$kc_url" ]; then
        return 0
    fi

    echo "Cleanup: checking for leftover Keycloak user '$username' at $kc_url ..."

    token=$(curl -s --max-time 15 -X POST "$kc_url/auth/realms/master/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "username=$admin_user" \
        --data-urlencode "password=$admin_pass" \
        -d "grant_type=password" -d "client_id=admin-cli" \
        | jq -r '.access_token // empty' 2>/dev/null)

    if [ -z "$token" ]; then
        echo "Cleanup: could not obtain a Keycloak admin token - cannot verify/delete user '$username'. Check and delete it manually if the run failed."
        return 1
    fi

    user_id=$(curl -s --max-time 15 "$kc_url/auth/admin/realms/mosip/users?username=$username" \
        -H "Authorization: Bearer $token" \
        | jq -r '.[0].id // empty' 2>/dev/null)

    if [ -z "$user_id" ]; then
        echo "Cleanup: no Keycloak user named '$username' found - nothing to delete."
        return 0
    fi

    http_code=$(curl -s --max-time 15 -o /dev/null -w "%{http_code}" -X DELETE \
        "$kc_url/auth/admin/realms/mosip/users/$user_id" \
        -H "Authorization: Bearer $token")

    case "$http_code" in
        200|204|404)
            echo "Cleanup: deleted (or already absent) Keycloak user '$username' (id $user_id)."
            ;;
        *)
            echo "Cleanup: FAILED to delete Keycloak user '$username' (id $user_id) - HTTP $http_code. This user may still have roles assigned - check and delete it manually."
            ;;
    esac
}

upload_ida_root_cert() {
    echo "Uploading ida root cert"
    reports_dir="./reports/IDA/$current_datetime"
    mkdir -p "$reports_dir"
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --bail \
    --env-var url="$URL" \
    --env-var authmanager-url=$AUTHMANAGER_URL \
    --env-var pms-url=$PMS_URL \
    --env-var cert-application-id=ROOT \
    --env-var cert-reference-id=  \
    --env-var request-time="$DATE" \
    --env-var cert-manager-username="$KEYCLOAK_CLIENT" \
    --env-var cert-manager-password="$KEYCLOAK_CLIENT_SECRET" \
    --env-var partner-domain=AUTH \
    --folder authenticate-as-cert-manager \
    --folder download-ida-certificate \
    --folder upload-ca-certificate \
    $ADD_SSL_NEWMAN \
	  -r cli,htmlextra --reporter-htmlextra-export "$reports_dir/ida-root.html"

}

upload_ida_cert() {
    echo "Uploading ida cert"
    reports_dir="./reports/IDA/$current_datetime"
    mkdir -p "$reports_dir"
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --bail \
    --env-var url="$URL" \
    --env-var authmanager-url=$AUTHMANAGER_URL \
    --env-var pms-url=$PMS_URL \
    --env-var cert-application-id=IDA \
    --env-var cert-reference-id=  \
    --env-var request-time="$DATE" \
    --env-var cert-manager-username="$KEYCLOAK_CLIENT" \
    --env-var cert-manager-password="$KEYCLOAK_CLIENT_SECRET" \
    --env-var partner-domain=AUTH \
    --folder authenticate-as-cert-manager \
    --folder download-ida-certificate \
    --folder upload-ca-certificate \
    $ADD_SSL_NEWMAN \
    -r cli,htmlextra --reporter-htmlextra-export "$reports_dir/ida.html"
}

upload_ida_partner_cert () {
    echo "Uploading mpartner-default-auth cert"
    reports_dir="./reports/IDA/$current_datetime"
    mkdir -p "$reports_dir"
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --bail \
    --env-var url="$URL" \
    --env-var authmanager-url=$AUTHMANAGER_URL \
    --env-var pms-url=$PMS_URL \
    --env-var request-time="$DATE" \
    --env-var cert-application-id=IDA \
    --env-var cert-reference-id=mpartner-default-auth \
    --env-var cert-manager-username="$KEYCLOAK_CLIENT" \
    --env-var cert-manager-password="$KEYCLOAK_CLIENT_SECRET" \
    --env-var keycloak-admin-username="$KEYCLOAK_ADMIN_USER" \
    --env-var keycloak-admin-password="$KEYCLOAK_ADMIN_PASSWORD" \
    --env-var partner-kc-username=mpartner-default-auth \
    --env-var partner-domain=AUTH \
    --folder authenticate-as-cert-manager \
    --folder download-ida-certificate \
    --folder upload-leaf-certificate \
    --folder upload-signed-leaf-certificate \
    $ADD_SSL_NEWMAN \
    -r cli,htmlextra --reporter-htmlextra-export "$reports_dir/ida-partner.html" --reporter-htmlextra-showEnvironmentData
}

upload_ida_cred_cert () {
    echo "Uploading ida cred cert to keymanager for zero knowledge encryption"
    reports_dir="./reports/IDA/$current_datetime"
    mkdir -p "$reports_dir"
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --bail \
    --env-var url="$URL" \
    --env-var authmanager-url=$AUTHMANAGER_URL \
    --env-var request-time="$DATE" \
    --env-var cert-application-id=IDA \
    --env-var cert-reference-id=CRED_SERVICE \
    --env-var cert-manager-username="$KEYCLOAK_CLIENT" \
    --env-var cert-manager-password="$KEYCLOAK_CLIENT_SECRET" \
    --env-var partner-kc-username=mpartner-default-auth \
    --env-var partner-domain=AUTH \
    --folder authenticate-as-cert-manager \
    --folder download-ida-certificate \
    --folder upload-ida-cred-cert-to-keymanager \
    $ADD_SSL_NEWMAN \
    -r cli,htmlextra --reporter-htmlextra-export "$reports_dir/ida-cred.html" --reporter-htmlextra-showEnvironmentData
}

upload_resident_cert() {
    echo "Uploading mpartner-default-resident cert"
    reports_dir="./reports/RESIDENT/$current_datetime"
    mkdir -p "$reports_dir"
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --bail \
    --env-var url="$URL" \
    --env-var authmanager-url=$AUTHMANAGER_URL \
    --env-var pms-url=$PMS_URL \
    --env-var request-time="$DATE" \
    --env-var cert-application-id=RESIDENT \
    --env-var cert-reference-id=mpartner-default-resident \
    --env-var cert-manager-username="$KEYCLOAK_CLIENT" \
    --env-var cert-manager-password="$KEYCLOAK_CLIENT_SECRET" \
    --env-var keycloak-admin-username="$KEYCLOAK_ADMIN_USER" \
    --env-var keycloak-admin-password="$KEYCLOAK_ADMIN_PASSWORD" \
    --env-var partner-kc-username=mpartner-default-resident \
    --env-var partner-domain=AUTH \
    --folder authenticate-as-cert-manager \
    --folder download-intermediate-resident-certificate-from-keymanager \
    --folder download-leaf-certificate-from-keymanager \
    --folder upload-intermediate-ca-certificate \
    --folder upload-leaf-certificate \
    --folder upload-signed-leaf-certifcate-to-keymanager \
    $ADD_SSL_NEWMAN \
    -r cli,htmlextra --reporter-htmlextra-export "$reports_dir/resident.html" --reporter-htmlextra-showEnvironmentData
}
upload_print_cert() {
    echo "Uploading mpartner-default-print cert"
    reports_dir="./reports/PRINT/$current_datetime"
    mkdir -p "$reports_dir"
    root_cert_path="$MYDIR/certs/print/root-ca-inline.pem"
    partner_cert_path="$MYDIR/certs/print/client-inline.pem"
    root_ca_cert=`awk '{ print $0 }' $root_cert_path`
    partner_cert=`awk '{ print $0 }' $partner_cert_path`
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --bail \
    --env-var url="$URL" \
    --env-var authmanager-url=$AUTHMANAGER_URL \
    --env-var pms-url=$PMS_URL \
    --env-var request-time="$DATE" \
    --env-var cert-manager-username="$KEYCLOAK_CLIENT" \
    --env-var cert-manager-password="$KEYCLOAK_CLIENT_SECRET" \
    --env-var partner-kc-username=mpartner-default-print \
    --env-var application-id=ida \
    --env-var partner-domain=AUTH \
    --env-var ca-certificate="$root_ca_cert" \
    --env-var leaf-certificate="$partner_cert" \
    --folder authenticate-as-cert-manager \
    --folder upload-ca-certificate \
    --folder upload-leaf-certificate \
    $ADD_SSL_NEWMAN \
    -r cli,htmlextra --reporter-htmlextra-export "$reports_dir/print.html" --reporter-htmlextra-showEnvironmentData
}

upload_abis_cert () {
    echo "Uploading mpartner-default-abis cert"
    reports_dir="./reports/ABIS/$current_datetime"
    mkdir -p "$reports_dir"
    root_cert_path="$MYDIR/certs/abis/root-ca-inline.pem"
    partner_cert_path="$MYDIR/certs/abis/client-inline.pem"
    root_ca_cert=`awk '{ print $0 }' $root_cert_path`
    partner_cert=`awk '{ print $0 }' $partner_cert_path`
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --bail \
    --env-var url="$URL" \
    --env-var authmanager-url=$AUTHMANAGER_URL \
    --env-var pms-url=$PMS_URL \
    --env-var request-time="$DATE" \
    --env-var cert-manager-username="$KEYCLOAK_CLIENT" \
    --env-var cert-manager-password="$KEYCLOAK_CLIENT_SECRET" \
    --env-var partner-kc-username=mpartner-default-abis \
    --env-var application-id=ida \
    --env-var partner-domain=AUTH \
    --env-var ca-certificate="$root_ca_cert" \
    --env-var leaf-certificate="$partner_cert" \
    --folder authenticate-as-cert-manager \
    --folder upload-ca-certificate \
    --folder upload-leaf-certificate \
    $ADD_SSL_NEWMAN \
    -r cli,htmlextra --reporter-htmlextra-export "$reports_dir/abis.html" --reporter-htmlextra-showEnvironmentData
}
upload_mpartner_default_mobile_cert() {
    echo "Uploading mpartner-default-mobile cert"
    reports_dir="./reports/MOBILEID/$current_datetime"
    mkdir -p "$reports_dir"
    root_cert_path="$MYDIR/certs/mpartner-default-mobile/root-ca-inline.pem"
    partner_cert_path="$MYDIR/certs/mpartner-default-mobile/client-inline.pem"
    root_ca_cert=`awk '{ print $0 }' $root_cert_path`
    partner_cert=`awk '{ print $0 }' $partner_cert_path`
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --bail \
    --env-var url="$URL" \
    --env-var authmanager-url=$AUTHMANAGER_URL \
    --env-var pms-url=$PMS_URL \
    --env-var request-time="$DATE" \
    --env-var cert-manager-username="$KEYCLOAK_CLIENT" \
    --env-var cert-manager-password="$KEYCLOAK_CLIENT_SECRET" \
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
    $ADD_SSL_NEWMAN \
    -r cli,htmlextra --reporter-htmlextra-export "$reports_dir/mpartner-default-mobile.html" --reporter-htmlextra-showEnvironmentData
}
upload_mpartner_default_digitalcard_cert() {
    echo "Uploading mpartner-default-digitalcard cert"
    reports_dir="./reports/DIGITALCARD/$current_datetime"
    mkdir -p "$reports_dir"
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --bail \
    --env-var url="$URL" \
    --env-var authmanager-url=$AUTHMANAGER_URL \
    --env-var pms-url=$PMS_URL \
    --env-var request-time="$DATE" \
    --env-var cert-application-id=DIGITAL_CARD \
    --env-var cert-reference-id=mpartner-default-digitalcard \
    --env-var cert-manager-username="$KEYCLOAK_CLIENT" \
    --env-var cert-manager-password="$KEYCLOAK_CLIENT_SECRET" \
    --env-var keycloak-admin-username="$KEYCLOAK_ADMIN_USER" \
    --env-var keycloak-admin-password="$KEYCLOAK_ADMIN_PASSWORD" \
    --env-var partner-kc-username=mpartner-default-digitalcard \
    --env-var partner-domain=AUTH \
    --folder authenticate-as-cert-manager \
    --folder download-intermediate-resident-certificate-from-keymanager \
    --folder download-leaf-certificate-from-keymanager \
    --folder upload-intermediate-ca-certificate \
    --folder upload-leaf-certificate \
    --folder upload-signed-leaf-certifcate-to-keymanager \
    $ADD_SSL_NEWMAN \
    -r cli,htmlextra --reporter-htmlextra-export "$reports_dir/mpartner-default-digitalcard.html" --reporter-htmlextra-showEnvironmentData
}

onboard_esignet_partner() {
    echo "Onboarding esignet-partner"
    reports_dir="./reports/ESIGNET/$current_datetime"
    mkdir -p "$reports_dir"
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --bail \
    --env-var url="$URL" \
    --env-var authmanager-url=$AUTHMANAGER_URL \
    --env-var pms-url=$PMS_URL \
    --env-var request-time="$DATE" \
	--env-var partner-manager-username=$PARTNER_MANAGER_USERNAME \
	--env-var partner-manager-password=$PARTNER_MANAGER_PASSWORD \
	--env-var application-id=$APPLICATION_ID \
	--env-var module-clientid=$MODULE_CLIENTID \
	--env-var module-secretkey=$MODULE_SECRETKEY \
	--env-var policy-group-name=$POLICY_GROUP_NAME \
	--env-var partner-kc-username=$PARTNER_KC_USERNAME \
	--env-var partner-organization-name=$PARTNER_ORGANIZATION_NAME \
    --env-var partner-type=$PARTNER_TYPE \
    --env-var external-url=$EXTERNAL_URL \
	--env-var policy-name=$POLICY_NAME \
	--env-var keycloak-url=$KEYCLOAK_URL \
	--env-var keycloak-admin-password="$KEYCLOAK_ADMIN_PASSWORD" \
	--env-var keycloak-admin-username=$KEYCLOAK_ADMIN_USERNAME \
	--env-var partner-domain=$PARTNER_DOMAIN \
	--folder 'create_keycloak_user' \
	--folder 'create/publish_policy_group_and_policy' \
	--folder partner-self-registration \
    --folder download-esignet-root-certificate \
	--folder download-esignet-partner-certificate \
	--folder authenticate-to-upload-certs \
    --folder upload-ca-certificate \
    --folder upload-leaf-certificate \
    --folder activate-partner \
	--folder upload-signed-esignet-certificate \
	--folder partner_request_mapping_to_policyname \
	--folder approve-partner-mapping-to-policy \
	--folder create-the-MISP-license-key-for-partner \
	--folder login-to-keycloak-as-admin \
	--folder delete-user \
    $ADD_SSL_NEWMAN \
    --export-environment ./config-secrets.json -d "$POLICY_DATA_FILE" -r cli,htmlextra --reporter-htmlextra-export "$reports_dir/esignet.html" --reporter-htmlextra-showEnvironmentData
    MISP_LICENSE_KEY=$(jq -r '.values[] | select(.key == "mpartner-default-esignet-misp-license-key") | .value' config-secrets.json)

if [ -z "$MISP_LICENSE_KEY" ]; then
    MISP_LICENSE_KEY=$(jq -r '.values[] | select(.key | contains("mpartner-default-esignet-misp-license-key")) | .value' config-secrets.json)
fi
}

onboard_mock_relying_party_with_mock_rp_oidc_client(){
    echo "Onboarding mock-rp-oidc-client"
  reports_dir="./reports/MOCK_RP_OIDC/$current_datetime"
  mkdir -p "$reports_dir"
	sh $MYDIR/certs/create-signing-certs.sh $MYDIR
	root_ca_cert=$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' $root_cert_path)
	partner_cert=$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' $client_cert_path)
	echo $root_ca_cert
	echo $partner_cert
	newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --bail \
    --env-var url="$URL" \
    --env-var authmanager-url=$AUTHMANAGER_URL \
    --env-var pms-url=$PMS_URL \
    --env-var request-time="$DATE" \
	--env-var partner-manager-username=$PARTNER_MANAGER_USERNAME \
	--env-var partner-manager-password=$PARTNER_MANAGER_PASSWORD \
	--env-var application-id=$APPLICATION_ID \
	--env-var module-clientid=$MODULE_CLIENTID \
	--env-var module-secretkey=$MODULE_SECRETKEY \
	--env-var policy-group-name=$POLICY_GROUP_NAME \
	--env-var partner-kc-username=$PARTNER_KC_USERNAME \
	--env-var partner-organization-name=$PARTNER_ORGANIZATION_NAME \
    --env-var partner-type=$PARTNER_TYPE \
    --env-var external-url=$EXTERNAL_URL \
	--env-var policy-name=$POLICY_NAME \
	--env-var logo-uri=$LOGO_URI \
	--env-var redirect-uris=$REDIRECT_URIS\
	--env-var keycloak-url=$KEYCLOAK_URL \
	--env-var mosip-id="$MOSIP_ID" \
	--env-var keycloak-admin-password=$KEYCLOAK_ADMIN_PASSWORD \
	--env-var keycloak-admin-username=$KEYCLOAK_ADMIN_USERNAME \
	--env-var cert-manager-username="$KEYCLOAK_CLIENT" \
    --env-var cert-manager-password="$KEYCLOAK_CLIENT_SECRET" \
	--env-var partner-domain=$PARTNER_DOMAIN \
	--env-var ca-certificate="$root_ca_cert" \
	--env-var leaf-certificate="$partner_cert" \
	--env-var oidc-client-name="$OIDC_CLIENT_NAME" \
	--env-var client-name-lang-map-json="$CLIENT_NAME_LANG_MAP_JSON" \
	--env-var additional-config-json="$ADDITIONAL_CONFIG_JSON" \
	--env-var oidc-clientid="$OIDC_CLIENTID" \
	--folder 'create_keycloak_user' \
	--folder 'create/publish_policy_group_and_policy' \
	--folder partner-self-registration \
	--folder authenticate-to-upload-certs \
	--folder authenticate-to-onboard-non-mosipid-client \
    --folder upload-ca-certificate \
    --folder upload-leaf-certificate \
    --folder activate-partner \
	--folder partner_request_mapping_to_policyname \
	--folder approve-partner-mapping-to-policy \
	--folder get-jwks \
	--folder create-oidc-client \
	--folder create-oidc-client-through-esignet \
	--folder delete-user \
    $ADD_SSL_NEWMAN \
    --export-environment ./config-secrets.json -d "$POLICY_DATA_FILE" -r cli,htmlextra --reporter-htmlextra-export "$reports_dir/mock-rp-oidc.html" --reporter-htmlextra-showEnvironmentData
privateandpublickeypair=$(jq -r '.values[] | select(.key == "privateandpublickeypair") | .value' config-secrets.json)
privateandpublickeypair=$(echo -n "$privateandpublickeypair" | base64)
mpartnerdefaultdemooidcclientID=$(jq -r '.values[] | select(.key == "oidc-client-id") | .value' "config-secrets.json")
}
onboard_resident_oidc_client() {
echo "Onboarding resident oidc client"
reports_dir="./reports/RESIDENT_OIDC/$current_datetime"
  mkdir -p "$reports_dir"
    sh $MYDIR/certs/create-jwks.sh
    if [ $? -gt 0 ]; then
      echo "JWK Key generation failed; EXITING";
      exit 1;
    fi
    echo "JWK Keys generated successfully"
    jwk_key=$(awk -F'"' '/"n"/ {print $8}' pubkey.jwk)
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --bail \
    --env-var url=$URL \
    --env-var authmanager-url=$AUTHMANAGER_URL \
    --env-var pms-url=$PMS_URL \
    --env-var request-time=$DATE \
	--env-var partner-manager-username=$PARTNER_MANAGER_USERNAME \
	--env-var partner-manager-password=$PARTNER_MANAGER_PASSWORD \
	--env-var application-id=$APPLICATION_ID \
	--env-var module-clientid=$MODULE_CLIENTID \
	--env-var module-secretkey=$MODULE_SECRETKEY \
	--env-var policy-group-name=$POLICY_GROUP_NAME \
	--env-var partner-kc-username=$PARTNER_KC_USERNAME \
	--env-var partner-organization-name=$PARTNER_ORGANIZATION_NAME \
    --env-var partner-type=$PARTNER_TYPE \
	--env-var partner-domain=$PARTNER_DOMAIN \
    --env-var external-url=$EXTERNAL_URL \
	--env-var policy-name=$POLICY_NAME \
	--env-var keycloak-url=$KEYCLOAK_URL \
	--env-var keycloak-admin-password=$KEYCLOAK_ADMIN_PASSWORD \
	--env-var keycloak-admin-username=$KEYCLOAK_ADMIN_USERNAME \
	--env-var cert-manager-username="$KEYCLOAK_CLIENT" \
    --env-var cert-manager-password="$KEYCLOAK_CLIENT_SECRET" \
	--env-var cert-application-id=$CERT_APPLICATION_ID \
    --env-var cert-reference-id=$CERT_REFERENCE_ID \
	--env-var key="$jwk_key" \
	--env-var oidc-client-name=$OIDC_CLIENT_NAME \
	--env-var client-name-lang-map-json="$CLIENT_NAME_LANG_MAP_JSON" \
	--env-var additional-config-json="$ADDITIONAL_CONFIG_JSON" \
	--env-var logo-uri=$LOGO_URI \
	--env-var redirect-uris=$REDIRECT_URIS \
	--folder 'create_keycloak_user' \
	--folder 'create/publish_policy_group_and_policy' \
	--folder partner-self-registration \
	--folder authenticate-as-cert-manager \
	--folder download-ca-certificate-from-keymanager \
	--folder download-intermediate-resident-certificate-from-keymanager \
    --folder download-leaf-certificate-from-keymanager \
	--folder authenticate-to-upload-certs \
    --folder upload-ca-certificate \
	--folder upload-intermediate-ca-certificate  \
    --folder upload-leaf-certificate \
	--folder partner_request_mapping_to_policyname \
	--folder approve-partner-mapping-to-policy \
	--folder login-to-keycloak-as-admin \
	--folder get-keyid-from-keymanager \
	--folder create-oidc-client \
	--folder delete-user \
	$ADD_SSL_NEWMAN \
    --export-environment ./config-secrets.json -d "$POLICY_DATA_FILE" -r cli,htmlextra --reporter-htmlextra-export "$reports_dir/resident-oidc.html" --reporter-htmlextra-showEnvironmentData
mpartnerdefaultresidentoidcclientID=$(jq -r '.values[] | select(.key == "oidc-client-id") | .value' "config-secrets.json")
}
onboard_mimoto_keybinding_partner(){
    echo "Onboarding Mimoto Keybinding partner"
    reports_dir="./reports/MIMOTO_KEYBINDING/$current_datetime"
  mkdir -p "$reports_dir"
	sh $MYDIR/certs/create-signing-certs.sh $MYDIR
	root_ca_cert=$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' $root_cert_path)
	partner_cert=$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' $client_cert_path)
	echo $root_ca_cert
	echo $partner_cert
	newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --bail \
  --env-var url="$URL" \
  --env-var authmanager-url=$AUTHMANAGER_URL \
  --env-var pms-url=$PMS_URL \
  --env-var request-time="$DATE" \
	--env-var partner-manager-username=$PARTNER_KC_USERNAME \
	--env-var partner-manager-password=$PARTNER_KC_USERPASSWORD \
	--env-var application-id=$APPLICATION_ID \
	--env-var module-clientid=$MODULE_CLIENTID \
	--env-var module-secretkey=$MODULE_SECRETKEY \
	--env-var policy-group-name=$POLICY_GROUP_NAME \
	--env-var partner-kc-username=$PARTNER_KC_USERNAME \
	--env-var partner-kc-userpassword=$PARTNER_KC_USERPASSWORD \
	--env-var partner-organization-name=$PARTNER_ORGANIZATION_NAME \
  --env-var partner-type=$PARTNER_TYPE \
  --env-var policy-name=$POLICY_NAME \
	--env-var keycloak-url=$KEYCLOAK_URL \
	--env-var keycloak-admin-password=$KEYCLOAK_ADMIN_PASSWORD \
	--env-var keycloak-admin-username=$KEYCLOAK_ADMIN_USERNAME \
	--env-var cert-manager-username="$KEYCLOAK_CLIENT" \
  --env-var cert-manager-password="$KEYCLOAK_CLIENT_SECRET" \
	--env-var partner-domain=$PARTNER_DOMAIN \
	--env-var ca-certificate="$root_ca_cert" \
	--env-var leaf-certificate="$partner_cert" \
	--folder 'create_keycloak_user' \
	--folder 'create/publish_policy_group_and_policy' \
	--folder partner-self-registration \
	--folder authenticate-to-upload-certs \
  --folder upload-ca-certificate \
  --folder upload-leaf-certificate \
	--folder partner_request_mapping_to_policyname \
	--folder approve-partner-mapping-to-policy \
	--folder authenticate-as-partner-for-api-key \
	--folder request-for-partner-apikey \
	--folder delete-user \
    $ADD_SSL_NEWMAN \
    --export-environment ./config-secrets.json -d "$POLICY_DATA_FILE" -r cli,htmlextra --reporter-htmlextra-export "$reports_dir/mimoto-keybinding.html" --reporter-htmlextra-showEnvironmentData
mpartnerdefaultmimotokeybindingapikey=$(jq -r '.values[] | select(.key == "mpartner-default-mimotokeybinding-apikey") | .value' "config-secrets.json")
}
onboard_mimoto_oidc_partner(){
    echo "Onboarding Mimoto OIDC partner"
    reports_dir="./reports/MIMOTO_OIDC/$current_datetime"
  mkdir -p "$reports_dir"
	sh $MYDIR/certs/create-signing-certs.sh $MYDIR
	root_ca_cert=$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' $root_cert_path)
	partner_cert=$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' $client_cert_path)
	sh $MYDIR/certs/convert.sh $MYDIR
	mv $MYDIR/certs/$PARTNER_KC_USERNAME/keystore.p12 $MYDIR/certs/$PARTNER_KC_USERNAME/oidckeystore.p12

	kubectl -n $custom_ns create secret generic mimotooidc --from-file=$MYDIR/certs/$PARTNER_KC_USERNAME/oidckeystore.p12 --dry-run=client -o yaml | kubectl apply -f -

	if [ $? -gt 0 ]; then
      echo "JWK Key generation failed; EXITING";
      exit 1;
    fi
    echo "JWK Keys generated successfully"
    jwk_key=$(awk -F'"' '/"n"/ {print $8}' $MYDIR/certs/$PARTNER_KC_USERNAME/publickey.jwk)
	echo $jwk_key
	newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --bail \
  --env-var url="$URL" \
  --env-var authmanager-url=$AUTHMANAGER_URL \
  --env-var pms-url=$PMS_URL \
  --env-var request-time="$DATE" \
	--env-var partner-manager-username=$PARTNER_KC_USERNAME \
	--env-var partner-manager-password=$PARTNER_KC_USERPASSWORD \
	--env-var logo-uri=$LOGO_URI \
	--env-var redirect-uris=$REDIRECT_URIS \
	--env-var application-id=$APPLICATION_ID \
	--env-var module-clientid=$MODULE_CLIENTID \
	--env-var module-secretkey=$MODULE_SECRETKEY \
	--env-var policy-group-name=$POLICY_GROUP_NAME \
	--env-var partner-kc-username=$PARTNER_KC_USERNAME \
	--env-var partner-kc-userpassword=$PARTNER_KC_USERPASSWORD \
	--env-var partner-organization-name=$PARTNER_ORGANIZATION_NAME \
  --env-var partner-type=$PARTNER_TYPE \
	--env-var key="$jwk_key" \
	--env-var keyid="" \
  --env-var policy-name=$POLICY_NAME \
	--env-var keycloak-url=$KEYCLOAK_URL \
	--env-var keycloak-admin-password=$KEYCLOAK_ADMIN_PASSWORD \
	--env-var keycloak-admin-username=$KEYCLOAK_ADMIN_USERNAME \
	--env-var cert-manager-username="$KEYCLOAK_CLIENT" \
  --env-var cert-manager-password="$KEYCLOAK_CLIENT_SECRET" \
	--env-var partner-domain=$PARTNER_DOMAIN \
	--env-var oidc-client-name="$OIDC_CLIENT_NAME" \
	--env-var client-name-lang-map-json="$CLIENT_NAME_LANG_MAP_JSON" \
	--env-var additional-config-json="$ADDITIONAL_CONFIG_JSON" \
	--env-var ca-certificate="$root_ca_cert" \
	--env-var leaf-certificate="$partner_cert" \
	--folder 'create_keycloak_user' \
	--folder 'create/publish_policy_group_and_policy' \
	--folder partner-self-registration \
	--folder authenticate-to-upload-certs \
  --folder upload-ca-certificate \
  --folder upload-leaf-certificate \
	--folder partner_request_mapping_to_policyname \
	--folder approve-partner-mapping-to-policy \
	--folder create-oidc-client \
	--folder delete-user \
    $ADD_SSL_NEWMAN \
  --export-environment ./config-secrets.json -d "$POLICY_DATA_FILE" -r cli,htmlextra --reporter-htmlextra-export "$reports_dir/mimoto-oidc.html" --reporter-htmlextra-showEnvironmentData
mpartnerdefaultmimotooidcclientID=$(jq -r '.values[] | select(.key == "oidc-client-id") | .value' "config-secrets.json")
}
onboard_esignet_signup_oidc_partner(){
    echo "Onboarding Esignet-signup OIDC partner"
    reports_dir="./reports/SIGNUP_OIDC/$current_datetime"
  mkdir -p "$reports_dir"
  sh $MYDIR/certs/create-signing-certs.sh $MYDIR
	root_ca_cert=$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' $root_cert_path)
	partner_cert=$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' $client_cert_path)
	sh $MYDIR/certs/convert.sh $MYDIR
  mv $MYDIR/certs/$PARTNER_KC_USERNAME/keystore.p12 $MYDIR/certs/$PARTNER_KC_USERNAME/oidckeystore.p12
	kubectl -n $ns_signup create secret generic signup-keystore --from-file=$MYDIR/certs/$PARTNER_KC_USERNAME/oidckeystore.p12 --dry-run=client -o yaml | kubectl apply -f -

	if [ $? -gt 0 ]; then
      echo "JWK Key generation failed; EXITING";
      exit 1;
    fi
    echo "JWK Keys generated successfully"
    jwk_key=$(awk -F'"' '/"n"/ {print $8}' $MYDIR/certs/$PARTNER_KC_USERNAME/publickey.jwk)

	newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --bail \
    --env-var url="$URL" \
    --env-var authmanager-url=$AUTHMANAGER_URL \
    --env-var external-url=$EXTERNAL_URL \
    --env-var request-time="$DATE" \
	--env-var logo-uri=$LOGO_URI \
	--env-var redirect-uris=$REDIRECT_URIS \
	--env-var application-id=$APPLICATION_ID \
	--env-var module-clientid=$MODULE_CLIENTID \
	--env-var module-secretkey=$MODULE_SECRETKEY \
	--env-var partner-kc-username=$PARTNER_KC_USERNAME \
	--env-var key="$jwk_key" \
	--env-var keyid="" \
	--env-var partner-manager-username=$PARTNER_MANAGER_USERNAME \
	--env-var partner-manager-password=$PARTNER_MANAGER_PASSWORD \
	--env-var keycloak-url=$KEYCLOAK_URL \
	--env-var keycloak-admin-password=$KEYCLOAK_ADMIN_PASSWORD \
	--env-var keycloak-admin-username=$KEYCLOAK_ADMIN_USERNAME \
	--env-var oidc-client-name="$OIDC_CLIENT_NAME" \
	--env-var oidc-clientid="$OIDC_CLIENTID" \
	--folder 'create_keycloak_user' \
	--folder authenticate-to-upload-certs \
	--folder keycloak-authentication-for-mock-plugin \
	--folder create-oidc-client-through-esignet-signup \
	--folder delete-user \
    $ADD_SSL_NEWMAN \
  --export-environment ./config-secrets.json  -r cli,htmlextra --reporter-htmlextra-export "$reports_dir/signup-oidc.html" --reporter-htmlextra-showEnvironmentData
}
## Script starts from here
export MYDIR=$(pwd)
DATE=$(date -u +%FT%T.%3NZ)
current_datetime=$(date -u +"%d-%m-%y-%H-%M"-UTC)

# Local/manual test runs only (outside a k8s Job, e.g. testing against a real env by hand):
# properties/local-test.properties can supply URL/KEYCLOAK_URL/EXTERNAL_URL/
# KEYCLOAK_ADMIN_USERNAME/KEYCLOAK_ADMIN_PASSWORD/KEYCLOAK_CLIENT_SECRET/
# mosip_pms_client_secret/mosip_deployment_client_secret directly, instead of the
# printenv-derived values below. This file is gitignored and never baked into the image -
# a real k8s Job never has it, so this is a no-op there and every value below computes
# exactly as before.
LOCAL_TEST_PROPS="${LOCAL_TEST_PROPS:-$MYDIR/properties/local-test.properties}"
if [ -f "$LOCAL_TEST_PROPS" ]; then
  echo "Loading local test properties from $LOCAL_TEST_PROPS"
  set -a
  . "$LOCAL_TEST_PROPS"
  set +a
fi

KEYCLOAK_URL="${KEYCLOAK_URL:-$(printenv keycloak-external-url)}"
KEYCLOAK_CLIENT="mosip-deployment-client"
KEYCLOAK_CLIENT_SECRET="${KEYCLOAK_CLIENT_SECRET:-$mosip_deployment_client_secret}"
echo "KEYCLOAK_CLIENT = $KEYCLOAK_CLIENT"
#echo "KEYCLOAK_CLIENT_SECRET = $KEYCLOAK_CLIENT_SECRET"
KEYCLOAK_ADMIN_USERNAME="${KEYCLOAK_ADMIN_USERNAME:-$(printenv KEYCLOAK_ADMIN_USER)}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-$(printenv admin-password)}"
echo " KEYCLOAK ADMIN USER : $KEYCLOAK_ADMIN_USERNAME"
#echo " KEYCLOAK ADMIN PASSWORD : $KEYCLOAK_ADMIN_PASSWORD"
URL="${URL:-https://$(printenv mosip-api-internal-host)}"
# idauthentication/keymanager live behind $URL. authmanager and partnermanager+policymanager
# (PMS) may each be on their own separate instance/host in more complex or cross-env setups -
# both default to the same host as $URL (single-domain deployments need no extra config),
# override AUTHMANAGER_URL/PMS_URL (properties/local-test.properties for a local run, or
# the equivalent env var for a real deployment) when either is actually on a different host.
AUTHMANAGER_URL="${AUTHMANAGER_URL:-$URL}"
PMS_URL="${PMS_URL:-$URL}"
EXTERNAL_URL="${EXTERNAL_URL:-https://$(printenv mosip-esignet-host)}"

echo "URL : $URL | AUTHMANAGER_URL : $AUTHMANAGER_URL | PMS_URL : $PMS_URL | EXTERNAL_URL : $EXTERNAL_URL"

if [ "$ENABLE_INSECURE" = "true" ]; then
  export HOST=$(printenv mosip-api-internal-host)
  if [ -z $HOST ]; then
    echo "Env variable mosip-api-internal-host not provided; EXITING;";
    exit 1;
  fi
  openssl s_client -servername "$HOST" -connect "$HOST":443  > "$MYDIR/$HOST.cer" 2>/dev/null & sleep 2 ;
  sed -i -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' "$MYDIR/$HOST.cer";
  cat "$MYDIR/$HOST.cer";

  export ADD_SSL_CURL="--cacert $MYDIR/$HOST.cer"
  export ADD_SSL_NEWMAN="--ssl-extra-ca-certs $MYDIR/$HOST.cer"
fi

# esignet-and-onward modules (esignet, mock-rp-oidc, resident-oidc, mimoto-keybinding,
# mimoto-oidc, signup-oidc) take every partner/policy/OIDC-client value from
# properties/<MODULE>.properties instead of a hardcoded shell variable below. On a
# duplicate/network/cert error, edit that file (or the override below) and rerun - nothing
# here tries to recover from a bad value automatically. Modules before esignet (ida, print,
# resident, abis, mobileid, digitalcard) have no properties file and are configured inline
# below, unchanged.
PROPERTIES_DIR="${PROPERTIES_DIR:-$MYDIR/properties}"
PROPS_FILE="$PROPERTIES_DIR/${MODULE}.properties"
if [ -f "$PROPS_FILE" ]; then
  echo "Loading properties for module '$MODULE' from $PROPS_FILE"
  set -a
  . "$PROPS_FILE"
  set +a
fi

# Optional per-deployment override, e.g. a ConfigMap mounted here by the
# partner-onboarder chart's onboarding.propertiesOverride value - only the keys present
# in this file take effect, everything else keeps the baked-in default above.
PROPERTIES_OVERRIDE_DIR="${PROPERTIES_OVERRIDE_DIR:-$MYDIR/properties/overrides}"
PROPS_OVERRIDE_FILE="$PROPERTIES_OVERRIDE_DIR/${MODULE}.properties"
if [ -f "$PROPS_OVERRIDE_FILE" ]; then
  echo "Loading property overrides for module '$MODULE' from $PROPS_OVERRIDE_FILE"
  set -a
  . "$PROPS_OVERRIDE_FILE"
  set +a
fi

# esignet-onward modules create a throwaway Keycloak user (PARTNER_MANAGER_USERNAME, or
# for mimoto-keybinding/mimoto-oidc the partner itself, PARTNER_KC_USERNAME, acting as its
# own manager) that normally gets deleted as the last step of a successful run. Register
# an EXIT trap now, before that user gets created, so it's always cleaned up even if the
# run fails/bails partway through - see delete_keycloak_user_if_exists() above.
KC_MOCK_USER_TO_CLEANUP="${PARTNER_MANAGER_USERNAME:-$PARTNER_KC_USERNAME}"
if [ -n "$KC_MOCK_USER_TO_CLEANUP" ]; then
  trap 'delete_keycloak_user_if_exists "$KC_MOCK_USER_TO_CLEANUP" "$KEYCLOAK_URL" "$KEYCLOAK_ADMIN_USERNAME" "$KEYCLOAK_ADMIN_PASSWORD"' EXIT
fi

# create-oidc-client's clientNameLangMap/additionalConfig (PMS's V3 OIDC-client fields) -
# raw JSON provided as-is via CLIENT_NAME_LANG_MAP/ADDITIONAL_CONFIG in properties/<MODULE>.properties.
# Default to {} (empty object), not null: dev2's PMS (ClientManagementServiceImpl.createOIDCClientV2)
# NPEs on a null clientNameLangMap ("Cannot invoke Map.put because clientNameMap is null") -
# the DTO has no @NotNull on this field, but the real implementation doesn't null-check it
# before using it, so null isn't actually safe there despite what the DTO alone suggests.
# additionalConfig IS properly null-guarded server-side, but {} is a no-op for it too, so
# defaulting both the same way is simpler and avoids relying on that distinction holding.
if [ -z "$CLIENT_NAME_LANG_MAP" ]; then
  CLIENT_NAME_LANG_MAP_JSON='{}'
else
  CLIENT_NAME_LANG_MAP_JSON="$CLIENT_NAME_LANG_MAP"
fi
if [ -z "$ADDITIONAL_CONFIG" ]; then
  ADDITIONAL_CONFIG_JSON='{}'
else
  ADDITIONAL_CONFIG_JSON="$ADDITIONAL_CONFIG"
fi

# esignet/mock-rp-oidc/resident-oidc/mimoto-keybinding/mimoto-oidc all write their onboarding
# result (client ID, keys, API key) into the live cluster afterward - creating/patching a
# secret the real service reads, and for mock-rp-oidc, restarting that service so it picks
# up the new client. Set SYNC_LIVE_DEPLOYMENT=false (in properties/<MODULE>.properties or an
# override) to skip that for a one-off/local/test run that shouldn't touch anything already
# running - the onboarding result still lands in config-secrets.json and the html report.
# Defaults to true (unchanged behavior) so existing real deployments aren't affected.
SYNC_LIVE_DEPLOYMENT="${SYNC_LIVE_DEPLOYMENT:-true}"

if [ "$MODULE" = "ida" ]; then
  upload_ida_root_cert
  upload_ida_cert
  upload_ida_partner_cert
  upload_ida_cred_cert
elif [ "$MODULE" = "print" ]; then
  upload_print_cert
elif [ "$MODULE" = "resident" ]; then
  upload_resident_cert
elif [ "$MODULE" = "abis" ]; then
  upload_abis_cert
elif [ "$MODULE" = "mobileid" ]; then
  upload_mpartner_default_mobile_cert
elif [ "$MODULE" = "digitalcard" ]; then
  upload_mpartner_default_digitalcard_cert
elif [ "$MODULE" = "esignet" ]; then
  MODULE_SECRETKEY=$mosip_pms_client_secret
  onboard_esignet_partner
  if [ "$SYNC_LIVE_DEPLOYMENT" != "false" ]; then
    kubectl create secret generic esignet-misp-onboarder-key -n $ns_esignet --from-literal=mosip-esignet-misp-key=$MISP_LICENSE_KEY --dry-run=client -o yaml | kubectl apply -f -
  fi
elif [ "$MODULE" = "mock-rp-oidc" ]; then
  MODULE_SECRETKEY=$mosip_pms_client_secret
  LOGO_URI="${LOGO_URI:-https://healthservices.$( printenv installation-domain)/logo.png}"
  REDIRECT_URIS="${REDIRECT_URIS:-https://healthservices.$( printenv installation-domain)/userprofile}"
  root_cert_path="$MYDIR/certs/$PARTNER_KC_USERNAME/RootCA.pem"
  client_cert_path="$MYDIR/certs/$PARTNER_KC_USERNAME/Client.pem"
  onboard_mock_relying_party_with_mock_rp_oidc_client
  if [ "$SYNC_LIVE_DEPLOYMENT" != "false" ]; then
    kubectl patch secret mock-relying-party-private-key-jwk -n $ns_esignet -p '{"data":{"client-private-key":"'$(echo -n "$privateandpublickeypair" | base64 | tr -d '\n')'"}}'
    kubectl rollout restart deployment -n $ns_esignet mock-relying-party-service
    kubectl -n $ns_esignet set env deployment/mock-relying-party-ui CLIENT_ID=$mpartnerdefaultdemooidcclientID
  fi
elif [ "$MODULE" = "resident-oidc" ]; then
  MODULE_SECRETKEY=$mosip_pms_client_secret
  LOGO_URI="${LOGO_URI:-https://$( printenv mosip-resident-host )/assets/MOSIP%20Vertical%20Black.png}"
  REDIRECT_URIS="${REDIRECT_URIS:-https://$( printenv mosip-api-internal-host )/resident/v1/login-redirect/**}"
  onboard_resident_oidc_client
  if [ "$SYNC_LIVE_DEPLOYMENT" != "false" ]; then
    kubectl create secret generic resident-oidc-onboarder-key -n $ns_esignet --from-literal=resident-oidc-clientid=$mpartnerdefaultresidentoidcclientID --dry-run=client -o yaml | kubectl apply -f -
  fi
  elif [ "$MODULE" = "mimoto-keybinding" ]; then
  MODULE_SECRETKEY=$mosip_pms_client_secret
  custom_ns=$( printenv customnamespace )
  root_cert_path="$MYDIR/certs/$PARTNER_KC_USERNAME/RootCA.pem"
  client_cert_path="$MYDIR/certs/$PARTNER_KC_USERNAME/Client.pem"
  onboard_mimoto_keybinding_partner
  if [ "$SYNC_LIVE_DEPLOYMENT" != "false" ]; then
    kubectl create secret generic mimoto-wallet-binding-partner-api-key -n $custom_ns --from-literal=mimoto-wallet-binding-partner-api-key=$mpartnerdefaultmimotokeybindingapikey --dry-run=client -o yaml | kubectl apply -f -
  fi
  elif [ "$MODULE" = "mimoto-oidc" ]; then
  MODULE_SECRETKEY=$mosip_pms_client_secret
  root_cert_path="$MYDIR/certs/$PARTNER_KC_USERNAME/RootCA.pem"
  client_cert_path="$MYDIR/certs/$PARTNER_KC_USERNAME/Client.pem"
  custom_ns=$( printenv customnamespace )
  LOGO_URI="${LOGO_URI:-https://$( printenv mosip-api-host )/inji/inji-home-logo.png}"
  REDIRECT_URIS="${REDIRECT_URIS:-io.mosip.residentapp.inji://oauthredirect,https://inji.$( printenv installation-domain).mosip.net/redirect}"
  onboard_mimoto_oidc_partner
  if [ "$SYNC_LIVE_DEPLOYMENT" != "false" ]; then
    kubectl create secret generic mimoto-oidc-partner-clientid -n $custom_ns --from-literal=mimoto-oidc-partner-clientid=$mpartnerdefaultmimotooidcclientID --dry-run=client -o yaml | kubectl apply -f -
  fi
  elif [ "$MODULE" = "signup-oidc" ]; then
  MODULE_SECRETKEY=$mosip_pms_client_secret
  root_cert_path="$MYDIR/certs/$PARTNER_KC_USERNAME/RootCA.pem"
  client_cert_path="$MYDIR/certs/$PARTNER_KC_USERNAME/Client.pem"
  LOGO_URI="${LOGO_URI:-https://healthservices.$( printenv installation-domain)/images/brand_logo.png}"
  REDIRECT_URIS="${REDIRECT_URIS:-https://signup.$( printenv installation-domain)/identity-verification}"
  onboard_esignet_signup_oidc_partner
fi
