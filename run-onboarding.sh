#!/usr/bin/env bash

PROP_FILE=./onboarding.properties
function prop {
    grep "${1}=" ${PROP_FILE}|cut -d'=' -f2
}

mkdir -p $(prop 'report_dir') $(prop 'tmp_dir')

mydir="$(pwd)"
echo $mydir
env_temp_file=$(prop 'tmp_dir')
#get date

function update_props() {
    date=$(date --utc +%FT%T.%3NZ)
    env_url=$(prop 'env-url')
    keycloak_url=$(prop 'keycloak-url')
    keycloak_admin_username=$(prop 'keycloak-admin-username')
    keycloak_admin_password=$(prop 'keycloak-admin-password')
    partner_kc_username=$(prop 'partner-kc-username')
    partner_kc_userpassword=$(prop 'partner-kc-userpassword')
    partner_kc_user_firstname=$(prop 'partner-kc-user-firstname')
    partner_kc_user_lastname=$(prop 'partner-kc-user-lastname')
    partner_kc_user_email=$(prop 'partner-kc-user-email')
    partner_org_name=$(prop 'partner-org-name')
    partner_kc_user_role=$(prop 'partner-kc-user-role')
    partner_manager_username=$(prop 'partner-manager-username')
    partner_manager_password=$(prop 'partner-manager-password')
    application_id=$(prop 'application-id')
    policy_group_name=$(prop 'policy-group-name')
    policy_name=$(prop 'policy-name')
    policy_type=$(prop 'policy-type')
    partner_type=$(prop 'partner-type')
    partner_address=$(prop 'partner-address')
    partner_contact=$(prop 'partner-contact')
    partner_domain=$(prop 'partner-domain')
    credential_type=$(prop 'credential-type')
    cert_manager_username=$(prop 'cert-manager-username')
    cert_manager_password=$(prop 'cert-manager-password')

    root_cert_path="$mydir/certs/$partner_kc_username/RootCA.pem"
    client_cert_path="$mydir/certs/$partner_kc_username/Client.pem"

#
    echo "Copying properties to env variables."$'\n'
    jq '.values |= map(if .key=="request-time" then (.value="'$date'") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="url" then (.value="'$env_url'") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="keycloak-url" then (.value="'$keycloak_url'") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="keycloak-admin-username" then (.value="'$keycloak_admin_username'") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="keycloak-admin-password" then (.value="'$keycloak_admin_password'") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="partner-kc-username" then (.value="'$partner_kc_username'") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="partner-kc-user-firstname" then (.value="'$partner_kc_user_firstname'") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="partner-kc-user-lastname" then (.value="'$partner_kc_user_lastname'") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="partner-kc-user-email" then (.value="'$partner_kc_user_email'") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="partner-organization-name" then (.value="'$partner_org_name'") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="partner-kc-userpassword" then (.value="'$partner_kc_userpassword'") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="partner-kc-user-role" then (.value="'$partner_kc_user_role'") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="partner-manager-username" then (.value="'$partner_manager_username'") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="partner-manager-password" then (.value="'$partner_manager_password'") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="application-id" then (.value="'$application_id'") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="policy-group-name" then (.value="'$policy_group_name'") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="policy-name" then (.value="'$policy_name'") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="policy-type" then (.value="'$policy_type'") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="partner-type" then (.value="'$partner_type'") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="partner-address" then (.value="'$partner_address'") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="partner-contact" then (.value="'$partner_contact'") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="partner-domain" then (.value="'$partner_domain'") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="credential-type" then (.value="'$credential_type'") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="cert-manager-username" then (.value="'$cert_manager_username'") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="cert-manager-password" then (.value="'$cert_manager_password'") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    echo "Completed copying properties"$'\n'
}

function create_partner() {

    echo -e "\e[31m************Please select option based on your requirement.******************\e[0m \n \
    Press 0 : If you want to upload default certificates. \n \
    Press 1 : If you want to onboard Auth_Partner domain.\n \
    Press 2 : If you want to onboard Credential_Partner domain.  \n \
    Press 3 : If you want to onboard Misp_Partner domain. \n \
    Press 4 : If you want to onboard Device_Provider domain. \n \
    Press 5 : If you want to onboard Online_Verification_Partner domain. \n \
    Press 6 : If you want to onboard Manual_Adjudication domain. \n \
    Press 7 : If you want to onboard FTM_Provider domain. \n \
    Press 8 : If you want to onboard ABIS_Partner domain. \n \
    Press 9 : If you want to onboard Print_Partner domain. \n \
    Press 10 : If you want to connect with MOSIP Team. \n"

    read -p 'Enter Choice: ' choice
    if [[ -z "${choice}" ]]; then
        echo "\e[31m Input cannot be blank please try again.\e[0m  \n"
        exit 0
    else
        if ! [[ "${choice}" =~ ^[+-]?[0-9]+\.?[0-9]*$ ]]; then
            echo "\e[31m Input must be a numbers.\e[0m  \n"
            exit 1
        fi
    fi


    case ${choice} in
    0)
    update_props
    echo "upload default certs" $'\n'

    echo "uploading root cert" $'\n'
    jq '.values |= map(if .key=="cert-application-id" then (.value="ROOT") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="cert-reference-id" then (.value="NULL") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --export-environment $env_temp_file/onboarding.postman_environment.json \
    --folder authenticate-to-download-certs \
    --folder download-ida-certificate \
    --folder upload-ca-certificate \
    -r htmlextra --reporter-htmlextra-export $(prop 'report_dir')/IDA-Root.html
    rm $env_temp_file/*

    echo "uploading ida cert" $'\n'
    jq '.values |= map(if .key=="cert-application-id" then (.value="IDA") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="cert-reference-id" then (.value="NULL") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --export-environment $env_temp_file/onboarding.postman_environment.json \
    --folder authenticate-to-download-certs \
    --folder download-ida-certificate \
    --folder upload-ca-certificate \
    -r htmlextra --reporter-htmlextra-export $(prop 'report_dir')/IDA-CA.html
    rm $env_temp_file/*

    echo "uploading mpartner default auth cert" $'\n'
    jq '.values |= map(if .key=="cert-application-id" then (.value="IDA") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="cert-reference-id" then (.value="mpartner-default-auth") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="partner-kc-username" then (.value="mpartner-default-auth") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --export-environment $env_temp_file/onboarding.postman_environment.json \
    --folder authenticate-to-download-certs \
    --folder download-ida-certificate \
    --folder upload-leaf-certificate \
    --folder upload-signed-leaf-certifcate-to-keymanager \
    -r htmlextra --reporter-htmlextra-export $(prop 'report_dir')/mpartner-default-auth.html
    rm $env_temp_file/*

    echo "uploading ida cred cert" $'\n'
    jq '.values |= map(if .key=="cert-application-id" then (.value="IDA") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="cert-reference-id" then (.value="CRED_SERVICE") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --export-environment $env_temp_file/onboarding.postman_environment.json \
    --folder authenticate-to-download-certs \
    --folder download-ida-certificate \
    -r htmlextra --reporter-htmlextra-export $(prop 'report_dir')/cred-service.html

    jq '.values |= map(if .key=="cert-reference-id" then (.value="PUBLIC_KEY") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --export-environment $env_temp_file/onboarding.postman_environment.json \
    --folder authenticate-to-download-certs \
    --folder upload-other-domain-certificate-to-keymanager \
    -r htmlextra --reporter-htmlextra-export $(prop 'report_dir')/public-key.html
    rm $env_temp_file/*

    echo "uploading mpartner default resident cert" $'\n'
    jq '.values |= map(if .key=="cert-application-id" then (.value="RESIDENT") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="cert-reference-id" then (.value="mpartner-default-resident") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="partner-kc-username" then (.value="mpartner-default-resident") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --export-environment $env_temp_file/onboarding.postman_environment.json \
    --folder authenticate-to-download-certs \
    --folder download-ca-certificate-from-keymanager \
    --folder download-leaf-certificate-from-keymanager \
    --folder upload-ca-certificate \
    --folder upload-leaf-certificate \
    --folder upload-signed-leaf-certifcate-to-keymanager \
    -r htmlextra --reporter-htmlextra-export $(prop 'report_dir')/mapartner-default-resident.html
    rm $env_temp_file/*

    echo "uploading mpartner default print cert" $'\n'
    root_cert_path="$mydir/certs/print/RootCA.pem"
    client_cert_path="$mydir/certs/print/Client.pem"
    RootCACert=$(awk 'NF {sub(/\r/, ""); printf "%s\\r\\n",$0;}' $root_cert_path)
    PartnerCert=$(awk 'NF {sub(/\r/, ""); printf "%s\\r\\n",$0;}' $client_cert_path)
    jq '.values |= map(if .key=="partner-kc-username" then (.value="mpartner-default-print") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --export-environment $env_temp_file/onboarding.postman_environment.json \
    --folder authenticate-to-upload-certs \
    --env-var ca-certificate="$RootCACert" \
    --env-var leaf-certificate="$PartnerCert" \
    --folder upload-ca-certificate \
    --folder upload-leaf-certificate \
    -r htmlextra --reporter-htmlextra-export $(prop 'report_dir')/mapartner-default-print.html
    rm $env_temp_file/*

    echo "uploading mpartner default abis cert" $'\n'
    root_cert_path="$mydir/certs/abis/RootCA.pem"
    client_cert_path="$mydir/certs/abis/Client.pem"
    RootCACert=$(awk 'NF {sub(/\r/, ""); printf "%s\\r\\n",$0;}' $root_cert_path)
    PartnerCert=$(awk 'NF {sub(/\r/, ""); printf "%s\\r\\n",$0;}' $client_cert_path)
    jq '.values |= map(if .key=="partner-kc-username" then (.value="mpartner-default-abis") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --export-environment $env_temp_file/onboarding.postman_environment.json \
    --folder authenticate-to-upload-certs \
    --env-var ca-certificate="$RootCACert" \
    --env-var leaf-certificate="$PartnerCert" \
    --folder upload-ca-certificate \
    --folder upload-leaf-certificate \
    -r htmlextra --reporter-htmlextra-export $(prop 'report_dir')/mapartner-default-abis.html
    rm $env_temp_file/*
    ;;

    1)
    update_props
    bash $mydir/certs/create-signing-certs.sh $mydir
    RootCACert=$(awk 'NF {sub(/\r/, ""); printf "%s\\r\\n",$0;}' $root_cert_path)
    PartnerCert=$(awk 'NF {sub(/\r/, ""); printf "%s\\r\\n",$0;}' $client_cert_path)
    echo "Starting Auth Partner Creation" $'\n'
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --export-environment $env_temp_file/onboarding.postman_environment.json \
    --folder 'create_keycloak_user' \
    --folder 'create/publish_policy_group_and_policy' \
    --folder 'partner_self_registration' \
    --folder authenticate-to-upload-certs \
    --env-var ca-certificate="$RootCACert" \
    --env-var leaf-certificate="$PartnerCert" \
    --folder upload-ca-certificate \
    --folder upload-leaf-certificate \
    --folder 'partner_request_for_mapping_partner_to_policy' \
    --folder authenticate-as-partner-manager \
    --folder approve-partner-mapping-to-policy \
    --folder 'request_for_partner_api_key' \
    -d default-auth-policy.json -r htmlextra --reporter-htmlextra-export $(prop 'report_dir')/$partner_kc_username.html

    rm $env_temp_file/*
    ;;

    2)
    update_props
    bash $mydir/certs/create-signing-certs.sh $mydir
    RootCACert=$(awk 'NF {sub(/\r/, ""); printf "%s\\r\\n",$0;}' $root_cert_path)
    PartnerCert=$(awk 'NF {sub(/\r/, ""); printf "%s\\r\\n",$0;}' $client_cert_path)
    echo "Starting Credential Partner Creation" $'\n'
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --export-environment $env_temp_file/onboarding.postman_environment.json \
    --folder 'create_keycloak_user' \
    --folder 'create/publish_policy_group_and_policy' \
    --folder 'partner_self_registration' \
	--folder authenticate-to-upload-certs \
	--env-var ca-certificate="$RootCACert" \
	--env-var leaf-certificate="$PartnerCert" \
	--folder upload-ca-certificate \
	--folder upload-leaf-certificate \
	--folder 'partner_request_for_mapping_partner_to_policy' \
	--folder authenticate-as-partner-manager \
	--folder mapping-partner-to-policy-credential-type \
	--folder adding-bioextractors-for-partner \
    -d default-datashare-policy.json -r htmlextra --reporter-htmlextra-export $(prop 'report_dir')/$partner_kc_username.html

    rm $env_temp_file/*
    ;;

    3)
    update_props
    bash $mydir/certs/create-signing-certs.sh $mydir
    RootCACert=$(awk 'NF {sub(/\r/, ""); printf "%s\\r\\n",$0;}' $root_cert_path)
    PartnerCert=$(awk 'NF {sub(/\r/, ""); printf "%s\\r\\n",$0;}' $client_cert_path)
    echo "Starting MISP Partner Creation" $'\n'
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --export-environment $env_temp_file/onboarding.postman_environment.json \
    --folder 'create_keycloak_user' \
    --folder 'partner_self_registration' \
    --folder authenticate-to-upload-certs \
    --env-var ca-certificate="$RootCACert" \
    --env-var leaf-certificate="$PartnerCert" \
    --folder upload-ca-certificate \
    --folder upload-leaf-certificate \
    --folder create-the-MISP-license-key-for-partner \
    -r htmlextra --reporter-htmlextra-export $(prop 'report_dir')/$partner_kc_username.html

    rm $env_temp_file/*
    ;;

    4)
    update_props
    bash $mydir/certs/create-signing-certs.sh $mydir
    RootCACert=$(awk 'NF {sub(/\r/, ""); printf "%s\\r\\n",$0;}' $root_cert_path)
    PartnerCert=$(awk 'NF {sub(/\r/, ""); printf "%s\\r\\n",$0;}' $client_cert_path)
    echo "Starting Device Provider Partner Creation" $'\n'
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --export-environment $env_temp_file/onboarding.postman_environment.json \
    --folder 'create_keycloak_user' \
    --folder 'partner_self_registration' \
    --folder authenticate-to-upload-certs \
    --env-var ca-certificate="$RootCACert" \
    --env-var leaf-certificate="$PartnerCert" \
    --folder upload-ca-certificate \
    --folder upload-leaf-certificate \
    -r htmlextra --reporter-htmlextra-export $(prop 'report_dir')/$partner_kc_username.html

    rm $env_temp_file/*
    ;;

    5)
    update_props
    echo "Starting online-verification-partner creation" $'\n'
    jq '.values |= map(if .key=="cert-application-id" then (.value="IDA") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json
    jq '.values |= map(if .key=="cert-reference-id" then (.value="'$partner_kc_username'") else . end)' onboarding.postman_environment.json > $(prop 'tmp_dir')/tmp.json && mv $(prop 'tmp_dir')/tmp.json onboarding.postman_environment.json

    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --export-environment $env_temp_file/onboarding.postman_environment.json \
    --folder 'create_keycloak_user' \
    --folder 'create/publish_policy_group_and_policy' \
    --folder 'partner_self_registration' \
    --folder authenticate-to-download-certs \
    --folder download-ida-certificate \
    --folder upload-leaf-certificate \
    --folder upload-signed-leaf-certificate \
    --folder 'partner_request_for_mapping_partner_to_policy' \
    --folder authenticate-as-partner-manager \
    --folder adding-bioextractors-for-partner \
    --folder approve-partner-mapping-to-policy \
    --folder 'request_for_partner_api_key' \
    -d default-datashare-policy.json -r htmlextra --reporter-htmlextra-export $(prop 'report_dir')/$partner_kc_username.html

    rm $env_temp_file/*
    ;;

    6)
    update_props
    bash $mydir/certs/create-signing-certs.sh $mydir
    RootCACert=$(awk 'NF {sub(/\r/, ""); printf "%s\\r\\n",$0;}' $root_cert_path)
    PartnerCert=$(awk 'NF {sub(/\r/, ""); printf "%s\\r\\n",$0;}' $client_cert_path)
    echo "Starting Manual_Adjudication partner Creation" $'\n'
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --export-environment $env_temp_file/onboarding.postman_environment.json \
    --folder 'create_keycloak_user' \
    --folder 'create/publish_policy_group_and_policy' \
    --folder 'partner_self_registration' \
    --folder authenticate-to-upload-certs \
    --env-var ca-certificate="$RootCACert" \
    --env-var leaf-certificate="$PartnerCert" \
    --folder upload-ca-certificate \
    --folder upload-leaf-certificate \
    --folder 'partner_request_for_mapping_partner_to_policy' \
    --folder authenticate-as-partner-manager \
    --folder approve-partner-mapping-to-policy \
    --folder 'request_for_partner_api_key' \
    -d default-datashare-policy.json -r htmlextra --reporter-htmlextra-export $(prop 'report_dir')/$partner_kc_username.html

    rm $env_temp_file/*
    ;;

    7)update_props
    bash $mydir/certs/create-signing-certs.sh $mydir
    RootCACert=$(awk 'NF {sub(/\r/, ""); printf "%s\\r\\n",$0;}' $root_cert_path)
    PartnerCert=$(awk 'NF {sub(/\r/, ""); printf "%s\\r\\n",$0;}' $client_cert_path)
    echo "Starting FTM_Provider Partner Creation" $'\n'
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --export-environment $env_temp_file/onboarding.postman_environment.json \
    --folder 'create_keycloak_user' \
    --folder 'partner_self_registration' \
    --folder authenticate-to-upload-certs \
    --env-var ca-certificate="$RootCACert" \
    --env-var leaf-certificate="$PartnerCert" \
    --folder upload-ca-certificate \
    --folder upload-leaf-certificate \
    -r htmlextra --reporter-htmlextra-export $(prop 'report_dir')/$partner_kc_username.html

    rm $env_temp_file/*
    ;;


    8)
    update_props
    bash $mydir/certs/create-signing-certs.sh $mydir
    RootCACert=$(awk 'NF {sub(/\r/, ""); printf "%s\\r\\n",$0;}' $root_cert_path)
    PartnerCert=$(awk 'NF {sub(/\r/, ""); printf "%s\\r\\n",$0;}' $client_cert_path)
    echo "Starting ABIS_Partner Creation" $'\n'
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --export-environment $env_temp_file/onboarding.postman_environment.json \
    --folder 'create_keycloak_user' \
    --folder 'create/publish_policy_group_and_policy' \
    --folder 'partner_self_registration' \
    --folder authenticate-to-upload-certs \
    --env-var ca-certificate="$RootCACert" \
    --env-var leaf-certificate="$PartnerCert" \
    --folder upload-ca-certificate \
    --folder upload-leaf-certificate \
    --folder 'partner_request_for_mapping_partner_to_policy' \
    --folder authenticate-as-partner-manager \
    --folder adding-bioextractors-for-partner \
    -d default-datashare-policy.json -r htmlextra --reporter-htmlextra-export $(prop 'report_dir')/$partner_kc_username.html

    rm $env_temp_file/*
    ;;

    9)
    update_props
    bash $mydir/certs/create-signing-certs.sh $mydir
    RootCACert=$(awk 'NF {sub(/\r/, ""); printf "%s\\r\\n",$0;}' $root_cert_path)
    PartnerCert=$(awk 'NF {sub(/\r/, ""); printf "%s\\r\\n",$0;}' $client_cert_path)
    echo "Starting Print_Partner Creation" $'\n'
    newman run onboarding.postman_collection.json --delay-request 2000 -e onboarding.postman_environment.json --export-environment $env_temp_file/onboarding.postman_environment.json \
    --folder 'create_keycloak_user' \
    --folder 'create/publish_policy_group_and_policy' \
    --folder 'partner_self_registration' \
    --folder authenticate-to-upload-certs \
    --env-var ca-certificate="$RootCACert" \
    --env-var leaf-certificate="$PartnerCert" \
    --folder upload-ca-certificate \
    --folder upload-leaf-certificate \
    --folder 'partner_request_for_mapping_partner_to_policy' \
    --folder authenticate-as-partner-manager \
    --folder mapping-partner-to-policy-credential-type \
    --folder adding-bioextractors-for-partner \
    -d default-datashare-policy.json -r htmlextra --reporter-htmlextra-export $(prop 'report_dir')/$partner_kc_username.html

    rm $env_temp_file/*
    ;;

    10)
    echo -e "\e[31m\e[1m\e[5m**Please email on below email id. \e[25m\e[21m We will revert back to you with the solution.\e[0m  \n"
    echo "info@mosip.io"
    echo "Thanks for connecting with us. !!!Have a Good day"
    ;;
    esac

    echo "Your partner registered successfully. Please check the report for any issue"$'\n'
    read -p $'Do you want to register any other partner? (y/n): ' want
    if [[ ("$want" = "Y") || ("$want" = "y") ]]; then
        echo "Okay. Please change the properties for new partner and select the appropriate option"$'\n'
        read -rsn1 -p $"Have you updated properties for partner. Press any key to continue or Ctrl+C to stop."$'\n'
        create_partner
    else
        echo "Thank you for registering with MOSIP"$'\n'
        exit
    fi
}

echo -e "\e[31m\e[1m\e[5m**NOTE: \e[25m\e[21m This script is used to on-board different partners type available in MOSIP. You will be asked to provide few inputs initialy please accept accordingly.\e[0m  \n"
read -p $"Do you agree to install newman and its libraries? Please read docs in case of any issue. Press (y/n):  "$'\n' agree
if [[ ("$agree" = "Y") || ("$agree" = "y") ]]; then
   npm install -g newman -y
   npm install -g newman-reporter-htmlextra -y
else
   echo "Skipping installation. Please check requirement"$'\n'
fi
read -rsn1 -p $"Please make sure that you set the properties carefully. Press any key to continue or Ctrl+C to stop."$'\n'
create_partner
