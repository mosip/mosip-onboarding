#!/bin/bash
# Onboards default partners
## Usage: ./install.sh [kubeconfig]

if [ $# -ge 1 ] ; then
  export KUBECONFIG=$1

fi
echo "Do you have public domain & valid SSL? (Y/n) "
echo "Y: if you have public domain & valid ssl certificate"
echo "n: If you don't have a public domain and a valid SSL certificate. Note: It is recommended to use this option only in development environments."
read -p "" flag

if [ -z "$flag" ]; then
  echo "'flag' was not provided; EXITING;"
  exit 1;
fi

ENABLE_INSECURE=''
if [ "$flag" = "n" ]; then
  ENABLE_INSECURE='--set onboarding.configmaps.onboarding.ENABLE_INSECURE=true'
fi

NS=onboarder
CHART_VERSION=0.0.1-develop
echo Create $NS namespace

kubectl create ns $NS
function installing_onboarder() {
  read -p "Is values.yaml for onboarder chart set correctly as part of Pre-requisites?(Y/n) " yn;
  if [ "$yn" = "Y" ]; then
    NFS_OPTION=''
    S3_OPTION=''
    config_complete=false  # flag to check if S3 or NFS is configured
    while [ "$config_complete" = false ]; do
      read -p "Do you have S3 details for storing Onboarder reports? (Y/n) : " ans
      if [[ "$ans" == "y" || "$ans" == "Y" ]]; then
        read -p "Please provide S3 host: " s3_host
        if [[ -z $s3_host ]]; then
          echo "S3 host not provided; EXITING;"
          exit 1;
        fi
        read -p "Please provide S3 region: " s3_region
        if [[ $s3_region == *[' !@#$%^&*()+']* ]]; then
          echo "S3 region should not contain spaces or special characters; EXITING;"
          exit 1;
        fi
        read -p "Please provide S3 bucket: " s3_bucket
        if [[ $s3_bucket == *[' !@#$%^&*()+']* ]]; then
          echo "S3 bucket should not contain spaces or special characters; EXITING;"
          exit 1;
        fi
        read -p "Please provide S3 access key: " s3_user_key
        if [[ -z $s3_user_key ]]; then
          echo "S3 access key not provided; EXITING;"
          exit 1;
        fi
        read -p "Please provide S3 secret key: " s3_secret_key
        if [[ -z $s3_secret_key ]]; then
          echo "S3 secret key not provided; EXITING;"
          exit 1;
        fi
        S3_OPTION="--set onboarding.secrets.s3.s3-user-secret=$s3_secret_key --set onboarding.configmaps.s3.s3-host=$s3_host --set onboarding.configmaps.s3.s3-user-key=$s3_user_key --set onboarding.configmaps.s3.s3-region=$s3_region --set onboarding.configmaps.s3.s3-bucket-name=$s3_bucket"
        push_reports_to_s3=true
        config_complete=true
      elif [[ "$ans" == "n" || "$ans" == "N" ]]; then
        push_reports_to_s3=false
        read -p "Since S3 details are not available, do you want to use NFS directory mount for storing reports? (y/n) : " answer
        if [[ $answer == "Y" ]] || [[ $answer == "y" ]]; then
          read -p "Please provide NFS Server IP: " nfs_server
          if [[ -z $nfs_server ]]; then
            echo "NFS server not provided; EXITING."
            exit 1;
          fi
          read -p "Please provide NFS directory to store reports from NFS server (e.g. /srv/nfs/mosip/<sandbox>/onboarder/), make sure permission is 777 for the folder: " nfs_path
          if [[ -z $nfs_path ]]; then
            echo "NFS Path not provided; EXITING."
            exit 1;
          fi
          NFS_OPTION="--set onboarding.volumes.reports.nfs.server=$nfs_server --set onboarding.volumes.reports.nfs.path=$nfs_path"
          config_complete=true
        else
          echo "Please rerun the script with either S3 or NFS server details."
          exit 1;
        fi
      else
        echo "Invalid input. Please respond with Y (yes) or N (no)."
      fi
    done

    echo Istio label
    kubectl label ns $NS istio-injection=disabled --overwrite
    helm repo update

    echo Copy configmaps
    kubectl -n $NS --ignore-not-found=true delete cm s3
    kubectl -n $NS --ignore-not-found=true delete cm onboarder-namespace
    sed -i 's/\r$//' copy_cm.sh

    ./copy_cm.sh
    echo Copy secrets

    sed -i 's/\r$//' copy_secrets.sh
    ./copy_secrets.sh
    echo Onboarding default partners

    helm -n $NS install partner-onboarder mosip/partner-onboarder \
      $NFS_OPTION \
      $S3_OPTION \
      --set onboarding.variables.push_reports_to_s3=$push_reports_to_s3 \
      $ENABLE_INSECURE \
      -f values.yaml \
      --wait \
      --wait-for-jobs \
      --version $CHART_VERSION

    echo "Reports are moved to S3 under onboarder bucket"

    echo "Please follow the steps as mentioned in the document link below to configure mimoto-keybinding-partner:"
    BRANCH_NAME=$(git symbolic-ref --short HEAD)
    GITHUB_URL="https://github.com/mosip/mosip-infra/blob"
    FILE_PATH="/deployment/v3/mosip/partner-onboarder/README.md"
    FULL_URL="$GITHUB_URL/$BRANCH_NAME$FILE_PATH#configuration"
    echo -e "\e[1m\e[4m\e[34m\e]8;;$FULL_URL\a$FULL_URL\e]8;;\a\e[0m"
    echo -e "\e[1mHave you completed the changes mentioned in the onboarding document? (y/n)\e[0m"
    read answer
    if [[ "$answer" =~ [yY](es)* ]]; then
      echo -e "\e[1m\e[32mPartners onboarded successfully.\e[0m"
    else
      echo -e "\e[1m\e[31mPartner onboarding steps are pending. Please complete the configuration steps for onboarding partner.\e[0m"
    fi
    return 0
  fi
}
# set commands for error handling.
set -e
set -o errexit
set -o nounset
set -o errtrace
set -o pipefail
installing_onboarder
