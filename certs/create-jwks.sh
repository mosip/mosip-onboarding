#!/usr/bin/env bash

#get date
date=$(date --utc +%FT%T.%3NZ)
AUTHMANAGER_URL="https://$(printenv mosip-api-internal-host)"
KEYMANAGER_URL="https://$(printenv mosip-api-internal-host)"
KEYCLOAK_CLIENT_ID=mosip-deployment-client
KEYCLOAK_CLIENT_SECRET="$mosip_deployment_client_secret"
AUTH_APP_ID=partner
#rm -rf temp.txt result.txt pubkey.pem cert.pem

echo -e "\n Generating JWKS Keys \n";
echo "AUTHMANAGER URL : $AUTHMANAGER_URL"
echo "KEYMANAGER URL : $KEYMANAGER_URL"

#echo "* Request for authorization"
curl $ADD_SSL_CURL -s -D - -o /dev/null -X "POST" \
  "$AUTHMANAGER_URL/v1/authmanager/authenticate/clientidsecretkey" \
  -H "accept: */*" \
  -H "Content-Type: application/json" \
  -d '{
  "id": "string",
  "version": "string",
  "requesttime": "'$date'",
  "metadata": {},
  "request": {
    "clientId": "'$KEYCLOAK_CLIENT_ID'",
    "secretKey": "'$KEYCLOAK_CLIENT_SECRET'",
    "appId": "'$AUTH_APP_ID'"
  }
}' > temp.txt 2>&1 &

sleep 10
TOKEN=$( cat temp.txt | awk '/[aA]uthorization:/{print $2}' | sed -E 's/\n//g' | sed -E 's/\r//g')

if [[ -z $TOKEN ]]; then
  echo "Unable to Authenticate with authmanager. \"TOKEN\" is empty; EXITING";
  exit 1;
fi

echo -e "\nGot Authorization token from authmanager"

curl $ADD_SSL_CURL -X "GET" \
  -H "Accept: application/json" \
  --cookie "Authorization=$TOKEN" \
  "$KEYMANAGER_URL/v1/keymanager/getCertificate?applicationId=RESIDENT&referenceId=" > result.txt

RESPONSE_COUNT=$( cat result.txt | jq .response )
if [[ -z $RESPONSE_COUNT ]]; then
  echo "Unable to \"response\" read result.txt file; EXITING";
  exit 1;
fi

if [[ $RESPONSE_COUNT == null || -z $RESPONSE_COUNT ]]; then
  echo "No response from keymanager server; EXITING";
  exit 1;
fi

RESULT=$(cat result.txt)
CERT=$(echo $RESULT | sed 's/.*certificate\":\"//gi' | sed 's/\".*//gI')

if [[ -z $CERT ]]; then
  echo "Unable to read certificate from result.txt; EXITING";
  exit 1;
fi

echo $CERT >input.cer
sed 's/\\n/\n/g' input.cer > ./input.pem
# Replace CERTIFICATE_FILE with the path to your certificate file
CERTIFICATE_FILE=./input.pem

# Extract the public key from the certificate in PEM format
openssl x509 -in "${CERTIFICATE_FILE}" -pubkey -noout > pubkey.pem

# Convert the PEM public key to JWK format using the pem-jwk tool
#npm install -g pem-jwk
pem-jwk pubkey.pem > ./pubkey.jwk
rm input.cer input.pem pubkey.pem result.txt temp.txt

# Output the resulting JWK to the console
cat pubkey.jwk