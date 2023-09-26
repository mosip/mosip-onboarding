#!/bin/bash
path=$1
partner_name=$( printenv PARTNER_KC_USERNAME ) 
cert_path=$path/certs/$partner_name


keystore_file=$cert_path/keystore.p12

# Prompt for keystore password
keystore_password=$(cat key.pwd)


openssl pkcs12 -in "$keystore_file" -clcerts -nokeys -out temp.pem -passin pass:"$keystore_password"
openssl x509 -in temp.pem -out output.cer
rm temp.pem

echo "User certificate exported successfully to output.cer"

# Convert newline escape sequences to actual newlines
sed 's/\\n/\n/g' output.cer > input.pem

# Extract the public key from the certificate in PEM format
CERTIFICATE_FILE=./input.pem
openssl x509 -in "${CERTIFICATE_FILE}" -pubkey -noout > pubkey.pem

# Convert the PEM public key to JWK format using the pem-jwk tool
#npm install -g pem-jwk
pem-jwk pubkey.pem > ./publickey.jwk
cat publickey.jwk
mv ./publickey.jwk $cert_path/publickey.jwk

# Clean up temporary files
rm input.pem pubkey.pem

echo "Public key converted to JWK format and saved as pubkey.jwk"
