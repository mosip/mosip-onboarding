#!/usr/bin/env bash
# warning: do not use the certificates produced by this tool in production. This is for testing purposes only
# This is reference script.

path=$1
PROP_FILE=$path/onboarding.properties

function prop {
    grep "${1}" ${PROP_FILE}|cut -d'=' -f2
}

partner_name=$(prop 'partner-kc-username')
pname=$(echo ${partner_name^})
country=$(prop 'Country')
state=$(prop 'State')
locality=$(prop 'Locality')
orgnisation=$(prop 'partner-org-name')
email_id=$(prop 'partner-kc-user-email')
common_name=$pname
keystore_passowrd=$(prop 'keystore-passowrd')

echo "updating conf"
sed -i 's/\(^C =\).*/\1 '$country'/' $path/certs/root-openssl.cnf
sed -i 's/\(^ST =\).*/\1 '$state'/' $path/certs/root-openssl.cnf
sed -i 's/\(^L =\).*/\1 '$locality'/' $path/certs/root-openssl.cnf
sed -i 's/\(^O =\).*/\1 '$orgnisation'/' $path/certs/root-openssl.cnf
sed -i 's/\(^emailAddress =\).*/\1 '$email_id'/' $path/certs/root-openssl.cnf
sed -i 's/\(^CN =\).*/\1 '$common_name'-Root/' $path/certs/root-openssl.cnf

sed -i 's/\(^C =\).*/\1 '$country'/' $path/certs/client-openssl.cnf
sed -i 's/\(^ST =\).*/\1 '$state'/' $path/certs/client-openssl.cnf
sed -i 's/\(^L =\).*/\1 '$locality'/' $path/certs/client-openssl.cnf
sed -i 's/\(^O =\).*/\1 '$orgnisation'/' $path/certs/client-openssl.cnf
sed -i 's/\(^emailAddress =\).*/\1 '$email_id'/' $path/certs/client-openssl.cnf
sed -i 's/\(^CN =\).*/\1 '$common_name'-Client/' $path/certs/client-openssl.cnf

cert_path=$path/certs/$partner_name

if [ -d "$cert_path" ]
then
    echo "Directory $cert_path exists. Skipping cert creation"
else
  mkdir -p $cert_path
  ## certificate authority
  echo "==================== Creating CA certificate"
  openssl genrsa -out $cert_path/RootCA.key 4096
  openssl req -x509 -new -key $cert_path/RootCA.key -sha256 -days 1825 -out $cert_path/RootCA.pem -config $path/certs/root-openssl.cnf


##Partner certificate
  echo "==================== Creating partner certificate"
  openssl genrsa -out $cert_path/Client.key 4096
  openssl req -new -key $cert_path/Client.key -out $cert_path/Client.csr -config $path/certs/client-openssl.cnf
  openssl x509 -req -days 1825 -extensions v3_req -extfile $path/certs/client-openssl.cnf -in $cert_path/Client.csr -CA $cert_path/RootCA.pem -CAkey $cert_path/RootCA.key -CAcreateserial -out $cert_path/Client.pem

  openssl pkcs12 -export -in $cert_path/Client.pem -inkey $cert_path/Client.key -out $cert_path/keystore.p12 -name $partner_name -password pass:$keystore_passowrd

  echo "Cert generation complete"$'\n'

fi

