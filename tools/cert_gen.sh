#!/bin/bash

cat > x509_config.cfg <<EOT
[req]
req_extensions = client_auth
distinguished_name = req_distinguished_name

[req_distinguished_name]

[ client_auth ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOT

# Generate private key and certificate (public key). Note: The comman name must be device id.
openssl req -new -x509 -nodes -days 365 -newkey ec:<(openssl ecparam -name secp384r1) -keyout privkey.pem -out cert.pem -config x509_config.cfg -subj "/CN=ecc_cert"

# Convert format from key to der.
# openssl ec -outform der -in privkey.pem -out privkey.der

# Convert format from cert pem to der.
openssl x509 -outform der -in cert.pem -out cert.der
xxd -i cert.der > ../issue_107/cert.h