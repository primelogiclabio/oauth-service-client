#!/usr/bin/env bash
# Regenerates the throwaway TLS and key fixtures used by the tests (valid 10 years).
# Needs openssl and a JDK keytool. Run from this directory:  bash generate.sh
# Nothing here is used outside the tests; the password for every .p12 is "changeit".
set -euo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash on Windows: keep "/CN=..." subjects as typed
KEYTOOL="${KEYTOOL:-keytool}"
DAYS=3650
rm -f ./*.crt ./*.key ./*.p12 ./*.csr ./*.srl ./*.ext

# Extension files (process substitution does not work with every openssl build)
echo "subjectAltName=DNS:localhost,IP:127.0.0.1" > server.ext
echo "extendedKeyUsage=serverAuth" >> server.ext
echo "extendedKeyUsage=clientAuth" > client.ext

# Test CA
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days $DAYS \
  -subj "/CN=oauth-service-client test CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"

# Server certificate for localhost (HTTPS stub server and Keycloak)
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days $DAYS -extfile server.ext
openssl pkcs12 -export -in server.crt -inkey server.key -certfile ca.crt -name server -out server.p12 -passout pass:changeit

# Client certificate issued by the CA (mutual TLS, or the certificate behind a private_key_jwt signing key)
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/O=oauth-service-client tests/CN=test-client"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days $DAYS -extfile client.ext
cat client.crt ca.crt > client-chain.crt
openssl pkcs12 -export -in client.crt -inkey client.key -certfile ca.crt -name client -out client.p12 -passout pass:changeit
# The same key as PKCS#1 ("RSA PRIVATE KEY"), the form DocuSign hands out
openssl rsa -in client.key -traditional -out client-pkcs1.key

# Self-signed EC client certificate
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout self-signed-client.key \
  -out self-signed-client.crt -days $DAYS -subj "/CN=self-signed-client" -addext "extendedKeyUsage=clientAuth"

# SEC1 EC key ("EC PARAMETERS" + "EC PRIVATE KEY"), as openssl ecparam writes it
openssl ecparam -name prime256v1 -genkey -out ec-sec1.key

# Trust store holding only the test CA
"$KEYTOOL" -importcert -noprompt -alias test-ca -file ca.crt -keystore ca-truststore.p12 -storetype PKCS12 -storepass changeit

rm -f ./*.csr ./*.srl ./*.ext ca.key   # the CA key is only needed while issuing
echo "TLS fixtures regenerated."
