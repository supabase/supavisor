#!/usr/bin/env bash
set -euo pipefail

CERTS_DIR="$(dirname "$0")/../priv/test/certs"
mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

# CA (RSA 2048)
openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.crt \
  -days 3650 -nodes -subj "/CN=Supavisor Test CA"

SAN="subjectAltName=DNS:localhost"

# RSA server cert
openssl req -newkey rsa:2048 -keyout server_rsa.key -out server_rsa.csr \
  -nodes -subj "/CN=localhost"
openssl x509 -req -in server_rsa.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server_rsa.crt -days 3650 -extfile <(echo "$SAN")

# ECDSA server cert (prime256v1)
openssl ecparam -genkey -name prime256v1 -out server_ecdsa.key
openssl req -new -key server_ecdsa.key -out server_ecdsa.csr -subj "/CN=localhost"
openssl x509 -req -in server_ecdsa.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server_ecdsa.crt -days 3650 -extfile <(echo "$SAN")

# v2 CA (RSA 2048), served to SNI hostname v2.localhost
openssl req -x509 -newkey rsa:2048 -keyout ca_v2.key -out ca_v2.crt \
  -days 3650 -nodes -subj "/CN=Supavisor Test CA v2"

SAN_V2="subjectAltName=DNS:v2.localhost"

# v2 RSA server cert
openssl req -newkey rsa:2048 -keyout server_v2_rsa.key -out server_v2_rsa.csr \
  -nodes -subj "/CN=v2.localhost"
openssl x509 -req -in server_v2_rsa.csr -CA ca_v2.crt -CAkey ca_v2.key \
  -CAcreateserial -out server_v2_rsa.crt -days 3650 -extfile <(echo "$SAN_V2")

# v2 ECDSA server cert (prime256v1)
openssl ecparam -genkey -name prime256v1 -out server_v2_ecdsa.key
openssl req -new -key server_v2_ecdsa.key -out server_v2_ecdsa.csr -subj "/CN=v2.localhost"
openssl x509 -req -in server_v2_ecdsa.csr -CA ca_v2.crt -CAkey ca_v2.key \
  -CAcreateserial -out server_v2_ecdsa.crt -days 3650 -extfile <(echo "$SAN_V2")

# Backward compat: server.{crt,key} = RSA copies
cp server_rsa.crt server.crt
cp server_rsa.key server.key

# Cleanup CSRs and serial
rm -f *.csr *.srl

echo "All certificates generated successfully."
