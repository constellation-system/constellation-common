#!/bin/sh

CAS_DIR=test/data/certs
CONFIG_FILE=${CAS_DIR}/openssl.cnf
SERVER_CA_DIR=${CAS_DIR}/server
CLIENT_CA_DIR=${CAS_DIR}/client
EC_CURVE=secp384r1

mkdir -p ${SERVER_CA_DIR}
mkdir -p ${SERVER_CA_DIR}/certs
mkdir -p ${SERVER_CA_DIR}/crl
mkdir -p ${SERVER_CA_DIR}/private
mkdir -p ${SERVER_CA_DIR}/reqs

# Generate server CA cert

openssl ecparam -out ${SERVER_CA_DIR}/ca_key.pem -name ${EC_CURVE} -genkey
openssl req -config ${CONFIG_FILE} -new -key ${SERVER_CA_DIR}/ca_key.pem \
    -x509 -utf8 -nodes -days 36500 -reqexts v3_CA -extensions v3_CA \
    -out ${SERVER_CA_DIR}/ca_cert.pem \
    -subj "/C=US/O=Constellation/OU=Tests/CN=Test Server CA"

# Generate server cert

openssl ecparam -out ${SERVER_CA_DIR}/private/test_server_key.pem \
    -name ${EC_CURVE} -genkey

openssl req -new -utf8 -key ${SERVER_CA_DIR}/private/test_server_key.pem \
    -nodes -out ${SERVER_CA_DIR}/reqs/test_server_req.pem \
    -subj "/C=US/O=Constellation/OU=Tests/CN=test-server.nowhere.com" \

EXTFILE=`mktemp`
echo "basicConstraints=CA:FALSE" >> ${EXTFILE}
echo "subjectKeyIdentifier=hash" >> ${EXTFILE}
echo "keyUsage=digitalSignature" >> ${EXTFILE}
echo "subjectAltName=DNS:test-server.nowhere.com" >> ${EXTFILE}

openssl x509 -req -sha384 -in ${SERVER_CA_DIR}/reqs/test_server_req.pem \
    -out ${SERVER_CA_DIR}/certs/test_server_cert.pem \
    -CA ${SERVER_CA_DIR}/ca_cert.pem -CAcreateserial \
    -CAkey ${SERVER_CA_DIR}/ca_key.pem -days 18250 \
    -extfile ${EXTFILE}

rm ${EXTFILE}

mkdir -p ${CLIENT_CA_DIR}
mkdir -p ${CLIENT_CA_DIR}/certs
mkdir -p ${CLIENT_CA_DIR}/crl
mkdir -p ${CLIENT_CA_DIR}/private
mkdir -p ${CLIENT_CA_DIR}/reqs

# Generate client CA cert

openssl ecparam -out ${CLIENT_CA_DIR}/ca_key.pem -name ${EC_CURVE} -genkey
openssl req -config ${CONFIG_FILE} -new -key ${CLIENT_CA_DIR}/ca_key.pem \
    -x509 -nodes -days 36500 -extensions v3_CA -reqexts v3_client \
    -out ${CLIENT_CA_DIR}/ca_cert.pem \
    -subj "/C=US/O=Constellation/OU=Tests/CN=Test Client CA"

# Generate client cert

openssl ecparam -out ${CLIENT_CA_DIR}/private/test_client_key.pem \
    -name ${EC_CURVE} -genkey

openssl req -new -utf8 -key ${CLIENT_CA_DIR}/private/test_client_key.pem \
    -nodes -out ${CLIENT_CA_DIR}/reqs/test_client_req.pem \
    -subj "/C=US/O=Constellation/OU=Tests/CN=test-client.nowhere.com" \

EXTFILE=`mktemp`
echo "basicConstraints=CA:FALSE" >> ${EXTFILE}
echo "subjectKeyIdentifier=hash" >> ${EXTFILE}
echo "keyUsage=digitalSignature" >> ${EXTFILE}
echo "subjectAltName=DNS:test-client.nowhere.com" >> ${EXTFILE}

openssl x509 -req -sha384 -in ${CLIENT_CA_DIR}/reqs/test_client_req.pem \
    -out ${CLIENT_CA_DIR}/certs/test_client_cert.pem \
    -CA ${CLIENT_CA_DIR}/ca_cert.pem -CAcreateserial \
    -CAkey ${CLIENT_CA_DIR}/ca_key.pem -days 18250 \
    -extfile ${EXTFILE}

rm ${EXTFILE}
