#!/usr/bin/env bash
set -e

# 1. Generate Root CA Private Key (4096-bit RSA)
openssl genrsa -out fedmitigate-root-ca.key 4096

# 2. Root CA Config
cat << 'EOCFG' > ca.cnf
[ req ]
default_bits        = 4096
prompt              = no
default_md          = sha256
distinguished_name  = req_distinguished_name
x509_extensions     = v3_ca

[ req_distinguished_name ]
C                   = US
ST                  = Virginia
L                   = Reston
O                   = FedMitigate LLC
OU                  = FedMitigate Certificate Authority
CN                  = FedMitigate Root Certification Authority

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
EOCFG

# 3. Create Root CA Certificate (valid for 20 years)
openssl req -x509 -new -nodes -key fedmitigate-root-ca.key -sha256 -days 7300 -out fedmitigate-root-ca.crt -config ca.cnf

# 4. Generate Code Signing Private Key
openssl genrsa -out fedmitigate-codesign.key 4096

# 5. Code Signing CSR Config
cat << 'EOCFG' > codesign.cnf
[ req ]
default_bits        = 4096
prompt              = no
default_md          = sha256
distinguished_name  = req_distinguished_name
req_extensions      = v3_req

[ req_distinguished_name ]
C                   = US
ST                  = Virginia
L                   = Reston
O                   = FedMitigate LLC
OU                  = Security & Cryptographic Operations
CN                  = FedMitigate LLC

[ v3_req ]
basicConstraints    = critical, CA:FALSE
keyUsage            = critical, digitalSignature
extendedKeyUsage    = critical, codeSigning, 1.3.6.1.5.5.7.3.3
subjectKeyIdentifier = hash
EOCFG

# 6. Create CSR
openssl req -new -key fedmitigate-codesign.key -out fedmitigate-codesign.csr -config codesign.cnf

# 7. Sign Code Signing Certificate with Root CA (valid for 10 years)
cat << 'EOCFG' > v3_ext.cnf
basicConstraints    = critical, CA:FALSE
keyUsage            = critical, digitalSignature
extendedKeyUsage    = critical, codeSigning, 1.3.6.1.5.5.7.3.3
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOCFG

openssl x509 -req -in fedmitigate-codesign.csr -CA fedmitigate-root-ca.crt -CAkey fedmitigate-root-ca.key -CAcreateserial -out fedmitigate-codesign.crt -days 3650 -sha256 -extfile v3_ext.cnf

# 8. Create full chain file
cat fedmitigate-codesign.crt fedmitigate-root-ca.crt > fedmitigate-chain.crt

# 9. Create PKCS#12 bundle (password: fedmitigate)
openssl pkcs12 -export -out fedmitigate-codesign.p12 -inkey fedmitigate-codesign.key -in fedmitigate-codesign.crt -certfile fedmitigate-root-ca.crt -password pass:fedmitigate

# 10. Convert certificates to Windows-native DER format (.cer)
openssl x509 -in fedmitigate-codesign.crt -outform DER -out FedMitigate-LLC-CodeSigning.cer
openssl x509 -in fedmitigate-root-ca.crt -outform DER -out FedMitigate-Root-CA.cer

echo "Certificate generation complete."
