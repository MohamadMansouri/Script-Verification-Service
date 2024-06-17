#!/bin/bash

mkdir -p ../keys
mkdir -p ../certificates

# Generate RSA 4096 key
openssl genpkey -algorithm RSA -out ../keys/rsa_4096.key -pkeyopt rsa_keygen_bits:4096

# Generate RSA 2048 key
openssl genpkey -algorithm RSA -out ../keys/rsa_2048.key -pkeyopt rsa_keygen_bits:2048

# Generate DSA 2048 key
openssl genpkey -genparam -algorithm DSA -out dsaparam.pem -pkeyopt pbits:2048 -pkeyopt qbits:224 -pkeyopt digest:SHA256 -pkeyopt gindex:1 -text
openssl genpkey -paramfile dsaparam.pem -out ../keys/dsa_2048.key
rm dsaparam.pem

# Generate EDDSA key on curve 448
openssl genpkey -algorithm ED448 -out ../keys/eddsa_448.key

# Create configuration file for the certificates
cat > cert_config.cnf <<EOL
[ req ]
default_bits       = 2048
distinguished_name = req_distinguished_name
x509_extensions    = v3_req
prompt             = no

[ req_distinguished_name ]
C  = US
ST = State
L  = City
O  = Organization
OU = Unit
CN = www.anything.com

[ v3_req ]
keyUsage = critical, digitalSignature
extendedKeyUsage = codeSigning
EOL

# Create configuration file for the certificate without Key Usage and Extended Key Usage
cat > cert_config_no_usage.cnf <<EOL
[ req ]
default_bits       = 2048
distinguished_name = req_distinguished_name
prompt             = no

[ req_distinguished_name ]
C  = US
ST = State
L  = City
O  = Organization
OU = Unit
CN = www.anything.com
EOL

# Function to generate self-signed certificate
generate_self_signed_cert() {
  local key_file=$1
  local cert_file=$2
  local digest=$3

  openssl req -new -x509 -key $key_file -out $cert_file -days 365 -$digest -config cert_config.cnf
}

# Generate self-signed certificates
generate_self_signed_cert ../keys/rsa_4096.key ../certificates/rsa_4096_sha256_cert.pem sha256
generate_self_signed_cert ../keys/rsa_2048.key ../certificates/rsa_2048_sha512_cert.pem sha512
generate_self_signed_cert ../keys/dsa_2048.key ../certificates/dsa_2048_sha512_cert.pem sha256
generate_self_signed_cert ../keys/eddsa_448.key ../certificates/eddsa_448_sha256_cert.pem sha256

# Generate a certificate signed by rsa_4096_sha256_cert.pem
openssl req -new -key ../keys/rsa_2048.key -out rsa_2048_csr.pem -config cert_config.cnf
openssl x509 -req -in rsa_2048_csr.pem -CA ../certificates/rsa_4096_sha256_cert.pem -CAkey ../keys/rsa_4096.key -CAcreateserial -out ../certificates/rsa_2048_signed_by_rsa_4096_cert.pem -days 365 -sha256 -extfile cert_config.cnf -extensions v3_req

# Generate a certificate without Key Usage and Extended Key Usage
openssl req -new -x509 -key ../keys/rsa_2048.key -out ../certificates/rsa_2048_no_usage_cert.pem -days 365 -sha256 -config cert_config_no_usage.cnf

# Clean up
rm rsa_2048_csr.pem
rm cert_config.cnf cert_config_no_usage.cnf
rm ../certificates/*.srl

echo "Keys have been generated in the '../keys' directory."
echo "Certificates have been generated in the '../certificates' directory."
