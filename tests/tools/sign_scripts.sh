#!/bin/bash

tmpsigraw=/tmp/signature.sha256
tmpsigtxt=/tmp/signature.sha256.txt

script_path=../scripts
keys_path=../keys

# Function to sign a script with a specific key
generate_signed_script() {
    openssl dgst -sha256 -sign $keys_path/$1.key -out $tmpsigraw $script_path/$2.sh
    base64 -w 0 $tmpsigraw > $tmpsigtxt
    echo >> $tmpsigtxt
    cat $script_path/$2.sh >> $tmpsigtxt
    cp $tmpsigtxt $script_path/$2.sh.signed
}

generate_signed_script rsa_4096 script
generate_signed_script dsa_2048 script_long_input
generate_signed_script rsa_2048 script_long_output