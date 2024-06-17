/*
 * Project Name: Script Verification Service
 * Filename: verify.c
 *
 * Copyright © 2024 Mohamad Mansouri
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "debug.h"
#include "verify.h"
#include "server.h"
#include "cert_utils.h"

int decode_signature(unsigned char* decoded_signature, const char* signature, size_t signature_size)
{
    EVP_ENCODE_CTX* encoding_ctx = NULL;
    int decoded_signature_size;

    /* Create context for decoding signature from base64 */
    encoding_ctx = EVP_ENCODE_CTX_new();
    if (!encoding_ctx) 
    {
        PRINT_ERROR_DEBUG(debug, "Cannot create context for decoding signature");
        return -1;
    }

    /* Convert signature from base64 to binary */
    EVP_DecodeInit(encoding_ctx);
    
    if(EVP_DecodeUpdate(encoding_ctx, decoded_signature, &decoded_signature_size, (const unsigned char *)signature, signature_size) < 0)
    {
        PRINT_ERROR_DEBUG(debug, "Decoding signature failed in EVP_DecodeUpdate");
        EVP_ENCODE_CTX_free(encoding_ctx);
        return -1;
    }

    int d;
    if(EVP_DecodeFinal(encoding_ctx, decoded_signature, &d) < 0)
    {
        PRINT_ERROR_DEBUG(debug, "Decoding signature failed in EVP_DecodeFinal");
        EVP_ENCODE_CTX_free(encoding_ctx);
        return -1;
    }

    EVP_ENCODE_CTX_free(encoding_ctx);
    return decoded_signature_size;

}

int verify_signature(cert_container_t* certs, signed_script_t* signed_script)
{
    EVP_MD_CTX* digest_ctx = NULL;
    unsigned char decoded_signature[MAX_SIGNATURE_SIZE];
    int decoded_signature_size;
    int ret = VERIFY_SIGNATURE_ERROR;

    signed_script->valid = VERIFY_SIGNATURE_INVALID; // reset because signed_script struct might be reused

    /* Decode the signature */
    decoded_signature_size = decode_signature(decoded_signature, signed_script->signature, signed_script->signature_size);
    if(decoded_signature_size <= 0)
    {
        PRINT_ERROR("Decoding signature failed");
        return VERIFY_SIGNATURE_ERROR;
    }

    for(cert_container_t* cert_curr = certs; cert_curr != NULL; cert_curr = cert_curr->next)
    {
        /* Create context for verifying signature */
        digest_ctx = EVP_MD_CTX_new();
        if (!digest_ctx) 
        {
            PRINT_ERROR("Cannot create context for digest");
            return VERIFY_SIGNATURE_ERROR;
        }

        /* Initialize context with the chosen digest algorithm */
        /* Note that we use X509_get0_pubkey so no need to free the returned public key */
        if (!EVP_DigestVerifyInit(digest_ctx, NULL, EVP_sha256(), NULL, X509_get0_pubkey(cert_curr->cert))) 
        {
            PRINT_ERROR_DEBUG(debug, "Cannot initialize verification context for certificate %s", cert_curr->name);
            EVP_MD_CTX_free(digest_ctx);
            continue;
        }

        /* Update the context with the script contents */
        if (!EVP_DigestVerifyUpdate(digest_ctx, signed_script->script, signed_script->script_size)) 
        {
            PRINT_ERROR_DEBUG(debug, "Cannot update verification context for certificate %s", cert_curr->name);
            EVP_MD_CTX_free(digest_ctx);
            continue;
        }

        /* Verify the signature */
        int ret_verification = EVP_DigestVerifyFinal(digest_ctx, decoded_signature, decoded_signature_size);


        if (1 == ret_verification) 
        {
            PRINT_DEBUG(debug, "The signature is validated under certificate %s", cert_curr->name);
            signed_script->valid = VERIFY_SIGNATURE_VALID; // set for redundency check
            EVP_MD_CTX_free(digest_ctx);
            /* If the signature is validated by one certificate, return immediately with VALID */
            return VERIFY_SIGNATURE_VALID;
        } 
        else if (0 == ret_verification) 
        {
            PRINT_WARN_DEBUG(debug, "The signature cannot be validated with with certificate %s", cert_curr->name);
            ret = VERIFY_SIGNATURE_INVALID;
            EVP_MD_CTX_free(digest_ctx);
            continue;
        } 
        else 
        {
            PRINT_WARN_DEBUG(debug, "Error occured while verifying with certificate %s", cert_curr->name);
            EVP_MD_CTX_free(digest_ctx);
            continue;
        }
    }

    /* If signature cannot be validated and at least one certificate gives invalid signature on verification, 
       the function returns INVALID otherwise, it returns ERROR */
    return ret;

}
