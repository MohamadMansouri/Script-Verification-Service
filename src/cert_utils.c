/*
 * Project Name: Script Verification Service
 * Filename: cert_utils.c
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
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <dirent.h>

#include "cert_utils.h"
#include "debug.h"

/* Function to read a PEM certificate */
X509* read_pem_cert(const char *certfile) 
{
    FILE *fp = fopen(certfile, "r");
    if (!fp) {
        PRINT_ERROR_DEBUG(debug, "Unable to open as a PEM certificate file");
        perror("");
        return NULL;
    }
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    return cert;
}

/* Function to read a DER certificate */
X509* read_der_cert(const char *certfile) 
{
    FILE *fp = fopen(certfile, "rb");
    if (!fp) {
        PRINT_ERROR_DEBUG(debug, "Unable to open as a DER certificate file");
        return NULL;
    }
    X509 *cert = d2i_X509_fp(fp, NULL);
    fclose(fp);
    return cert;
}

/* Function to read the certificate, trying PEM first, then DER */
X509* read_cert(const char *certfile) 
{
    X509 *cert = read_pem_cert(certfile);
    if (cert == NULL) {
        cert = read_der_cert(certfile);
    }
    return cert;
}

/* Free up all memory located for certificates */
void cleanup_certs(cert_container_t** certs)
{
    cert_container_t* cert_curr = *certs;
    cert_container_t* cert_next = NULL;
    while(NULL != cert_curr)
    {
        X509_free(cert_curr->cert);
        cert_next = cert_curr->next;
        free(cert_curr);
        cert_curr = cert_next;
    }
}

int validate_selfsigned_cert(X509* cert)
{
    int result;
    EVP_PKEY *pub_key = X509_get_pubkey(cert);
    if(!pub_key)
    {
        return NOT_SELFSIGNED;
    }

    result = X509_verify(cert, pub_key);
    EVP_PKEY_free(pub_key);

    if(1 == result)
    {
        return IS_SELFSIGNED;
    }
    return NOT_SELFSIGNED;
}

int validate_codesigning_cert(X509* cert)
{
    int valid1 = INVALID_CERTIFICATE;
    int valid2 = INVALID_CERTIFICATE;

    /* Verify the Key Usage includes digitalSignature */
    ASN1_BIT_STRING *usage = X509_get_ext_d2i(cert, NID_key_usage, NULL, NULL);
    if (usage) 
    {
        if(ASN1_BIT_STRING_get_bit(usage, 0)) // digitalSignature is bit 0
        {
            valid1 = VALID_CERTIFICATE;
        }
        ASN1_BIT_STRING_free(usage);
    }

    /* Verify the Extended Key Usage includes codeSigning */
    STACK_OF(ASN1_OBJECT) *ext_key_usage = (STACK_OF(ASN1_OBJECT) *)X509_get_ext_d2i(cert, NID_ext_key_usage, NULL, NULL);
    if (ext_key_usage) 
    {
        int num = sk_ASN1_OBJECT_num(ext_key_usage);
        for (int i = 0; i < num; i++) 
        {
            ASN1_OBJECT *obj = sk_ASN1_OBJECT_value(ext_key_usage, i);
            if (OBJ_obj2nid(obj) == NID_code_sign) 
            {
                valid2 = VALID_CERTIFICATE;
                break;
            }
        }
        sk_ASN1_OBJECT_pop_free(ext_key_usage, ASN1_OBJECT_free);
    }
    if(VALID_CERTIFICATE == valid1 && VALID_CERTIFICATE == valid2)
    {
        return VALID_CERTIFICATE;
    }
    return INVALID_CERTIFICATE;
}

/* Load certificates from a directory to a linked list */
cert_container_t* load_certs(const char *certpath)
{
    DIR *dir;
    struct dirent *entry;
    char filepath[MAX_FILEPATH_CHARS_SIZE+1];
    int len;
    cert_container_t* certs = NULL;
    cert_container_t* cert_cont_curr;
    cert_container_t* cert_cont_new;
    X509* cert_new = NULL;
    int cert_counter = 0;

    dir = opendir(certpath);
    if (!dir) 
    {
        PRINT_ERROR("Cannot open certificates directory");
        return NULL;
    }

    while ((entry = readdir(dir)) != NULL) 
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) 
        {
            continue;
        }

        /* Only read files */
        if(entry->d_type != DT_REG)
        {
            PRINT_WARN_DEBUG(debug, "Skipping %s since it is not a file", entry->d_name);
            continue;
        }
        /* Get full path of the file */
        len = snprintf(filepath, MAX_FILEPATH_CHARS_SIZE, "%s%c%s", certpath, '/', entry->d_name);
        if(len < 0 || len >= MAX_FILEPATH_CHARS_SIZE)
        {
            PRINT_WARN_DEBUG(debug, "Skipping %s since the full path name is too long", entry->d_name);
            continue;
        }

        /* Initialize OpenSSL algorithms*/
        OpenSSL_add_all_algorithms();

        /* Read one certificate */
        cert_new = read_cert(filepath);
        if (!cert_new) 
        {
            PRINT_WARN_DEBUG(debug, "Skipping %s since the certificate cannot be read", entry->d_name);
            continue;
        }
    
        /* Check if the certificate is self-signed */
        if(IS_SELFSIGNED != validate_selfsigned_cert(cert_new))
        {
            PRINT_WARN_DEBUG(debug, "Skipping %s since the certificate is not self-signed", entry->d_name);
            X509_free(cert_new);
            continue;
        }

        /* Check if the certificate has correct Key Usage */
        if(VALID_CERTIFICATE != validate_codesigning_cert(cert_new))
        {
            PRINT_WARN_DEBUG(debug, "Skipping %s since the certificate's key usage is not codeSigning", entry->d_name);
            X509_free(cert_new);
            continue;
        }

        cert_cont_new = malloc(sizeof(cert_container_t));

        if(!cert_cont_new)
        {
            PRINT_ERROR("Memory allocation failed");
            closedir(dir);
            cleanup_certs(&certs);
            return NULL;
        }

        strncpy(cert_cont_new->name, entry->d_name, sizeof(cert_cont_new->name));
        cert_cont_new->cert = cert_new;
        cert_cont_new->next = NULL;

        if(!certs)
        {
            certs = cert_cont_new;
            cert_cont_curr = cert_cont_new;
        }
        else
        {
            cert_cont_curr->next = cert_cont_new;
            cert_cont_curr = cert_cont_curr->next;
        }

        PRINT_INFO("Successfully loaded certificate %s", entry->d_name);
        cert_counter++;
    }
    closedir(dir);
    PRINT_INFO("Loaded a total of %d certificates", cert_counter);
    return certs;
}