/*
 * Project Name: Script Verification Service
 * Filename: cert_utils.h
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

#ifndef __CERT_UTILS_H_
#define __CERT_UTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include <openssl/x509.h>

#define MAX_FILEPATH_CHARS_SIZE 300

#define VALID_CERTIFICATE       0
#define INVALID_CERTIFICATE     -1

#define NOT_SELFSIGNED          0
#define IS_SELFSIGNED           -1

typedef struct cert_container
{
    X509* cert;
    struct cert_container* next;
    char name[255];
} cert_container_t;

X509* read_pem_cert(const char *certfile);
X509* read_der_cert(const char *certfile);
X509* read_cert(const char *certfile);
cert_container_t* load_certs(const char *certpath);
void cleanup_certs(cert_container_t** certs);
int validate_selfsigned_cert(X509* cert);
int validate_codesigning_cert(X509* cert);

#endif /* __CERT_UTILS_H_ */
