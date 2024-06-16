/*
 * Project Name: Script Verification Service
 * Filename: server.h
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

#ifndef __SERVER_H_
#define __SERVER_H_

#include <stdio.h>
#include <stdlib.h>

#include "cert_utils.h"

#define ERROR                               -1
#define OK                                  0

#define MIN_SIGNATURE_SIZE                  32
#define MAX_SIGNATURE_SIZE                  4096
#define MAX_SCRIPT_SIZE                     8192
#define MAX_FILE_SIZE                       (MAX_SIGNATURE_SIZE + MAX_SCRIPT_SIZE + 1)

#define VERIFY_SIGNATURE_VALID               0
#define VERIFY_SIGNATURE_ERROR              -1
#define VERIFY_SIGNATURE_INVALID            -2
#define VERIFY_SIGNATURE_BAD_CERTIFICATE    -3

#define DEBUG_ENABLED                       1
#define DEBUG_DISABLED                      0

#define SERVER_DEFAULT_CERTS_PATH   "./tests/certificates"


typedef struct signed_script
{
    size_t signature_size;
    size_t script_size;
    char* signature;
    char* script;
    int  valid; // for redundent check
} signed_script_t;

extern long int counter;
#endif /* __SERVER_H_ */
