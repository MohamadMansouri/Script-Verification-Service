/*
 * Project Name: Script Verification Service
 * Filename: verify.h
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

#ifndef __VERIFY_H_
#define __VERIFY_H_

#include <stdio.h>
#include <stdlib.h>
#include <openssl/err.h>

#include "cert_utils.h"
#include "server.h"

#define VERIFY_SIGNATURE_VALID               0
#define VERIFY_SIGNATURE_ERROR              -1
#define VERIFY_SIGNATURE_INVALID            -2

int verify_signature(cert_container_t* certs, signed_script_t* signed_script);
int decode_signature(unsigned char* decoded_signature, const char* signature, size_t signature_size);

#endif /* __VERIFY_H_ */
