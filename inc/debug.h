/*
 * Project Name: Script Verification Service
 * Filename: debug.h
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

#ifndef __DEBUG_H_
#define __DEBUG_H_

#include <stdio.h>
#include <stdlib.h>
#include <openssl/err.h>

#define DEBUG_ENABLED                       1
#define DEBUG_DISABLED                      0

#define PRINT_DEBUG(debug, msg, ...) \
    if(debug) \
    { \
        printf("DEBUG: " ); \
        printf(msg, ##__VA_ARGS__); \
        printf("\n"); \
    }

#define PRINT_INFO(msg, ...) \
        printf("INFO : " ); \
        printf(msg, ##__VA_ARGS__); \
        printf("\n"); 

#define PRINT_ERROR_DEBUG(debug, msg, ...) \
    if(debug) \
    { \
        fprintf(stderr, "ERROR: "); \
        fprintf(stderr, msg, ##__VA_ARGS__); \
        fprintf(stderr, "\n"); \
    }

#define PRINT_WARN_DEBUG(debug, msg, ...) \
    if(debug) \
    { \
        printf("WARN : " ); \
        printf(msg, ##__VA_ARGS__); \
        printf("\n"); \
    }

#define PRINT_ERROR(msg, ...) \
        fprintf(stderr, "ERROR: " ); \
        fprintf(stderr, msg, ##__VA_ARGS__); \
        fprintf(stderr, "\n");

extern int debug;

#endif /* __DEBUG_H_ */
