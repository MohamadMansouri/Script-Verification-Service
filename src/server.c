/*
 * Project Name: Script Verification Service
 * Filename: server.c
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
#include <openssl/err.h>

#include "debug.h"
#include "verify.h"
#include "run_script.h"
#include "server.h"
#include "ipc_pipe.h"
#include "cert_utils.h"


    
int debug = DEBUG_DISABLED;
long int counter = 0;

int main(int argc, char *argv[]) 
{
    int opt;
    int verify_sig_ret = VERIFY_SIGNATURE_INVALID;
    signed_script_t signed_script = {.script = NULL, .signature = NULL, .script_size = 0, .signature_size = 0, .valid = VERIFY_SIGNATURE_INVALID};
    cert_container_t* certs = NULL;
    char certs_path[300];
    certs_path[0] = '\0';

    while ((opt = getopt(argc, argv, "dc:")) != -1) 
    {
        switch (opt) 
        {
            case 'd':
                debug = DEBUG_ENABLED;
                break;
            case 'c':
                strncpy(certs_path, optarg, sizeof(certs_path) - 1);
                certs_path[sizeof(certs_path) - 1] = '\0';
                break;
            default:
                fprintf(stderr, "Usage: %s [-d] [-c <certs_path>]\n", argv[0]);
                fprintf(stderr, "       -d : enable debug\n");
                fprintf(stderr, "       -c <certs_path> : specify certificates directory\n");
                return ERROR;
        }
    }
   
    if(strlen(certs_path) == 0)
    {
        certs = load_certs(SERVER_DEFAULT_CERTS_PATH);
    }
    else
    {
        certs = load_certs(certs_path);
    }

    if(NULL == certs)
    {
        PRINT_ERROR("Cannot load any certificate");
        return ERROR;
    }


    if(READ_PIPE_OK != init_pipe(&signed_script))
    {
        PRINT_ERROR("Cannot open a fifo named pipe");
        return ERROR;
    }

    for(;;)
    {
        if (READ_PIPE_ERROR == read_from_pipe(&signed_script))
        {
            PRINT_INFO("Error occured while parsing script #%ld. Skipping...", counter);
            continue;
        }

        else
        {
            verify_sig_ret = verify_signature(certs, &signed_script);

            if(VERIFY_SIGNATURE_VALID == verify_sig_ret)
            {
                PRINT_INFO("Script #%ld has VALID signature, executing...", counter);
                if (EXECUTING_SCRIPT_OK != run_script(&signed_script))
                {
                    PRINT_ERROR("Failed to execute the script");
                }
            }
            else if(VERIFY_SIGNATURE_INVALID == verify_sig_ret)
            {
                PRINT_INFO("The script has INVALID signature, skipping...\n");
            }
            else
            {
                PRINT_ERROR("Error occured while verifying the signature");
                ERR_print_errors_fp(stderr);
            }
        }
    }


    cleanup_certs(&certs);
    free(signed_script.signature);
    EVP_cleanup();
    ERR_free_strings();
    return OK;
}