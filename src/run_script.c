/*
 * Project Name: Script Verification Service
 * Filename: run_script.c
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

#include "debug.h"
#include "verify.h"
#include "run_script.h"
#include "server.h"

int run_script(signed_script_t* signed_script)
{
   /* Double check that the signature is valid in case execution flow was hijacked */
    if (VERIFY_SIGNATURE_VALID != signed_script->valid)
    {
        PRINT_ERROR_DEBUG(debug, "An attempt to run an unverified script");
        return EXECUTING_SCRIPT_FAILED;
    }

    /* Open a pipe to bash as a child process */
    FILE *pipe = popen(BASH_COMMAND, "w");
    if (!pipe) 
    {
        PRINT_ERROR_DEBUG(debug, "Error opening pipe to bash");
        return EXECUTING_SCRIPT_FAILED;
    }

    /* Write the script content to the pipe (i.e., execute it)*/
    fputs(signed_script->script, pipe);

    /* Close the pipe */
    if (pclose(pipe) < 0) 
    {
        PRINT_ERROR_DEBUG(debug, "Error closing pipe");
        return EXECUTING_SCRIPT_FAILED;
    }

    /* Open the file containing the result of the script */
    FILE *fd = fopen(BASH_OUTPUT_FILE, "r");
    if (!fd) 
    {
        PRINT_ERROR_DEBUG(debug, "Error opening output file of bash");
        return EXECUTING_SCRIPT_FAILED;
    }

    /* Read and print the output of the script */
    PRINT_INFO("++++++++++++ SCRIPT OUTPUT ++++++++++++++++");
    PRINT_INFO("++++++++++++++++ START ++++++++++++++++++++");
    char buffer[SCRIPT_OUTPUT_BUFFER_SIZE];
    while (NULL != fgets(buffer, SCRIPT_OUTPUT_BUFFER_SIZE, fd)) 
    {
        printf("%s", buffer);
    }
    PRINT_INFO("+++++++++++++++++ END +++++++++++++++++++++");
    PRINT_INFO("+++++++++++++++++++++++++++++++++++++++++++");

    /* Close the pipe */
    if (fclose(fd) < 0) 
    {
        PRINT_ERROR_DEBUG(debug, "Error closing output file of bash");
        return EXECUTING_SCRIPT_FAILED;
    }

    return EXECUTING_SCRIPT_OK;
}
