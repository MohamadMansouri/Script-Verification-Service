/*
 * Project Name: Script Verification Service
 * Filename: ipc_pipe.c
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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "debug.h"
#include "ipc_pipe.h"
#include "server.h"

int init_pipe(signed_script_t* signed_script)
{
    /* Allocate memory for buffer */
    signed_script->signature = malloc(MAX_FILE_SIZE);

    if (NULL == signed_script->signature)
    {
        PRINT_ERROR("Memory allocation failed");
        return READ_PIPE_INIT_ERROR;
    }

    remove(SERVER_PIPE_PATH);
    if(mkfifo(SERVER_PIPE_PATH, 0666) < 0)
    {
        PRINT_ERROR("Cannot create a fifo named pipe");
        perror("");
        return READ_PIPE_INIT_ERROR;
    }


    return READ_PIPE_INIT_OK;
}

int read_from_pipe(signed_script_t* signed_script)
{
    int file_size;
    int fifo_fd;

    signed_script->signature_size = 0;
    signed_script->script_size = 0;

    /* Open the fifo pipe to receive files */
    fifo_fd = open(SERVER_PIPE_PATH, O_RDONLY);
    if(fifo_fd < 0)
    {
        PRINT_ERROR_DEBUG(debug, "Cannot open the fifo named pipe");
        return READ_PIPE_ERROR;
    }

    /* Read one file. This is blocking */
    file_size = read(fifo_fd, signed_script->signature, MAX_FILE_SIZE);

    PRINT_INFO(" ");
    PRINT_INFO(" ");
    PRINT_INFO("============================================");
    PRINT_INFO("========== Received script #%ld ==============", ++counter);
    PRINT_INFO("============================================");

    /* Close the fifo pipe after reading one file */
    if(close(fifo_fd) < 0)
    {
        PRINT_ERROR_DEBUG(debug, "Cannot close the fifo named pipe");
        return READ_PIPE_ERROR;
    }

    /* Stop if the size is zero */
    if(file_size == 0)
    {
        PRINT_ERROR("The received file is empty file");
        return READ_PIPE_ERROR;
    }

    /* Parse the signature part */
    char* sigend = strchr(signed_script->signature, '\n');
    if(!sigend)
    {
        PRINT_ERROR_DEBUG(debug, "Cannot parse the signature from the file");
        return READ_PIPE_ERROR;
    }

    signed_script->signature_size = sigend - signed_script->signature;

    /* Ensure that the signature size is acceptable */
    if (signed_script->signature_size < MIN_SIGNATURE_SIZE || signed_script->signature_size > MAX_SIGNATURE_SIZE)
    {
        PRINT_ERROR_DEBUG(debug, "Signature size in the file (size = %ld) is not acceptable", signed_script->signature_size);
        return READ_PIPE_ERROR;
    }

    /* Parse the script */
    signed_script->script = signed_script->signature + signed_script->signature_size + 1;
    signed_script->script_size = file_size - signed_script->signature_size - 1;
    signed_script->script[signed_script->script_size] = '\0';

    PRINT_DEBUG(debug, "Script #%ld is parsed successfuly", counter);
    PRINT_DEBUG(debug, "Size of the recieved file is %d", file_size);
    PRINT_DEBUG(debug, "Size of the signature is %lu", signed_script->signature_size);
    PRINT_DEBUG(debug, "Size of the script is %lu", signed_script->script_size);
    PRINT_DEBUG(debug, "Signature value\n===>\n%.*s\n<===", (int)signed_script->signature_size, signed_script->signature);
    PRINT_DEBUG(debug, "Script content\n===>\n%.*s\n<===", (int) signed_script->script_size, signed_script->script);

    return READ_PIPE_OK;
}