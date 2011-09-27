/* 
* por.h
*
* Copyright (c) 2010, Zachary N J Peterson <znpeters@nps.edu>
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*     * Redistributions of source code must retain the above copyright
*       notice, this list of conditions and the following disclaimer.
*     * Redistributions in binary form must reproduce the above copyright
*       notice, this list of conditions and the following disclaimer in the
*       documentation and/or other materials provided with the distribution.
*     * Neither the name of the Naval Postgraduate School nor the
*       names of its contributors may be used to endorse or promote products
*       derived from this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY ZACHARY N J PETERSON ``AS IS'' AND ANY
* EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL ZACHARY N J PETERSON BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef __POR_H__
#define __POR_H__

#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

/* Tagging is "embarrassingly" parallelizable as each tag can be calculated
 * independenlty.  During tagging, N threads can be spawned, dividing the file
 * into N sections.  Each thread processes every Nth block of a file */
#define THREADING

/* TODO: This should probably be set by autoconf based on some proc variables */
/* The number of threads should be about the number of cores a processor has.
 * Processing is the bottleneck in tagging, so launching more than the number of
 * of cores won't achieve much, if any, speedup. */
#ifdef THREADING
#define NUM_THREADS 2
#endif


#define POR_PRF_KEY_SIZE SHA_DIGEST_LENGTH /* Size (in bytes) of an HMAC-SHA1 */

#define POR_BLOCK_SIZE 4096

#define MAGIC_NUM_CHALLENGE_BLOCKS 460

typedef struct POR_key_struct POR_key;

struct POR_key_struct{

	unsigned char *prf_key;
	size_t prf_key_size;
};

typedef struct POR_challenge_struct POR_challenge;

struct POR_challenge_struct{

	unsigned int l;			/* The number of elements to be tested */
	unsigned int *I;		/* An array of l indicies to be tested */
};

int por_tag_file(char *filepath, size_t filepath_len, char *tagfilepath, size_t tagfilepath_len);
int por_verify_block(char *filepath, size_t filepath_len, unsigned char *block, size_t block_len, unsigned int index, unsigned char *tag, size_t tag_len);
int get_por_block(char *filepath, size_t filepath_len, unsigned char *block, size_t block_len, unsigned int index);
int get_por_tag(char *tagfilepath, size_t tagfilepath_len, unsigned char *tag, size_t tag_len, unsigned int index);

#ifdef USE_S3
int por_s3_write_file(char *filepath, size_t filepath_len);
int por_s3_get_file(char *filepath, size_t filepath_len);
int por_s3_get_block(char *filepath, size_t filepath_len, unsigned char *block, size_t block_len, unsigned int index);
#endif

POR_key *generate_por_key();
void destroy_por_key(POR_key *key);
POR_key *por_get_keys();

POR_challenge *allocate_por_challenge(unsigned int l);
void destroy_por_challenge(POR_challenge *challenge);
POR_challenge *por_create_challenge(unsigned int n);
void printhex(unsigned char *ptr, size_t size);
void sfree(void *ptr, size_t size);

#endif 