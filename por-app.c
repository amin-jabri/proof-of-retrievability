/* 
* por-app.c
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

#include "por.h"

int main(int argc, char **argv){

	POR_challenge *challenge = NULL;
	struct stat statbuf;
	unsigned int numfileblocks = 0;
	unsigned char block[POR_BLOCK_SIZE];
	unsigned char tag[SHA_DIGEST_LENGTH];
	char tagfilepath[MAXPATHLEN];
	int i = 0;
	
	memset(block, 0, POR_BLOCK_SIZE);
	memset(tag, 0, SHA_DIGEST_LENGTH);
	memset(tagfilepath, 0, MAXPATHLEN);

	if(!argv[1]) return -1;

	snprintf(tagfilepath, MAXPATHLEN, "%s.tag", argv[1]);
	
	printf("Tagging file...");
	if(!por_tag_file(argv[1], strlen(argv[1]),  NULL, 0)) printf("Tag error\n");
	else printf("Done.\n");

#ifdef USE_S3
	/* Write the file to S3 */
	printf("Writing file to S3...");
	if(!por_s3_write_file(argv[1], strlen(argv[1]))) printf("Couldn't write file to S3.\n");
	else printf("Done.\n");
	
	/* Write tag file to S3 */
	printf("Writing tag to S3...");
	fflush(stdout);
	if(!por_s3_write_file(tagfilepath, strlen(tagfilepath))) printf("Couldn't write file to S3.\n");	
	else printf("Done.\n");
#endif

	/* Create the challenge */
	if (stat(argv[1], &statbuf) == -1) {
		fprintf(stderr, "\nERROR: Failed to stat file %s: ", argv[1]);
		perror(0);
		exit(-1);
	}
	numfileblocks = (statbuf.st_size/POR_BLOCK_SIZE);
	if(statbuf.st_size%POR_BLOCK_SIZE) numfileblocks++;

	printf("Creating challenge...");
	fflush(stdout);
	challenge = por_create_challenge(numfileblocks);	
	if(!challenge){printf("Couldn't create challenge.\n"); return 0;}
	else printf("Done.\n");

#ifdef USE_S3
	printf("Retrieving tag file...");
	fflush(stdout);
	if(!por_s3_get_file(tagfilepath, strlen(tagfilepath))) printf("Cloudn't get tag file.\n");
	else printf("Done.\n");
#endif
	
	printf("Challenging file...");
	fflush(stdout);
	for(i = 0; i < challenge->l; i++){
		if(i%10 == 0) printf(".");
		fflush(stdout);
		memset(block, 0, POR_BLOCK_SIZE);
#ifdef USE_S3
		if(!por_s3_get_block(argv[1], strlen(argv[1]), block, POR_BLOCK_SIZE, challenge->I[i])) printf("Couldn't get block from S3\n");
#else
		if(!get_por_block(argv[1], strlen(argv[1]), block, POR_BLOCK_SIZE, challenge->I[i])) printf("Couldn't get read block\n");
#endif
		if(!get_por_tag(tagfilepath, strlen(tagfilepath), tag, SHA_DIGEST_LENGTH, challenge->I[i])) printf("Couldn't get tag\n");
		if(!por_verify_block(argv[1], strlen(argv[1]), block, POR_BLOCK_SIZE, challenge->I[i], tag, SHA_DIGEST_LENGTH)){ printf("Didn't verify %d\n", challenge->I[i]); return 0;}
	}
	printf("Verified!\n");

	if(challenge) destroy_por_challenge(challenge);
	

	return 0;
}