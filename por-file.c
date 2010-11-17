/* 
* por-file.c
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

int por_tag_file(char *filepath, size_t filepath_len, char *tagfilepath, size_t tagfilepath_len){
		
	HMAC_CTX ctx;
	POR_key *key = NULL;
	FILE *file = NULL;
	FILE *tagfile = NULL;
	char realtagfilepath[MAXPATHLEN];
	char yesorno = 0;
	unsigned int index = 0;
	unsigned char buf[POR_BLOCK_SIZE];
	unsigned char digest[SHA_DIGEST_LENGTH];
	unsigned int digest_len = 0;
	memset(realtagfilepath, 0, MAXPATHLEN);


	if(!filepath) return 0;
	if(filepath_len >= MAXPATHLEN) return 0;
	if(tagfilepath_len >= MAXPATHLEN) return 0;
	
	/* If no tag file path is specified, add a .tag extension to the filepath */
	if(!tagfilepath && (filepath_len < MAXPATHLEN - 5)){
		if( snprintf(realtagfilepath, MAXPATHLEN, "%s.tag", filepath) >= MAXPATHLEN ) goto cleanup;
	}else{
		memcpy(realtagfilepath, tagfilepath, tagfilepath_len);
	}
	
	/* Check to see if the tag file exists */
	if( (access(realtagfilepath, F_OK) == 0)){
		fprintf(stdout, "WARNING: A tag file for %s already exist; do you want to overwite (y/N)?", filepath);
		scanf("%c", &yesorno);
		if(yesorno != 'y') goto exit;
	}
	
	tagfile = fopen(realtagfilepath, "w");
	if(!tagfile){
		fprintf(stderr, "ERROR: Was not able to create %s.\n", realtagfilepath);
		goto cleanup;
	}

	/* Get the POR key */
	key = por_get_keys();
	if(!key) goto cleanup;
	
	/* Open the file for reading */
	file = fopen(filepath, "r");
	if(!file){
		fprintf(stderr, "ERROR: Was not able to open %s for reading.\n", filepath);
		goto cleanup;
	}

	OpenSSL_add_all_digests();
	
	index = 0;
	do{
		/* Calculate the tag for this block */
		HMAC_CTX_init(&ctx);
		HMAC_Init(&ctx, key->prf_key, key->prf_key_size, EVP_sha1());
		memset(buf, 0, POR_BLOCK_SIZE);

		fread(buf, POR_BLOCK_SIZE, 1, file);
		if(ferror(file)) goto cleanup;
		
		HMAC_Update(&ctx, (const unsigned char *)&index, sizeof(unsigned int));
		HMAC_Update(&ctx, (unsigned char *)filepath, (int)filepath_len);
		HMAC_Update(&ctx, buf, POR_BLOCK_SIZE);
		
		HMAC_Final(&ctx, digest, &digest_len);

		/* Write the tag to disk */
		fwrite(&digest_len, sizeof(unsigned int), 1, tagfile);
		if(ferror(tagfile)) goto cleanup;	
		fwrite(digest, digest_len, 1, tagfile);
		if(ferror(tagfile)) goto cleanup;
		
		index++;
		HMAC_cleanup(&ctx);		

	}while(!feof(file));

exit:
	destroy_por_key(key);
	if(file) fclose(file);
	if(tagfile) fclose(tagfile);
	return 1;

cleanup:
	fprintf(stderr, "ERROR: Was unable to create tag file.\n");
	if(key) destroy_por_key(key);	
	if(file) fclose(file);
	if(tagfile){ 
		ftruncate(fileno(tagfile), 0);
		unlink(realtagfilepath);
		fclose(tagfile);
	}
	return 0;
}

int get_por_tag(char *tagfilepath, size_t tagfilepath_len, unsigned char *tag, size_t tag_len, unsigned int index){

	FILE *tagfile = NULL;
	unsigned int digest_len = 0;
	int i = 0;
	
	if(!tagfilepath || !tagfilepath_len || !tag || !tag_len) return 0;
	if(tagfilepath_len >= MAXPATHLEN) return 0;

	tagfile = fopen(tagfilepath, "r");
	if(!tagfile){
		fprintf(stderr, "ERROR: Was not able to open %s for reading.\n", tagfilepath);
		goto cleanup;
	}
	
	/* Seek to start of tag file */
	if(fseek(tagfile, 0, SEEK_SET) < 0) goto cleanup;
	
	/* Seek to tag offset index */
	for(i = 0; i < index; i++){
		fread(&digest_len, sizeof(unsigned int), 1, tagfile);
		if(ferror(tagfile)) goto cleanup;
		if(fseek(tagfile, digest_len, SEEK_CUR) < 0) goto cleanup;
	}
	
	/* Read in the tag */
	fread(&digest_len, sizeof(unsigned int), 1, tagfile);
	if(ferror(tagfile)) goto cleanup;	
	fread(tag, digest_len, 1, tagfile);
	if(ferror(tagfile)) goto cleanup;	
		
	if(tagfile) fclose(tagfile);	

	return 1;
	
cleanup:
	if(tagfile) fclose(tagfile);

	return 0;
}

int get_por_block(char *filepath, size_t filepath_len, unsigned char *block, size_t block_len, unsigned int index){

	FILE *file = NULL;
	
	if(!filepath || !filepath_len || !block || !block_len) return 0;
	if(filepath_len >= MAXPATHLEN) return 0;

	file = fopen(filepath, "r");
	if(!file){
		fprintf(stderr, "ERROR: Was not able to open %s for reading.\n", filepath);
		goto cleanup;
	}
	
	/* Seek to data block at I[i] */
	if(fseek(file, (block_len * index), SEEK_SET) < 0) goto cleanup;
	
	fread(block, POR_BLOCK_SIZE, 1, file);
	if(ferror(file)) goto cleanup;
	
	if(file) fclose(file);	

	return 1;
	
cleanup:
	if(file) fclose(file);
	
	return 0;
}

int por_verify_block(char *filepath, size_t filepath_len, unsigned char *block, size_t block_len, unsigned int index, unsigned char *tag, size_t tag_len){
	
	HMAC_CTX ctx;
	POR_key *key = NULL;
	unsigned char digest[SHA_DIGEST_LENGTH];
	unsigned int digest_len = 0;
	int ret = 0;
	
	if(!filepath || !block || !block_len || !tag || !tag_len) return 0;
	if(filepath_len >= MAXPATHLEN) return 0;
	
	key = por_get_keys();
	if(!key) goto cleanup;
	
	HMAC_CTX_init(&ctx);
	HMAC_Init(&ctx, key->prf_key, key->prf_key_size, EVP_sha1());

	HMAC_Update(&ctx, (const unsigned char *)&index, sizeof(unsigned int));
	HMAC_Update(&ctx, (unsigned char *)filepath, (int)filepath_len);
	HMAC_Update(&ctx, block, block_len);
		
	HMAC_Final(&ctx, digest, &digest_len);
		
	HMAC_cleanup(&ctx);			

	ret = memcmp(digest, tag, tag_len);

/*	printf("Tag: ");
	printhex(tag, tag_len);
	printf("Verify: ");
	printhex(digest, digest_len);
*/
	if(key) destroy_por_key(key);

	if(ret == 0) return 1;
	
cleanup:
	return 0;
	
}