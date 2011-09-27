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
#ifdef THREADING
#include <pthread.h>
#endif

#ifdef THREADING

struct thread_arguments{

	FILE *file;		/* File to tag; a unique file descriptor to this thread */
	char *filepath; /* Unique path of the file */
	size_t filepath_len; /*Length of the file path */
	POR_key *key;	/* POR key pair */
	int threadid;	/* The ID of the thread used to determine which blocks to tag */
	int numblocks;	/* The number blocks this thread needs to tag */
	unsigned char *tags;	/* Shared memory between threads used to store the result tags */
};

void *por_tag_thread(void *threadargs_ptr){

	HMAC_CTX ctx;
	unsigned char digest[SHA_DIGEST_LENGTH];
	unsigned int digest_len = 0;
	unsigned int block;
	int *ret = NULL;
	unsigned char buf[POR_BLOCK_SIZE];
	struct thread_arguments *threadargs = threadargs_ptr;
	int i = 0;
	
	if(!threadargs || !threadargs->file || !threadargs->tags || !threadargs->key || !threadargs->numblocks) goto cleanup;
	
	/* Allocate memory for return value - this should be freed by the checker */
	ret = malloc(sizeof(int));
	if(!ret) goto cleanup;
	*ret = 0;
	
	/* For N threads, read in and tag each Nth block */
	block = threadargs->threadid;
	for(i = 0; i < threadargs->numblocks; i++){
		memset(digest, 0, SHA_DIGEST_LENGTH);
		memset(buf, 0, POR_BLOCK_SIZE);
		fseek(threadargs->file, (block*POR_BLOCK_SIZE), SEEK_SET);
		fread(buf, POR_BLOCK_SIZE, 1, threadargs->file);
		if(ferror(threadargs->file)) goto cleanup;

		/* Calculate the tag for this block */
		HMAC_CTX_init(&ctx);
		HMAC_Init(&ctx, threadargs->key->prf_key, threadargs->key->prf_key_size, EVP_sha1());
	
		
		HMAC_Update(&ctx, (const unsigned char *)&block, sizeof(unsigned int));
		HMAC_Update(&ctx, (unsigned char *)threadargs->filepath, (int)threadargs->filepath_len);
		HMAC_Update(&ctx, buf, POR_BLOCK_SIZE);
		
		HMAC_Final(&ctx, digest, &digest_len);

		HMAC_cleanup(&ctx);		

		/* Store the tag in a buffer until all threads are done. Writer should destroy tags. */
		memcpy((threadargs->tags + (SHA_DIGEST_LENGTH * block)), digest, digest_len);
		block += NUM_THREADS;
	}

	*ret = 1;
	pthread_exit(ret);

cleanup:
	pthread_exit(ret);
	
}

#endif 

int por_tag_file(char *filepath, size_t filepath_len, char *tagfilepath, size_t tagfilepath_len){
		
	
	POR_key *key = NULL;
	FILE *file = NULL;
	FILE *tagfile = NULL;
	char realtagfilepath[MAXPATHLEN];
	char yesorno = 0;
	unsigned int index = 0;
#ifdef THREADING
	pthread_t threads[NUM_THREADS];
	int *thread_return = NULL;
	struct thread_arguments threadargs[NUM_THREADS];
	struct stat st;
	size_t numfileblocks = 0;

	unsigned char *tags = NULL;
	unsigned int digest_len = 0;
	memset(threads, 0, sizeof(pthread_t) * NUM_THREADS);
	memset(&st, 0, sizeof(struct stat));
#else
	HMAC_CTX ctx;
	unsigned char buf[POR_BLOCK_SIZE];
	unsigned char digest[SHA_DIGEST_LENGTH];
	unsigned int digest_len = 0;
#endif

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
	

	OpenSSL_add_all_digests();

#ifdef THREADING

	/* Calculate the number blocks in the file */
	if(stat(filepath, &st) < 0) return 0;
	numfileblocks = (st.st_size/POR_BLOCK_SIZE);
	if(st.st_size%POR_BLOCK_SIZE) numfileblocks++;

	/* Allocate buffer to hold tags until we write them out */
	if( ((tags = malloc( SHA_DIGEST_LENGTH * numfileblocks )) == NULL)) goto cleanup;
	memset(tags, 0, (SHA_DIGEST_LENGTH * numfileblocks));

	for(index = 0; index < NUM_THREADS; index++){
		/* Open a unique file descriptor for each thread to avoid race conditions */
		threadargs[index].file = fopen(filepath, "r");
		if(!threadargs[index].file) goto cleanup;
		threadargs[index].filepath = filepath;
		threadargs[index].filepath_len = filepath_len;
		threadargs[index].key = key;
		threadargs[index].threadid = index;
		threadargs[index].numblocks = numfileblocks/NUM_THREADS;
		threadargs[index].tags = tags;
		
		/* If there is not an equal number of blocks to tag, add the extra blocks to
		 * the corresponding threads */
		if(index < numfileblocks%NUM_THREADS)
			threadargs[index].numblocks++;
		/* If the thread has blocks to tag, spawn it */
		if(threadargs[index].numblocks > 0)
			if(pthread_create(&threads[index], NULL, por_tag_thread, (void *) &threadargs[index]) != 0) goto cleanup;
	}
	/* Check to see all tags were generated */
	for(index = 0; index < NUM_THREADS; index++){
		if(threads[index]){
			if(pthread_join(threads[index], (void **)&thread_return) != 0) goto cleanup;
			if(!thread_return || !(*thread_return))goto cleanup;
			else free(thread_return);
			/* Close the file */
			if(threadargs[index].file)
				fclose(threadargs[index].file);
		}
	}
	/* Write the tags out */
	for(index = 0; index < numfileblocks; index++){
		if(!tags[index]) goto cleanup;
		
		/* Write the tag to disk */
		digest_len = SHA_DIGEST_LENGTH;
		fwrite(&digest_len, sizeof(unsigned int), 1, tagfile);
		if(ferror(tagfile)) goto cleanup;	
		fwrite(tags + (SHA_DIGEST_LENGTH * index), SHA_DIGEST_LENGTH, 1, tagfile);
		if(ferror(tagfile)) goto cleanup;
		
	}
	sfree(tags, (SHA_DIGEST_LENGTH * numfileblocks));
#else
	/* Open the file for reading */
	file = fopen(filepath, "r");
	if(!file){
		fprintf(stderr, "ERROR: Was not able to open %s for reading.\n", filepath);
		goto cleanup;
	}

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
#endif

exit:
	destroy_por_key(key);
	if(file) fclose(file);
	if(tagfile) fclose(tagfile);
	return 1;

cleanup:
	fprintf(stderr, "ERROR: Was unable to create tag file.\n");
#ifdef THREADING
	for(index = 0; index < NUM_THREADS; index++){
		if(threads[index] != NULL) pthread_cancel(threads[index]);
		if(threadargs[index].file) fclose(threadargs[index].file);
	}

	sfree(tags, (SHA_DIGEST_LENGTH * numfileblocks));
#endif
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
	//int i = 0;
	
	if(!tagfilepath || !tagfilepath_len || !tag || !tag_len) return 0;
	if(tagfilepath_len >= MAXPATHLEN) return 0;

	tagfile = fopen(tagfilepath, "r");
	if(!tagfile){
		fprintf(stderr, "ERROR: Was not able to open %s for reading.\n", tagfilepath);
		goto cleanup;
	}
	
	/* Seek to tag offset */
	if(fseek(tagfile, (index * (sizeof(unsigned int) + SHA_DIGEST_LENGTH)), SEEK_SET) < 0) goto cleanup;	

	// While this is more "correct" and handles variable length MACs, it is pretty slow.  The above is much faster.
	/* 
	//Seek to start of tag file 
	if(fseek(tagfile, 0, SEEK_SET) < 0) goto cleanup;
	
	//Seek to tag offset index 
	for(i = 0; i < index; i++){
		fread(&digest_len, sizeof(unsigned int), 1, tagfile);
		if(ferror(tagfile)) goto cleanup;
		printf("Got digest_len %d\n", digest_len);
		if(fseek(tagfile, digest_len, SEEK_CUR) < 0) goto cleanup;
	}
	*/
	
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