/* 
* por-misc.c
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

void printhex(unsigned char *ptr, size_t size){

	int i = 0;
	for(i = 0; i < size; i++){
		printf("%02X", *ptr);
		ptr++;
	}
	printf("\n");
}

void sfree(void *ptr, size_t size){ memset(ptr, 0, size); free(ptr); ptr = NULL;}

static int get_rand_range(unsigned int min, unsigned int max, unsigned int *value){
	unsigned int rado;
	unsigned int range = max - min + 1;
	
	if(!value) return 0;
	if(max < min) return 0;
	do{
		if(!RAND_bytes((unsigned char *)&rado, sizeof(unsigned int))) return 0;
	}while(rado > UINT_MAX - (UINT_MAX % range));
	
	*value = min + (rado % range);
	
	return 1;
}

static void bubbleSort(unsigned int *numbers, unsigned int array_size){

	int i, j, temp;
 
	for (i = (array_size - 1); i >= 0; i--){
		for (j = 1; j <= i; j++){
      		if (numbers[j-1] > numbers[j]){
        		temp = numbers[j-1];
        		numbers[j-1] = numbers[j];
        		numbers[j] = temp;
      		}
    	}
  	}
}

POR_challenge *por_create_challenge(unsigned int n){
	
	POR_challenge *challenge;
	int i = 0;
	unsigned int l;
	unsigned int *random_indices = NULL;
	unsigned int tmp = 0;
	unsigned int swapwith = 0;
	

	if(n > MAGIC_NUM_CHALLENGE_BLOCKS)
		l = MAGIC_NUM_CHALLENGE_BLOCKS;
	else
		l = n;

	/* Allocate memory */
	if( ((challenge = allocate_por_challenge(l)) == NULL)) goto cleanup;
	
	/* Randomly choose l indices (without replacement) */
	/* To do this, we create an array with all indices 0 - n-1, shuffle it, and take the first l values */
	if( ((random_indices = malloc(sizeof(unsigned int) * n)) == NULL)) goto cleanup;
	for(i = 0; i < n; i++)
		random_indices[i] = i;
	for(i = 0; i < n; i++){
		get_rand_range(0, n-1, &swapwith);
		tmp = random_indices[swapwith];
		random_indices[swapwith] = random_indices[i];
		random_indices[i] = tmp;
	}
	for(i = 0; i < l; i++)
		challenge->I[i] = random_indices[i];

	/* Sort the challenge for any potential efficiencies */
	bubbleSort(challenge->I, l);

	sfree(random_indices, sizeof(unsigned int) * n);
	
	return challenge;
	
cleanup:
	if(challenge) destroy_por_challenge(challenge);
	if(random_indices) sfree(random_indices, sizeof(unsigned int) * n);
	
	return NULL;
}

void destroy_por_challenge(POR_challenge *challenge){

	if(!challenge) return;
	if(challenge->I) sfree(challenge->I, sizeof(unsigned int) * challenge->l);
	challenge->l = 0;
	sfree(challenge, sizeof(POR_challenge));
	
	return;
}

POR_challenge *allocate_por_challenge(unsigned int l){
	
	POR_challenge *challenge = NULL;

	if( ((challenge = malloc(sizeof(POR_challenge))) == NULL)) return NULL;
	memset(challenge, 0, sizeof(POR_challenge));
	challenge->l = l;
	if( ((challenge->I = malloc(sizeof(unsigned int) * challenge->l)) == NULL)) goto cleanup;
	memset(challenge->I, 0, sizeof(unsigned int) * challenge->l);

	return challenge;
	
cleanup:
	destroy_por_challenge(challenge);
	return NULL;
}