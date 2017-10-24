/*
PBKDF2 Algorithm
Copyright (C) 2017 Gabriel Nathan Maiberger

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <sha3.h>

unsigned char *pbkdf2_derive_key(unsigned char *password, unsigned char *salt, int c, int len);
unsigned char *pbkdf2_function(unsigned char *password, unsigned char *salt, int c, int i);
unsigned char *hmac_sha3(unsigned char *key, unsigned char *message);

unsigned char *pbkdf2_derive_key(unsigned char *password, unsigned char *salt, int c, int len){
	int n=len/64;

	printf("%i\n", n);

	unsigned char *t[n];
	unsigned char *key=malloc(len);

	int i;
	for(i=0; i<n; i++){
		t[i]=pbkdf2_function(password, salt, c, i);
		memset(key+i*64, (long int)t[i], 64);
	}

	return key;
}

unsigned char *pbkdf2_function(unsigned char *password, unsigned char *salt, int c, int i){
	unsigned char *u[c];
	long int u_final;

	int j;
	for(j=0; j<c; j++){
		if(j==0){
			strcat(salt, (unsigned char *)&i);
			u[j]=hmac_sha3(password, salt);
			u_final=(long int)u[j];
		} else {
			u[j]=hmac_sha3(password, u[j-1]);
			u_final^=(long int)u[j];
		}
	}

	return (unsigned char *)u_final;
}

unsigned char *hmac_sha3(unsigned char *key, unsigned char *message){
	int size=sizeof(key)/sizeof(key[0]);
	printf("%i\n", size);

	if(size>64){
		key=sha3_512(key,64);
		size=64;
	} else if(size<64){
		strncat(key, (unsigned char *)"\x00", 64-size);
		size=64;
	}

	unsigned char *o_key_pad=malloc(128);
	unsigned char *i_key_pad=malloc(128);

	int i;
	for(i=0; i<64; i++){
		memset((o_key_pad+i), (long int)(0x5c*64)^(long int)key[i], 1);
		memset((i_key_pad+i), (long int)(0x36*64)^(long int)key[i], 1);
	}

	strcat(i_key_pad, message);
	unsigned char *i_key_pad_hash=sha3_512(i_key_pad, 128);
	strcat(o_key_pad, i_key_pad_hash);

	unsigned char *hash=sha3_512(o_key_pad, 128);

	return hash;
}
