/*
PBKDF2 Algorithm
Copyright (C) 2017-2022 Gabriel Nathan Maiberger

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
#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <sha3.h>

unsigned char *pbkdf2_derive_key(unsigned char *password, unsigned char *salt, int c, int len);
unsigned char *pbkdf2_function(unsigned char *password, unsigned char *salt, int c, int i);
unsigned char *hmac_sha3(unsigned char *key, unsigned char *message);

unsigned char *pbkdf2_derive_key(unsigned char *password, unsigned char *salt, int c, int len){
	int n=len/64;

	unsigned char *t[n];
	unsigned char *key=malloc(len);

	int i;
	for(i=0; i<n; i++){
		t[i]=pbkdf2_function(password, salt, c, i);
		memcpy(key+(i*64), t[i], 64);
	}

	return key;
}

unsigned char *pbkdf2_function(unsigned char *password, unsigned char *salt, int c, int i){
	unsigned char *u_prev;
	unsigned char *u_final=malloc(64);

	int j;
	int k;
	for(j=0; j<c; j++){
		if(j==0){
			salt[63]=(uint8_t)i;
			u_prev=hmac_sha3(password, salt);
			for(k=0; k<64; k++){
				u_final[k]=u_prev[k];
			}
		} else {
			u_prev=hmac_sha3(password, u_prev);
			for(k=0; k<64; k++){
				u_final[k]^=u_prev[k];
			}
		}
	}

	return u_final;
}

unsigned char *hmac_sha3(unsigned char *key, unsigned char *message){
	int size=sizeof(key)/sizeof(key[0]);

	if(size>64){
		key=sha3_512(key, 64);
		size=64;
	} else if(size<64){
		strncat(key, "\x00", 64-size);
		size=64;
	}

	unsigned char *i_key_pad=malloc(128);
	unsigned char *o_key_pad=malloc(128);

	int i;
	for(i=0; i<64; i++){
		i_key_pad[i]=(unsigned char)((0x36*64)^key[i]);
		o_key_pad[i]=(unsigned char)((0x5c*64)^key[i]);
	}

	memcpy(i_key_pad+64, message, 64);

	unsigned char *i_key_pad_hash=sha3_512(i_key_pad, 128);

	memcpy(o_key_pad+64, i_key_pad_hash, 64);

	unsigned char *hash=sha3_512(o_key_pad, 128);

	free(i_key_pad);
	free(o_key_pad);

	return hash;
}
