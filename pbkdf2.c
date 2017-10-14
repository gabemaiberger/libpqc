#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <sha3.h>

unsigned char *pbkdf2_derive_key(unsigned char *password, unsigned char *salt, int c, int len);
unsigned char *pbkdf2_function(unsigned char *password, unsigned char *salt, int c, int i);
unsigned char *hmac_sha3(unsigned char *key, unsigned char *message);

unsigned char *pbkdf2_derive_key(unsigned char *password, unsigned char *salt, int c, int len){
	unsigned char *t[len/64];
	unsigned char *key=malloc(len);

	int i;
	for(i=0; i<len/64; i++){
		t[i]=pbkdf2_function(password, salt, c, i);
		memset(key+i*64, (long int)t[i], 64);
	}

	for(i=0; i<512; i++){
		printf("%x", key[i]);
	}

	return key;
}

unsigned char *pbkdf2_function(unsigned char *password, unsigned char *salt, int c, int i){
	unsigned char *u[c];
	long int u_final;

	int j;
	for(j=0; j<c; j++){
		if(j==0){
			asprintf(salt, i);
			u[j]=hmac_sha3(password, salt);
		} else {
			u[j]=hmac_sha3(password, u[j-1]);
		}
	}
	for(j=0; j<c; j++){
		if(j==0){
			u_final=(long int)u[j];
		} else {
			u_final^=(long int)u[j];
		}
	}

	return (unsigned char *)u_final;
}

unsigned char *hmac_sha3(unsigned char *key, unsigned char *message){
	int size=sizeof(key)/sizeof(key[0]);
	if(size>64){
		key=sha3_512(key,64);
	} else if(size<64){
		strncat(key, (unsigned char *)"\x00", 64-size);
	}

	unsigned char o_key_pad=(long int)(0x5c*64)^(long int)key;
	unsigned char i_key_pad=(long int)(0x36*64)^(long int)key;

	unsigned char *i_key_pad_hash=malloc(64);

	strcat(&i_key_pad, message);
	i_key_pad_hash=sha3_512(&i_key_pad, strlen(&i_key_pad));
	strcat(&o_key_pad, i_key_pad_hash);

	unsigned char *hash=malloc(64);
	hash=sha3_512(&o_key_pad, strlen(&o_key_pad));
	return hash;
}
