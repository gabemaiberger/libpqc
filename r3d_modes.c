/*
R3D Block Cipher Modes of Operation
Copyright (C) 2017-2019 Gabriel Nathan Maiberger

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

#include <string.h>
#include <malloc.h>
#include <pthread.h>

void r3d_encrypt_block(unsigned char plaintext_block[512], unsigned char key[512], unsigned char ciphertext_block[512]);
void r3d_decrypt_block(unsigned char ciphertext_block[512], unsigned char key[512], unsigned char plaintext_block[512]);

void r3d_encrypt_ecb(unsigned char *plaintext, unsigned char *key, unsigned char *ciphertext, int size);
void r3d_decrypt_ecb(unsigned char *ciphertext, unsigned char *key, unsigned char *plaintext, int size);

void r3d_encrypt_ctr(unsigned char *plaintext, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int size);
void r3d_decrypt_ctr(unsigned char *ciphertext, unsigned char *key, unsigned char *iv, unsigned char *plaintext, int size);

void r3d_encrypt_xex(unsigned char *plaintext, unsigned char *key, unsigned char *ciphertext, int size);
void r3d_decrypt_xex(unsigned char *ciphertext, unsigned char *key, unsigned char *plaintext, int size);

void r3d_encrypt_ctr_mt(unsigned char *plaintext, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int size, int num_threads);
void r3d_decrypt_ctr_mt(unsigned char *ciphertext, unsigned char *key, unsigned char *iv, unsigned char *plaintext, int size, int num_threads);
void *ctr_encrypt_thread(void *vargp);
void *ctr_decrypt_thread(void *vargp);

void r3d_encrypt_xex_mt(unsigned char *plaintext, unsigned char *key, unsigned char *ciphertext, int size, int num_threads);
void r3d_decrypt_xex_mt(unsigned char *ciphertext, unsigned char *key, unsigned char *plaintext, int size, int num_threads);
void *xex_encrypt_thread(void *vargp);
void *xex_decrypt_thread(void *vargp);

const unsigned char gf256[256] = {
0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e,
0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e,
0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e,
0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e,0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e,
0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e,0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e,
0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae,0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe,
0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce,0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde,
0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee,0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe,
0x1b,0x19,0x1f,0x1d,0x13,0x11,0x17,0x15,0x0b,0x09,0x0f,0x0d,0x03,0x01,0x07,0x05,
0x3b,0x39,0x3f,0x3d,0x33,0x31,0x37,0x35,0x2b,0x29,0x2f,0x2d,0x23,0x21,0x27,0x25,
0x5b,0x59,0x5f,0x5d,0x53,0x51,0x57,0x55,0x4b,0x49,0x4f,0x4d,0x43,0x41,0x47,0x45,
0x7b,0x79,0x7f,0x7d,0x73,0x71,0x77,0x75,0x6b,0x69,0x6f,0x6d,0x63,0x61,0x67,0x65,
0x9b,0x99,0x9f,0x9d,0x93,0x91,0x97,0x95,0x8b,0x89,0x8f,0x8d,0x83,0x81,0x87,0x85,
0xbb,0xb9,0xbf,0xbd,0xb3,0xb1,0xb7,0xb5,0xab,0xa9,0xaf,0xad,0xa3,0xa1,0xa7,0xa5,
0xdb,0xd9,0xdf,0xdd,0xd3,0xd1,0xd7,0xd5,0xcb,0xc9,0xcf,0xcd,0xc3,0xc1,0xc7,0xc5,
0xfb,0xf9,0xff,0xfd,0xf3,0xf1,0xf7,0xf5,0xeb,0xe9,0xef,0xed,0xe3,0xe1,0xe7,0xe5
};

typedef struct {
	unsigned char *plaintext;
	unsigned char *ciphertext;
	unsigned char *key;
	unsigned char *iv;
	int i;
} ctr_args;

typedef struct {
	unsigned char *plaintext;
	unsigned char *ciphertext;
	unsigned char *key;
	int i;
} xex_args;

//Electronic CodeBlock (ECB) Mode Encryption
void r3d_encrypt_ecb(unsigned char *plaintext, unsigned char *key, unsigned char *ciphertext, int size){
	int block_num=(size/512); //calculate the number of blocks in the plaintext

	unsigned char plaintext_block[512]; //plaintext block
	unsigned char ciphertext_block[512]; //ciphertext block
	unsigned char key_block[512]; //key block

	memcpy(key_block, key, 512); //copy the cryptographic key to the key block

	int i;
	for(i=0; i<block_num; i++){
		//copy a block from the plaintext buffer to the plaintext block
		memcpy(plaintext_block, plaintext+(i*512), 512);

		//encrypt the plaintext block
		r3d_encrypt_block(plaintext_block, key_block, ciphertext_block);

		//copy the ciphertext block to the ciphertext buffer
		memcpy(ciphertext+(i*512), ciphertext_block, 512);

		printf("%d\n", i); //print the iteration we are on
	}
}

//Electronic CodeBlock (ECB) Mode Decryption
void r3d_decrypt_ecb(unsigned char *ciphertext, unsigned char *key, unsigned char *plaintext, int size){
	int block_num=(size/512); //calculate the number of blocks in the ciphertext

	unsigned char ciphertext_block[512]; //ciphertext block
	unsigned char plaintext_block[512]; //plaintext block
	unsigned char key_block[512]; //key block

	memcpy(key_block, key, 512); //copy the cryptographic key to the key block

	int i;
	for(i=0; i<block_num; i++){
		//copy a block from the ciphertext buffer to the ciphertext block
		memcpy(ciphertext_block, ciphertext+(i*512), 512);

		//decrypt the ciphertext block
		r3d_decrypt_block(ciphertext_block, key_block, plaintext_block);

		//copy the plaintext block to the plaintext buffer
		memcpy(plaintext+(i*512), plaintext_block, 512);

		printf("%d\n", i); //print the iteration we are on
	}
}

//Counter (CTR) Mode Encryption
void r3d_encrypt_ctr(unsigned char *plaintext, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int size){
	int block_num=(size/512); //calculate the number of blocks in the plaintext

	unsigned char plaintext_block[512]; //plaintext block
	unsigned char ciphertext_block[512]; //ciphertext block
	unsigned char key_block[512]; //key block
	unsigned char iv_block[512]; //initialization vector (iv) block
	unsigned int i_block[512]; //counter block
	unsigned char temp_block[512]; //temporary block
	unsigned char keystream[512];

	memcpy(key_block, key, 512); //copy the cryptographic key to the key block
	memcpy(iv_block, iv, 512); //copy the initialization vector to the iv block

	int i;
	int j;
	for(i=0; i<block_num; i++){
		memset(i_block, i, 512); //set the counter block to the value of integer i

		//copy a block from the plaintext buffer to the plaintext block
		memcpy(plaintext_block, plaintext+(i*512), 512);

		//XOR the iv block with the i block to produce the temporary block
		for(j=0; j<512; j++){
			temp_block[j]=iv_block[j]^i_block[j];
		}

		//encrypt the temporary block to produce the keystream
		r3d_encrypt_block(temp_block, key, keystream);

		//XOR the plaintext with the keystream to produce the ciphertext
		for(j=0; j<512; j++){
			ciphertext_block[j]=plaintext_block[j]^keystream[j];
		}

		//copy the ciphertext block to the ciphertext buffer
		memcpy(ciphertext+(i*512), ciphertext_block, 512);

		printf("%d\n", i); //print the iteration we are on
	}
}

//Counter (CTR) Mode Decryption
void r3d_decrypt_ctr(unsigned char *ciphertext, unsigned char *key, unsigned char *iv, unsigned char *plaintext, int size){
	int block_num=(size/512); //calculate the number of blocks in the ciphertext

	unsigned char plaintext_block[512]; //plaintext block
	unsigned char ciphertext_block[512]; //ciphertext block
	unsigned char key_block[512]; //key block
	unsigned char iv_block[512]; //initialization vector (iv) block
	unsigned int i_block[512]; //counter block
	unsigned char temp_block[512]; //temporary block
	unsigned char keystream[512];

	memcpy(key_block, key, 512); //copy the cryptographic key to the key block
	memcpy(iv_block, iv, 512); //copy the initialization vector to the iv block

	int i;
	int j;
	for(i=0; i<block_num; i++){
		memset(i_block, i, 512); //set the counter block to the value of integer i

		//copy a block from the ciphertext buffer to the ciphertext block
		memcpy(ciphertext_block, ciphertext+(i*512), 512);

		//XOR the iv block with the i block to produce the temporary block
		for(j=0; j<512; j++){
			temp_block[j]=iv_block[j]^i_block[j];
		}

		//encrypt the temporary block to produce the keystream
		r3d_encrypt_block(temp_block, key, keystream);

		//XOR the ciphertext with the keystream to produce the plaintext
		for(j=0; j<512; j++){
			plaintext_block[j]=ciphertext_block[j]^keystream[j];
		}

		//copy the plaintext block to the plaintext buffer
		memcpy(plaintext+(i*512), plaintext_block, 512);

		printf("%d\n", i); //print the iteration we are on
	}
}

//XOR-Encrypt-XOR (XEX) Mode Encryption
void r3d_encrypt_xex(unsigned char *plaintext, unsigned char *key, unsigned char *ciphertext, int size){
	int block_num=(size/512); //calculate the number of blocks in the plaintext

	unsigned char plaintext_block[512]; //plaintext block
	unsigned char ciphertext_block[512]; //ciphertext block
	unsigned char key_block[512]; //key block

	unsigned int i_block[512]; //counter block
	unsigned char x_block[512]; //x block

	memcpy(key_block, key, 512); //copy the cryptographic key to the key block

	int i;
	int j;
	for(i=0; i<block_num; i++){
		memset(i_block, i, 512); //set the counter block to the value of integer i

		//encrypt the counter block to produce the x block
		r3d_encrypt_block((unsigned char *)i_block, key_block, x_block);

		//multiply the x block by 2 over GF(2^8)
		for(j=0; j<512; j++){
			x_block[j]=gf256[x_block[j]];
		}

		//copy a block from the plaintext buffer to the plaintext block
		memcpy(plaintext_block, plaintext+(i*512), 512);

		//XOR the plaintext block with the x block
		for(j=0; j<512; j++){
			plaintext_block[j]^=x_block[j];
		}

 		//encrypt the plaintext block
		r3d_encrypt_block(plaintext_block, key_block, ciphertext_block);

		//XOR the ciphertext block with the x block
		for(j=0; j<512; j++){
			ciphertext_block[j]^=x_block[j];
		}

		//copy the ciphertext block to the ciphertext buffer
		memcpy(ciphertext+(i*512), ciphertext_block, 512);

		printf("%d\n", i); //print the iteration we are on
	}
}

//XOR-Encrypt-XOR (XEX) Mode Decryption
void r3d_decrypt_xex(unsigned char *ciphertext, unsigned char *key, unsigned char *plaintext, int size){
	int block_num=(size/512); //calculate the number of blocks in the ciphertext

	unsigned char plaintext_block[512]; //plaintext block
	unsigned char ciphertext_block[512]; //ciphertext block
	unsigned char key_block[512]; //key block

	unsigned int i_block[512]; //counter block
	unsigned char x_block[512]; //x block

	memcpy(key_block, key, 512); //copy the cryptographic key to the key block

	int i;
	int j;
	for(i=0; i<block_num; i++){
		memset(i_block, i, 512); //set the counter block to the value of integer i

		//encrypt the counter block to produce the x block
		r3d_encrypt_block((unsigned char *)i_block, key_block, x_block);

		//multiply the x block by 2 over GF(2^8)
		for(j=0; j<512; j++){
			x_block[j]=gf256[x_block[j]];
		}

		//copy a block from the ciphertext buffer to the ciphertext block
		memcpy(ciphertext_block, ciphertext+(i*512), 512);

		//XOR the ciphertext block with the x block
		for(j=0; j<512; j++){
			ciphertext_block[j]^=x_block[j];
		}

		//decrypt the ciphertext block
		r3d_decrypt_block(ciphertext_block, key_block, plaintext_block);

		//XOR the plaintext block with the x block
		for(j=0; j<512; j++){
			plaintext_block[j]^=x_block[j];
		}

		//copy the plaintext block to the plaintext buffer
		memcpy(plaintext+(i*512), plaintext_block, 512);

		printf("%d\n", i); //print the iteration we are on
	}
}

void r3d_encrypt_ctr_mt(unsigned char *plaintext, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int size, int num_threads){
	int block_num=(size/512); //calculate the number of blocks in the plaintext
	int i;
	int j;

	pthread_t tid[num_threads];
	ctr_args args[num_threads];
	for(i=0; i<num_threads; i++){
		args[i]=(ctr_args){plaintext, ciphertext, key, iv, i};
	}

	for(i=0; i<=block_num; i+=num_threads){
		for(j=0; j<num_threads; j++){
			args[j].i=i+j;
			pthread_create(&tid[j], NULL, ctr_encrypt_thread, &args[j]);
		}
		for(j=0; j<num_threads; j++){
			pthread_join(tid[j], NULL);
		}
		printf("%d\n", i);
	}
}

void r3d_decrypt_ctr_mt(unsigned char *ciphertext, unsigned char *key, unsigned char *iv, unsigned char *plaintext, int size, int num_threads){
	int block_num=(size/512); //calculate the number of blocks in the ciphertext
	int i;
	int j;

	pthread_t tid[num_threads];
	ctr_args args[num_threads];
	for(i=0; i<num_threads; i++){
		args[i]=(ctr_args){plaintext, ciphertext, key, iv, i};
	}

	for(i=0; i<=block_num; i+=num_threads){
		for(j=0; j<num_threads; j++){
			args[j].i=i+j;
			pthread_create(&tid[j], NULL, ctr_decrypt_thread, &args[j]);
		}
		for(j=0; j<num_threads; j++){
			pthread_join(tid[j], NULL);
		}
		printf("%d\n", i);
	}
}

void *ctr_encrypt_thread(void *vargp){
	unsigned char plaintext_block[512];
	unsigned char ciphertext_block[512];
	unsigned char key_block[512];
	unsigned char iv_block[512];
	unsigned int i_block[512];
	unsigned char temp_block[512];
	unsigned char keystream[512];

	ctr_args *args=vargp;

	int j;

	memcpy(key_block, &args->key, 512);
	memcpy(iv_block, &args->iv, 512);
	memset(i_block, args->i, 512);
	memcpy(plaintext_block, args->plaintext+(args->i*512), 512);

	for(j=0; j<512; j++){
		temp_block[j]=iv_block[j]^i_block[j];
	}

	r3d_encrypt_block(temp_block, key_block, keystream);
	for(j=0; j<512; j++){
		ciphertext_block[j]=plaintext_block[j]^keystream[j];
	}

	memcpy(args->ciphertext+(args->i*512), ciphertext_block, 512);
	pthread_exit(NULL);
}

void *ctr_decrypt_thread(void *vargp){
	unsigned char plaintext_block[512];
	unsigned char ciphertext_block[512];
	unsigned char key_block[512];
	unsigned char iv_block[512];
	unsigned int i_block[512];
	unsigned char temp_block[512];
	unsigned char keystream[512];

	ctr_args *args=vargp;

	int j;

	memcpy(key_block, &args->key, 512);
	memcpy(iv_block, &args->iv, 512);
	memset(i_block, args->i, 512);
	memcpy(ciphertext_block, args->ciphertext+(args->i*512), 512);

	for(j=0; j<512; j++){
		temp_block[j]=iv_block[j]^i_block[j];
	}

	r3d_encrypt_block(temp_block, key_block, keystream);
	for(j=0; j<512; j++){
		plaintext_block[j]=ciphertext_block[j]^keystream[j];
	}

	memcpy(args->plaintext+(args->i*512), plaintext_block, 512);
	pthread_exit(NULL);
}


void r3d_encrypt_xex_mt(unsigned char *plaintext, unsigned char *key, unsigned char *ciphertext, int size, int num_threads){
	int block_num=(size/512); //calculate the number of blocks in the plaintext
	int i;
	int j;

	pthread_t tid[num_threads];
	xex_args args[num_threads];
	for(i=0; i<num_threads; i++){
		args[i]=(xex_args){plaintext, ciphertext, key, i};
	}

	for(i=0; i<=block_num; i+=num_threads){
		for(j=0; j<num_threads; j++){
			args[j].i=i+j;
			pthread_create(&tid[j], NULL, xex_encrypt_thread, &args[j]);
		}
		for(j=0; j<num_threads; j++){
			pthread_join(tid[j], NULL);
		}
		printf("%d\n", i);
	}
}

void r3d_decrypt_xex_mt(unsigned char *ciphertext, unsigned char *key, unsigned char *plaintext, int size, int num_threads){
	int block_num=(size/512); //calculate the number of blocks in the ciphertext
	int i;
	int j;

	pthread_t tid[num_threads];
	xex_args args[num_threads];
	for(i=0; i<num_threads; i++){
		args[i]=(xex_args){plaintext, ciphertext, key, i};
	}

	for(i=0; i<=block_num; i+=num_threads){
		for(j=0; j<num_threads; j++){
			args[j].i=i+j;
			pthread_create(&tid[j], NULL, xex_decrypt_thread, &args[j]);
		}
		for(j=0; j<num_threads; j++){
			pthread_join(tid[j], NULL);
		}
		printf("%d\n", i);
	}
}

void *xex_encrypt_thread(void *vargp){
	unsigned char plaintext_block[512]; //plaintext block
	unsigned char ciphertext_block[512]; //ciphertext block
	unsigned char key_block[512]; //key block
	unsigned int i_block[512]; //counter block
	unsigned char x_block[512]; //x block

	xex_args *args=vargp;

	int j;

	memcpy(key_block, args->key, 512); //copy the cryptographic key to the key block
	memset(i_block, args->i, 512); //set the counter block to the value of integer i

	//encrypt the counter block to produce the x block
	r3d_encrypt_block((unsigned char *)i_block, key_block, x_block);

	//multiply the x block by 2 over GF(2^8)
	for(j=0; j<512; j++){
		x_block[j]=gf256[x_block[j]];
	}

	//copy a block from the plaintext buffer to the plaintext block
	memcpy(plaintext_block, args->plaintext+(args->i*512), 512);

	//XOR the plaintext block with the x block
	for(j=0; j<512; j++){
		plaintext_block[j]^=x_block[j];
	}

	//encrypt the plaintext block
	r3d_encrypt_block(plaintext_block, key_block, ciphertext_block);

	//XOR the ciphertext block with the x block
	for(j=0; j<512; j++){
		ciphertext_block[j]^=x_block[j];
	}

	//copy the ciphertext block to the ciphertext buffer
	memcpy(args->ciphertext+(args->i*512), ciphertext_block, 512);
	pthread_exit(0);
}

void *xex_decrypt_thread(void *vargp){
	unsigned char plaintext_block[512]; //plaintext block
	unsigned char ciphertext_block[512]; //ciphertext block
	unsigned char key_block[512]; //key block
	unsigned int i_block[512]; //counter block
	unsigned char x_block[512]; //x block

	xex_args *args=vargp;

	int j;

	memcpy(key_block, args->key, 512); //copy the cryptographic key to the key block
	memset(i_block, args->i, 512); //set the counter block to the value of integer i

	//encrypt the counter block to produce the x block
	r3d_encrypt_block((unsigned char *)i_block, key_block, x_block);

	//multiply the x block by 2 over GF(2^8)
	for(j=0; j<512; j++){
		x_block[j]=gf256[x_block[j]];
	}

	//copy a block from the ciphertext buffer to the ciphertext block
	memcpy(ciphertext_block, args->ciphertext+(args->i*512), 512);

	//XOR the ciphertext block with the x block
	for(j=0; j<512; j++){
		ciphertext_block[j]^=x_block[j];
	}

	//decrypt the ciphertext block
	r3d_decrypt_block(ciphertext_block, key_block, plaintext_block);

	//XOR the plaintext block with the x block
	for(j=0; j<512; j++){
		plaintext_block[j]^=x_block[j];
	}

	//copy the plaintext block to the plaintext buffer
	memcpy(args->plaintext+(args->i*512), plaintext_block, 512);
	pthread_exit(0);
}
