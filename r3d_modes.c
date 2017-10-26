/*
R3D Block Cipher Modes of Operation
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

#include <string.h>
#include <malloc.h>
#include <pthread.h>

#include <r3d.h>

void r3d_encrypt_block(unsigned char plaintext_block[512], unsigned char key[512], unsigned char ciphertext_block[512]);
void r3d_decrypt_block(unsigned char ciphertext_block[512], unsigned char key[512], unsigned char plaintext_block[512]);

void r3d_encrypt_ecb(unsigned char *plaintext, unsigned char *key, unsigned char *ciphertext, int size);
void r3d_decrypt_ecb(unsigned char *ciphertext, unsigned char *key, unsigned char *plaintext, int size);

void r3d_encrypt_ctr(unsigned char *plaintext, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int size);
void r3d_decrypt_ctr(unsigned char *ciphertext, unsigned char *key, unsigned char *iv, unsigned char *plaintext, int size);

void r3d_encrypt_xex(unsigned char *plaintext, unsigned char *key, unsigned char *ciphertext, int size);
void r3d_decrypt_xex(unsigned char *ciphertext, unsigned char *key, unsigned char *plaintext, int size);

//TODO: Fix CTR mode multithreaded functions
void r3d_encrypt_ctr_mt(unsigned char *plaintext, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int size);
void r3d_decrypt_ctr_mt(unsigned char *ciphertext, unsigned char *key, unsigned char *iv, unsigned char *plaintext, int size);
void *ctr_encrypt_thread(void *vargp);
void *ctr_decrypt_thread(void *vargp);

void r3d_encrypt_xex_mt(unsigned char *plaintext, unsigned char *key, unsigned char *ciphertext, int size);
void r3d_decrypt_xex_mt(unsigned char *ciphertext, unsigned char *key, unsigned char *plaintext, int size);
void *xex_encrypt_thread(void *vargp);
void *xex_decrypt_thread(void *vargp);

unsigned char gmul8(unsigned char x, unsigned char y);
unsigned char gmul128(unsigned char x, unsigned char y);

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

		//TODO: gmul8 function
		/*for(j=0; j<512; j++){
			x_block[j]=gmul8(x_block[j], 2);
		}*/

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

		//TODO: gmul8 function
		/*for(j=0; j<512; j++){
			x_block[j]=gmul8(x_block[j], 2);
		}*/

		//copy the plaintext block to the plaintext buffer
		memcpy(plaintext+(i*512), plaintext_block, 512);

		printf("%d\n", i); //print the iteration we are on
	}
}

//TODO: Fix CTR mode multithreaded functions
void r3d_encrypt_ctr_mt(unsigned char *plaintext, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int size){
	int block_num=(size/512); //calculate the number of blocks in the plaintext
	int i;
	int j;

	int num_threads=1;

	pthread_t tid[num_threads];
	ctr_args args[num_threads];
	for(i=0; i<num_threads; i++){
		args[i]=(ctr_args){plaintext, ciphertext, key, iv, i};
	}

	for(i=0; i<=block_num; i+=num_threads){
		for(j=0; j<num_threads; j++){
			args[j].i=i+j;
		}
		for(j=0; j<num_threads; j++){
			pthread_create(&tid[j], NULL, ctr_encrypt_thread, &args[j]);
		}
		for(j=0; j<num_threads; j++){
			pthread_join(tid[j], NULL);
		}
		printf("%d\n", i);
	}
}

void r3d_decrypt_ctr_mt(unsigned char *ciphertext, unsigned char *key, unsigned char *iv, unsigned char *plaintext, int size){
	int block_num=(size/512); //calculate the number of blocks in the ciphertext
	int i;
	int j;

	int num_threads=1;

	pthread_t tid[num_threads];
	ctr_args args[num_threads];
	for(i=0; i<num_threads; i++){
		args[i]=(ctr_args){plaintext, ciphertext, key, iv, i};
	}

	for(i=0; i<=block_num; i+=num_threads){
		for(j=0; j<num_threads; j++){
			args[j].i=i+j;
		}
		for(j=0; j<num_threads; j++){
			pthread_create(&tid[j], NULL, ctr_encrypt_thread, &args[j]);
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


void r3d_encrypt_xex_mt(unsigned char *plaintext, unsigned char *key, unsigned char *ciphertext, int size){
	int block_num=(size/512); //calculate the number of blocks in the plaintext
	int i;
	int j;

	int num_threads=4;

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
		pthread_join(tid[num_threads-1], NULL);
		/*for(j=0; j<num_threads; j++){
			pthread_join(tid[j], NULL);
		}*/
		printf("%d\n", i);
	}
}

void r3d_decrypt_xex_mt(unsigned char *ciphertext, unsigned char *key, unsigned char *plaintext, int size){
	int block_num=(size/512); //calculate the number of blocks in the ciphertext
	int i;
	int j;

	int num_threads=4;

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
		pthread_join(tid[num_threads-1], NULL);
		/*for(j=0; j<num_threads; j++){
			pthread_join(tid[j], NULL);
		}*/
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

	//TODO: gmul8 function
	/*for(j=0; j<512; j++){
		x_block[j]=gmul8(x_block[j], 2);
	}*/

	//copy the ciphertext block to the ciphertext buffer
	memcpy(args->ciphertext+(args->i*512), ciphertext_block, 512);
	pthread_exit(NULL);
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

	//TODO: gmul8 function
	/*for(j=0; j<512; j++){
		x_block[j]=gmul8(x_block[j], 2);
	}*/

	//copy the plaintext block to the plaintext buffer
	memcpy(args->plaintext+(args->i*512), plaintext_block, 512);
	pthread_exit(NULL);
}
