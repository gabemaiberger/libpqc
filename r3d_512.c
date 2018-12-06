/*
R3D-512 Cipher
Copyright (C) 2017-2018 Gabriel Nathan Maiberger

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

void r3d_encrypt_block(unsigned char plaintext_block[64], unsigned char key[64], unsigned char ciphertext_block[64]);
void r3d_decrypt_block(unsigned char ciphertext_block[64], unsigned char key[64], unsigned char plaintext_block[64]);

void SubBytes();
void InvSubBytes();
void ShiftRows();
void InvShiftRows();
void ShiftSlices();
void InvShiftSlices();
void MixColumns();
void InvMixColumns();
void AddRoundKey(unsigned char key[4][4][4]);
void ExpandKey();
void GetRoundKey(unsigned int r);

unsigned char gmul(unsigned char x, unsigned char y);

const unsigned char s[256] = { //substitution box
0xFA, 0x62, 0xA0, 0xEA, 0x81, 0xC9, 0x2F, 0x22, 0xE5, 0xA9, 0xBD, 0x1E, 0x13, 0x4D, 0x65, 0xC8,
0x87, 0x17, 0xBB, 0x88, 0xB8, 0x45, 0x57, 0x95, 0xF3, 0x0B, 0x9E, 0xD7, 0x68, 0x11, 0x8A, 0xB2,
0x3B, 0xA8, 0x1D, 0xA5, 0xF8, 0x5D, 0x3E, 0x8F, 0xD2, 0x0E, 0x80, 0x06, 0x54, 0x4B, 0x3D, 0x6E,
0xF0, 0x28, 0x02, 0x6D, 0xE9, 0x63, 0x32, 0x23, 0x82, 0x1C, 0xC3, 0xB3, 0x15, 0xB4, 0x0F, 0xC7,
0x12, 0x39, 0x19, 0x58, 0x7C, 0x99, 0xA1, 0x26, 0x89, 0xB7, 0x77, 0xC2, 0xD5, 0x66, 0x73, 0xDD,
0xBF, 0x40, 0x72, 0x0D, 0x4A, 0x97, 0x5C, 0x2B, 0xFD, 0xBE, 0x6B, 0xD1, 0x44, 0x9A, 0x69, 0x0A,
0x75, 0x6F, 0x70, 0x16, 0xEB, 0xFB, 0xBA, 0x33, 0x36, 0x3F, 0x78, 0x21, 0x74, 0x2E, 0xB1, 0x8E,
0x5B, 0x7B, 0x7A, 0xAD, 0x4E, 0x7E, 0xAF, 0xA4, 0xF6, 0x10, 0xB5, 0xC1, 0x48, 0xF1, 0x3C, 0xA6,
0x09, 0xE7, 0xCE, 0x8B, 0x24, 0x20, 0xDE, 0xD4, 0x9F, 0xAE, 0x79, 0x07, 0x61, 0xA2, 0xDB, 0x5E,
0xD8, 0x4C, 0xEE, 0xED, 0x7D, 0xC6, 0x71, 0xFE, 0x29, 0xFF, 0x31, 0xC5, 0x59, 0xFC, 0xDA, 0x98,
0x2A, 0x6A, 0xE6, 0x42, 0xB0, 0xCD, 0x04, 0x91, 0xF9, 0x14, 0x47, 0x27, 0x83, 0x34, 0x1F, 0xEC,
0x2D, 0x18, 0x5A, 0x76, 0x60, 0xE4, 0x50, 0x25, 0x3A, 0x56, 0x03, 0xD9, 0x85, 0x6C, 0x90, 0xE8,
0x41, 0x94, 0x92, 0x30, 0x05, 0x38, 0x84, 0xD6, 0xCA, 0x51, 0xAC, 0x43, 0x8C, 0xD3, 0xA7, 0xC0,
0x0C, 0x1A, 0x67, 0xAB, 0xD0, 0xF4, 0x1B, 0xBC, 0x8D, 0xF7, 0x5F, 0xAA, 0x08, 0x46, 0x35, 0xB6,
0x00, 0xE0, 0x9B, 0xCF, 0xEF, 0x86, 0x9D, 0x4F, 0xE3, 0xDF, 0xE1, 0x93, 0xB9, 0xE2, 0x53, 0x64,
0x7F, 0xCB, 0xCC, 0x01, 0x9C, 0x2C, 0xA3, 0xF5, 0x52, 0x55, 0x49, 0x96, 0xDC, 0xC4, 0xF2, 0x37
};

const unsigned char inv_s[256] = { //inverse substitution box
0xE0, 0xF3, 0x32, 0xBA, 0xA6, 0xC4, 0x2B, 0x8B, 0xDC, 0x80, 0x5F, 0x19, 0xD0, 0x53, 0x29, 0x3E,
0x79, 0x1D, 0x40, 0x0C, 0xA9, 0x3C, 0x63, 0x11, 0xB1, 0x42, 0xD1, 0xD6, 0x39, 0x22, 0x0B, 0xAE,
0x85, 0x6B, 0x07, 0x37, 0x84, 0xB7, 0x47, 0xAB, 0x31, 0x98, 0xA0, 0x57, 0xF5, 0xB0, 0x6D, 0x06,
0xC3, 0x9A, 0x36, 0x67, 0xAD, 0xDE, 0x68, 0xFF, 0xC5, 0x41, 0xB8, 0x20, 0x7E, 0x2E, 0x26, 0x69,
0x51, 0xC0, 0xA3, 0xCB, 0x5C, 0x15, 0xDD, 0xAA, 0x7C, 0xFA, 0x54, 0x2D, 0x91, 0x0D, 0x74, 0xE7,
0xB6, 0xC9, 0xF8, 0xEE, 0x2C, 0xF9, 0xB9, 0x16, 0x43, 0x9C, 0xB2, 0x70, 0x56, 0x25, 0x8F, 0xDA,
0xB4, 0x8C, 0x01, 0x35, 0xEF, 0x0E, 0x4D, 0xD2, 0x1C, 0x5E, 0xA1, 0x5A, 0xBD, 0x33, 0x2F, 0x61,
0x62, 0x96, 0x52, 0x4E, 0x6C, 0x60, 0xB3, 0x4A, 0x6A, 0x8A, 0x72, 0x71, 0x44, 0x94, 0x75, 0xF0,
0x2A, 0x04, 0x38, 0xAC, 0xC6, 0xBC, 0xE5, 0x10, 0x13, 0x48, 0x1E, 0x83, 0xCC, 0xD8, 0x6F, 0x27,
0xBE, 0xA7, 0xC2, 0xEB, 0xC1, 0x17, 0xFB, 0x55, 0x9F, 0x45, 0x5D, 0xE2, 0xF4, 0xE6, 0x1A, 0x88,
0x02, 0x46, 0x8D, 0xF6, 0x77, 0x23, 0x7F, 0xCE, 0x21, 0x09, 0xDB, 0xD3, 0xCA, 0x73, 0x89, 0x76,
0xA4, 0x6E, 0x1F, 0x3B, 0x3D, 0x7A, 0xDF, 0x49, 0x14, 0xEC, 0x66, 0x12, 0xD7, 0x0A, 0x59, 0x50,
0xCF, 0x7B, 0x4B, 0x3A, 0xFD, 0x9B, 0x95, 0x3F, 0x0F, 0x05, 0xC8, 0xF1, 0xF2, 0xA5, 0x82, 0xE3,
0xD4, 0x5B, 0x28, 0xCD, 0x87, 0x4C, 0xC7, 0x1B, 0x90, 0xBB, 0x9E, 0x8E, 0xFC, 0x4F, 0x86, 0xE9,
0xE1, 0xEA, 0xED, 0xE8, 0xB5, 0x08, 0xA2, 0x81, 0xBF, 0x34, 0x03, 0x64, 0xAF, 0x93, 0x92, 0xE4,
0x30, 0x7D, 0xFE, 0x18, 0xD5, 0xF7, 0x78, 0xD9, 0x24, 0xA8, 0x00, 0x65, 0x9D, 0x58, 0x97, 0x99
};

const unsigned char rcon[51][4] = { //round constants
0x01, 0x00, 0x00, 0x00,
0x02, 0x00, 0x00, 0x00,
0x04, 0x00, 0x00, 0x00,
0x08, 0x00, 0x00, 0x00,
0x10, 0x00, 0x00, 0x00,
0x20, 0x00, 0x00, 0x00,
0x40, 0x00, 0x00, 0x00,
0x80, 0x00, 0x00, 0x00,
0x1B, 0x00, 0x00, 0x00,
0x36, 0x00, 0x00, 0x00,
0x6C, 0x00, 0x00, 0x00,
0xD8, 0x00, 0x00, 0x00,
0xAB, 0x00, 0x00, 0x00,
0x4D, 0x00, 0x00, 0x00,
0x9A, 0x00, 0x00, 0x00,
0x2F, 0x00, 0x00, 0x00,
0x5E, 0x00, 0x00, 0x00,
0xBC, 0x00, 0x00, 0x00,
0x63, 0x00, 0x00, 0x00,
0xC6, 0x00, 0x00, 0x00,
0x97, 0x00, 0x00, 0x00,
0x35, 0x00, 0x00, 0x00,
0x6A, 0x00, 0x00, 0x00,
0xD4, 0x00, 0x00, 0x00,
0xB3, 0x00, 0x00, 0x00,
0x7D, 0x00, 0x00, 0x00,
0xFA, 0x00, 0x00, 0x00,
0xEF, 0x00, 0x00, 0x00,
0xC5, 0x00, 0x00, 0x00,
0x91, 0x00, 0x00, 0x00,
0x39, 0x00, 0x00, 0x00,
0x72, 0x00, 0x00, 0x00,
0xE4, 0x00, 0x00, 0x00,
0xD3, 0x00, 0x00, 0x00,
0xBD, 0x00, 0x00, 0x00,
0x61, 0x00, 0x00, 0x00,
0xC2, 0x00, 0x00, 0x00,
0x9F, 0x00, 0x00, 0x00,
0x25, 0x00, 0x00, 0x00,
0x4A, 0x00, 0x00, 0x00,
0x94, 0x00, 0x00, 0x00,
0x33, 0x00, 0x00, 0x00,
0x66, 0x00, 0x00, 0x00,
0xCC, 0x00, 0x00, 0x00,
0x83, 0x00, 0x00, 0x00,
0x1D, 0x00, 0x00, 0x00,
0x3A, 0x00, 0x00, 0x00,
0x74, 0x00, 0x00, 0x00,
0xE8, 0x00, 0x00, 0x00,
0xCB, 0x00, 0x00, 0x00,
0x8D, 0x00, 0x00, 0x00
};

const unsigned char kcon[4][4] = { //slice constants
0x01, 0x00, 0x00, 0x00,
0x02, 0x00, 0x00, 0x00,
0x04, 0x00, 0x00, 0x00,
0x08, 0x00, 0x00, 0x00
};

unsigned char state[4][4][4]; //temporary state for algorithm

unsigned char master_key[4][4][4]; //master key
unsigned char round_key[4][4][4]; //round key
unsigned char key_schedule[51][4][4][4]; //key schedule

//encrypt one block (64 bytes) of data
void r3d_encrypt_block(unsigned char plaintext_block[64], unsigned char key[64], unsigned char ciphertext_block[64]){
	int i;
	int j;
	int k;

	//copy the plaintext block into the state
	for(k=0; k<4; k++){
		for(j=0; j<4; j++){
			for(i=0; i<4; i++){
				state[k][i][j]=plaintext_block[(k*4+j)*4+i];
				master_key[k][j][i]=key[(k*4+j)*4+i];
			}
		}
	}

	//initial round
	ExpandKey();
	AddRoundKey(master_key);

	//one round of encryption
	for(i=1; i<=14; i++){
		SubBytes();
		if(i % 2 == 0){
			ShiftSlices();
		} else {
			ShiftRows();
		}
		MixColumns();
		GetRoundKey(i);
		AddRoundKey(round_key);
	}

	//final round
	SubBytes();
	ShiftRows();
	GetRoundKey(15);
	AddRoundKey(round_key);

	//copy the state into the ciphertext block
	for(k=0; k<4; k++){
		for(j=0; j<4; j++){
			for(i=0; i<4; i++){
				ciphertext_block[(k*4+j)*4+i]=state[k][i][j];
			}
		}
	}
}

//decrypt one block (64 bytes) of data
void r3d_decrypt_block(unsigned char ciphertext_block[64], unsigned char key[64], unsigned char plaintext_block[64]){
	int i;
	int j;
	int k;

	//copy the ciphertext block into the state
	for(k=0; k<4; k++){
		for(j=0; j<4; j++){
			for(i=0; i<4; i++){
				state[k][i][j]=ciphertext_block[(k*4+j)*4+i];
				master_key[k][j][i]=key[(k*4+j)*4+i];
			}
		}
	}

	//initial round
	ExpandKey();
	GetRoundKey(15);
	AddRoundKey(round_key);

	//one round of decryption
	for(i=14; i>=1; i--){
		if(i % 2 == 0){
			InvShiftRows();
		} else {
			InvShiftSlices();
		}
		InvSubBytes();
		GetRoundKey(i);
		AddRoundKey(round_key);
		InvMixColumns();
	}

	//final round
	InvShiftRows();
	InvSubBytes();
	AddRoundKey(master_key);

	//copy the state into the plaintext block
	for(k=0; k<4; k++){
		for(j=0; j<4; j++){
			for(i=0; i<4; i++){
				plaintext_block[(k*4+j)*4+i]=state[k][i][j];
			}
		}
	}
}

//substitute bytes
void SubBytes(){
	int i;
	int j;
	int k;

	for(k=0; k<4; k++){
		for(j=0; j<4; j++){
			for(i=0; i<4; i++){
				state[k][j][i]=s[state[k][j][i]]; //lookup the result in the sbox
			}
		}
	}
}

//inverse substitute bytes
void InvSubBytes(){
	int i;
	int j;
	int k;

	for(k=0; k<4; k++){
		for(j=0; j<4; j++){
			for(i=0; i<4; i++){
				state[k][j][i]=inv_s[state[k][j][i]]; //lookup the result in the inverse sbox
			}
		}
	}
}

//shift state rows
void ShiftRows(){
	int i;
	int j;
	int k;
	unsigned char temp[4];

	for(k=0; k<4; k++){
		for(j=1; j<4; j++){
			for(i=0; i<4; i++){
				temp[i]=state[k][j][(i+j)%4]; //shift to the left j times
			}
			for(i=0; i<4; i++){
				state[k][j][i]=temp[i]; //store the result
			}
		}
	}
}

//inverse shift state rows
void InvShiftRows(){
	int i;
	int j;
	int k;
	unsigned char temp[4];

	for(k=0; k<4; k++){
		for(j=1; j<4; j++){
			for(i=0; i<4; i++){
				temp[(i+j)%4]=state[k][j][i]; //shift to the right j times
			}
			for(i=0; i<4; i++){
				state[k][j][i]=temp[i]; //store the result
			}
		}
	}
}

//shift state slices
void ShiftSlices(){
	int i;
	int j;
	int k;
	unsigned char temp[4];

	for(i=0; i<4; i++){
		for(j=1; j<4; j++){
			for(k=0; k<4; k++){
				temp[k]=state[(k+j)%4][j][i]; //shift backward j times
			}
			for(k=0; k<4; k++){
				state[k][j][i]=temp[k]; //store the result
			}
		}
	}
}

//inverse shift state slices
void InvShiftSlices(){
	int i;
	int j;
	int k;
	unsigned char temp[4];

	for(i=0; i<4; i++){
		for(j=1; j<4; j++){
			for(k=0; k<4; k++){
				temp[(k+j)%4]=state[k][j][i]; //shift forward j times
			}
			for(k=0; k<4; k++){
				state[k][j][i]=temp[k]; //store the result
			}
		}
	}
}

//mix columns of state
void MixColumns(){
	int i;
	int j;
	int k;

	unsigned char temp_state[4][4][4];

	for(k=0; k<4; k++){
		for(j=0; j<4; j++){
			for(i=0; i<4; i++){
				temp_state[k][j][i]=state[k][j][i]; //backup our state
			}
		}
	}

	for(k=0; k<4; k++){
		for(i=0; i<4; i++){
				state[k][0][i]=gmul(temp_state[k][0][i], 2)^gmul(temp_state[k][1][i], 3)^temp_state[k][2][i]^ \
				temp_state[k][3][i];

				state[k][1][i]=temp_state[k][0][i]^gmul(temp_state[k][1][i], 2)^gmul(temp_state[k][2][i], 3)^ \
				temp_state[k][3][i];

				state[k][2][i]=temp_state[k][0][i]^temp_state[k][1][i]^gmul(temp_state[k][2][i], 2)^ \
				gmul(temp_state[k][3][i], 3);

				state[k][3][i]=gmul(temp_state[k][0][i], 3)^temp_state[k][1][i]^temp_state[k][2][i]^ \
				gmul(temp_state[k][3][i], 2);
		}
	}
}

//inverse mix columns of state
void InvMixColumns(){
	int i;
	int j;
	int k;

	unsigned char temp_state[4][4][4];

	for(k=0; k<4; k++){
		for(j=0; j<4; j++){
			for(i=0; i<4; i++){
				temp_state[k][j][i]=state[k][j][i];
			}
		}
	}

	for(k=0; k<4; k++){
		for(i=0; i<4; i++){
				state[k][0][i]=gmul(temp_state[k][0][i], 14)^gmul(temp_state[k][1][i], 11)^gmul(temp_state[k][2][i], 13)^ \
				gmul(temp_state[k][3][i], 9);

				state[k][1][i]=gmul(temp_state[k][0][i], 9)^gmul(temp_state[k][1][i], 14)^gmul(temp_state[k][2][i], 11)^ \
				gmul(temp_state[k][3][i], 13);

				state[k][2][i]=gmul(temp_state[k][0][i], 13)^gmul(temp_state[k][1][i], 9)^gmul(temp_state[k][2][i], 14)^ \
				gmul(temp_state[k][3][i], 11);

				state[k][3][i]=gmul(temp_state[k][0][i], 11)^gmul(temp_state[k][1][i], 13)^gmul(temp_state[k][2][i], 9)^ \
				gmul(temp_state[k][3][i], 14);
		}
	}
}

//add the round key to the state
void AddRoundKey(unsigned char round_key[4][4][4]){
	int i;
	int j;
	int k;

	for(k=0; k<4; k++){
		for(j=0; j<4; j++){
			for(i=0; i<4; i++){
				state[k][j][i]=state[k][j][i]^round_key[k][j][i]; //XOR the round key with the state
			}
		}
	}
}

//expand the key
void ExpandKey(){
	int i;
	int j;
	int k;
	unsigned char temp[4];

	for(k=0; k<4; k++){
		for(j=0; j<4; j++){
			for(i=0; i<4; i++){
				//copy the master key into round 0 of the key schedule
				key_schedule[0][k][j][i]=master_key[k][j][i];
			}
		}
	}

	int r_i;
	for(r_i=1; r_i<=15; r_i++){
		for(k=0; k<4; k++){
			if(k==0){
				//copy the final column from the final slice of the
				//previous round to the first column of the current slice
				for(j=0; j<4; j++){
					key_schedule[r_i][0][j][0]=key_schedule[r_i-1][3][j][3];
				}
			} else if(k>0){
				//copy the final column of the previous slice
				//to the first column of the current slice
				for(j=0; j<4; j++){
					key_schedule[r_i][k][j][0]=key_schedule[r_i][k-1][j][3];
				}
			}

			//rotate column by one
			for(j=0; j<4; j++){
				temp[(j+1)%4]=key_schedule[r_i][k][j][0];
			}
			for(j=0; j<4; j++){
				key_schedule[r_i][k][j][0]=temp[j];
			}

			//SubBytes
			for(j=0; j<4; j++){
				key_schedule[r_i][k][j][0]=s[key_schedule[r_i][k][j][0]];
			}

			if(k==0){
				//XOR with round constant (Rcon)
				key_schedule[r_i][0][0][0]=key_schedule[r_i][0][0][0]^rcon[r_i-1][j];
			} else if(k>0){
				//XOR with slice constant (Kcon)
				key_schedule[r_i][k][0][0]=key_schedule[r_i][k][0][0]^kcon[k-1][j];
			}

			if(k==0){
				//XOR with final slice of previous round
				for(j=0; j<4; j++){
					key_schedule[r_i][0][j][0]=key_schedule[r_i][0][j][0]^key_schedule[r_i-1][3][j][0];
				}

				for(i=1; i<4; i++){
					for(j=0; j<4; j++){
						key_schedule[r_i][0][j][i]=key_schedule[r_i][0][j][i-1]^key_schedule[r_i-1][3][j][i];
					}
				}
			} else if(k>0){
				//XOR with previous slice
				for(j=0; j<4; j++){
					key_schedule[r_i][k][j][0]=key_schedule[r_i][k][j][0]^key_schedule[r_i][k-1][j][0];
				}

				for(i=1; i<4; i++){
					for(j=0; j<4; j++){
						key_schedule[r_i][k][j][i]=key_schedule[r_i][k][j][i-1]^key_schedule[r_i][k-1][j][i];
					}
				}
			}

			//shift columns of current slice
			for(j=1; j<4; j++){
				for(i=0; i<4; i++){
					temp[i]=key_schedule[r_i][k][j][(i+j)%4]; //shift to the left j times 
				}
				for(i=0; i<4; i++){
					key_schedule[r_i][k][j][i]=temp[i]; //store the result
				}
			}
		}
	}
}

//get a round key from the key schedule
void GetRoundKey(unsigned int r){
	int i;
	int j;
	int k;

	for(k=0; k<4; k++){
		for(j=0; j<4; j++){
			for(i=0; i<4; i++){
				round_key[k][j][i]=key_schedule[r][k][j][i];
			}
		}
	}
}

//galois field multiplication
unsigned char gmul(unsigned char x, unsigned char y){
	unsigned char z;

	if(y==2){
		z=x<<1;
		if((z>>8)>0){
			z^=0x11B;
		}
	} else if(y==3){
		z=x<<1;
		if((z>>8)>0){
			z^=0x11B;
		}
		z^=x;
	} else if(y==9){
		z=x<<1;
		if((z>>8)>0){
			z^=0x11B;
		}
		z=z<<1;
		if((z>>8)>0){
			z^=0x11B;
		}
		z=z<<1;
		if((z>>8)>0){
			z^=0x11B;
		}
		z^=x;
	} else if(y==11){
		z=x<<1;
		if((z>>8)>0){
			z^=0x11B;
		}
		z=z<<1;
		if((z>>8)>0){
			z^=0x11B;
		}
		z^=x;

		z=z<<1;
		if((z>>8)>0){
			z^=0x11B;
		}
		z^=x;
	} else if(y==13){
		z=x<<1;
		if((z>>8)>0){
			z^=0x11B;
		}
		z^=x;

		z=z<<1;
		if((z>>8)>0){
			z^=0x11B;
		}
		z=z<<1;
		if((z>>8)>0){
			z^=0x11B;
		}
		z^=x;
	} else if(y==14){
		z=x<<1;
		if((z>>8)>0){
			z^=0x11B;
		}
		z^=x;
		z=z<<1;
		if((z>>8)>0){
			z^=0x11B;
		}
		z^=x;

		z=z<<1;
		if((z>>8)>0){
			z^=0x11B;
		}
	}

	return (unsigned char)z;
}
