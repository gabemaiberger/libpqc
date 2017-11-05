/*
SHA3 Hash Algorithm
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
#include <math.h>

unsigned long long int RC[24]={
0x0000000000000001, 0x0000000000008082,
0x800000000000808A, 0x8000000080008000,
0x000000000000808B, 0x0000000080000001,
0x8000000080008081, 0x8000000000008009,
0x000000000000008A, 0x0000000000000088,
0x0000000080008009, 0x000000008000000A,
0x000000008000808B, 0x800000000000008B,
0x8000000000008089, 0x8000000000008003,
0x8000000000008002, 0x8000000000000080,
0x000000000000800A, 0x800000008000000A,
0x8000000080008081, 0x8000000000008080,
0x0000000080000001, 0x8000000080008008
};

unsigned char *sha3_512(unsigned char *data, int size);
unsigned char *sha3_pad(unsigned char *data, int size);
unsigned char *sha3_permute_block(unsigned char *data);
unsigned int parity(unsigned int n);

unsigned char *sha3_512(unsigned char *data, int size){
	unsigned char *P;
	int i;
	int j;

 	if(size%72!=0){
		P=sha3_pad(data, size);
		size+=(72-size%72);
	}

	for(i=0; i<size; i++){
		printf("%x ", P[i]);
	}
	printf("\n\n");

	int n=(size/72);

	unsigned char *p[n];

	for(i=0; i<n; i++){
		p[i]=malloc(72);
		bzero(p[i], 72);
		strncpy(p[i], &P[i+(72*n)], 72);
	}

	/*for(i=0; i<72; i++){
		printf("%x ", p[0][i]);
	}
	printf("\n\n");*/

	unsigned char *S=malloc(72);
	bzero(S, 72);

	int c=128;
	for(i=0; i<n; i++){
		strncat(p[i], "\0", c);
		for(j=0; j<72; j++){
			S[j]^=p[i][j];
		}
		sha3_permute_block(S);
	}

	unsigned char *Z=malloc(72);

	strncpy(Z, S, 64);

	return Z;
}

unsigned char *sha3_pad(unsigned char *data, int size){
	int i;
	int margin=(72-size%72);

	unsigned char *P=malloc(size+margin);

	memcpy(P, data, size);

	P[size]=0x80;
	for(i=1; i<margin; i++){
		P[size+i]=0;
	}
	P[size+margin-1]=0x02;

	return P;
}

unsigned char *sha3_permute_block(unsigned char *data){
	unsigned char state[5][5][8];

	int i;
	int j;
	int k;
	int r;

	for(i=0; i<5; i++){
		for(j=0; j<5; j++){
			for(k=0; k<8; k++){
				state[i][j][k]=data[(i*5+j)*8+k];
			}
		}
	}
	
	for(r=0; r<24; r++){
		for(i=0; i<5; i++){
			for(j=0; j<5; j++){
				for(k=0; k<8; k++){
					state[i][j][k]^=(parity(state[i][j-1][k])^parity(state[i][j+1][k-1]));
				}
			}
		}

		int t=0;
		int t_inc=1;
		for(k=0; k<8; k++){
			if(i==0){
				for(j=1; j<5; j++){
					for(k=0; k<8; k++){
						state[i][j][k]=state[i][j][k-((t+1)*(t+2)/2)];
					}
					t_inc++;
					t+=t_inc;
				}
			} else {
				for(j=0; j<5; j++){
					for(k=0; k<8; k++){
						state[i][j][k]=state[i][j][k-((t+1)*(t+2)/2)];
					}
					t_inc++;
					t+=t_inc;
				}
			}
		}

		for(i=0; i<5; i++){
			for(j=0; j<5; j++){
				for(k=0; k<8; k++){
					state[i][j][k]=state[j][2*i+3*j][k];
				}
			}
		}

		for(i=0; i<5; i++){
			for(j=0; j<5; j++){
				for(k=0; k<8; k++){
					state[i][j][k]^=(~state[i][j+1][k] & state[i][j+2][k]);
				}
			}
		}

		for(k=0; k<8; k++){
			state[0][0][k]^=RC[r];
		}
	}

	for(i=0; i<5; i++){
		for(j=0; j<5; j++){
			for(k=0; k<8; k++){
				data[(i*5+j)*8+k]=state[i][j][k];
			}
		}
	}
}

unsigned int parity(unsigned int n){
	unsigned int parity=0;
	while(n){
		parity=!parity;
		n=n&(n-1);
	}
	return parity;
}
