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

unsigned char *sha3_512(unsigned char *data, int size);
unsigned char *sha3_pad(unsigned char *data);
unsigned char *sha3_permute_block(unsigned char *data);

unsigned char *sha3_512(unsigned char *data, int size){
	unsigned char *P;
	
	if(size%72!=0){
		P=sha3_pad(data);
		size+=(size%72);
	}

	int n=(size/72);

	unsigned char *p[n];

	int i;
	for(i=0; i<n; i++){
		p[i]=malloc(72);
		strncpy(p[i], P+(i*72), 72);
	}

	unsigned char *S=malloc(72);
	bzero(S, 72);

	int c=6;
	for(i=0; i<n; i++){
		strncat(p[i], "\0", 6);
		S[i]^=(long int)p[i];
		sha3_permute_block(S);
	}

	unsigned char *Z=malloc(64);

	strncpy(Z, S, 64);

	return Z;
}

unsigned char *sha3_pad(unsigned char *data){
	int i;
	long int size=sizeof(data)/sizeof(data[0]);

	for(i=0; i<(72-size); i++){
		if(i==0){
			strcat(data, "\1");
		} else {
			size=sizeof(data)/sizeof(data[0]);
			if(i==((72-size)-1)){
				strcat(data, "\xff");
			} else {
				strcat(data, "\x00");
			}
		}
	}

	return data;
}

unsigned char *sha3_permute_block(unsigned char *data){
	unsigned char state[5][5][6];

	int i;
	int j;
	int k;
	int r;

	for(i=0; i<5; i++){
		for(j=0; j<5; j++){
			for(k=0; k<6; k++){
				state[i][j][k]=data[(5*i+j)*6+k];
			}
		}
	}
	
	for(r=0; r<24; r++){
		for(i=0; i<4; i++){
			for(j=0; j<5; j++){
				for(k=0; k<6; k++){
					state[i][j][k]^=state[i][j-1][k]^state[i][j+1][k-1];
				}
			}
		}

		/*int t=0;
		int t_inc=1;
		for(i=1; i<5; i++){
			for(j=1; j<5; j++){
				for(k=0; k<6; k++){
					if(t>24){
						t=0;
						t_inc=1;
					}
					state[i][j][k]=state[i][j][k-(t+1)*(t+2)/2];
					t_inc++;
					t+=t_inc;
				}
			}
		}*/


		/*for(i=0; i<5; i++){
			for(j=0; j<5; j++){
				for(k=0; k<6; k++){
					state[i][j][k]=state[j][3*i+j][k];
				}
			}
		}*/

		for(i=0; i<5; i++){
			for(j=0; j<5; j++){
				for(k=0; k<6; k++){
					state[i][j][k]^=((!state[i][j+1][k])&&state[i][j+2][k]);
				}
			}
		}
	}

	for(i=0; i<5; i++){
		for(j=0; j<5; j++){
			for(k=0; k<6; k++){
				data[(5*i+j)*6+k]=state[i][j][k];
			}
		}
	}
}
