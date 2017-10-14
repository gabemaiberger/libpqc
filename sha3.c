#include <string.h>
#include <malloc.h>

unsigned char *sha3_512(unsigned char *data, int size);
unsigned char *sha3_pad(unsigned char *data);
unsigned char *sha3_permute_block(unsigned char *data);

unsigned char *sha3_512(unsigned char *data, int size){
	unsigned char *P;
	
	if(size%76!=0){
		if(size<76){
			P=sha3_pad(data);
			size=sizeof(data)/sizeof(data[0]);
		}
	}

	int n=(size/76);
	unsigned char *p[n];

	int i;
	for(i=0; i<n; i++){
		p[i]=malloc(76);
		strncpy(p[i], P+(i*76), 76);
	}

	unsigned char *S=malloc(76);
	bzero(S, 76);

	int c;
	for(i=0; i<n; i++){
		strncat(p[i], "\0", c);
		S=(long int)S^(long int)p[i];
		S=sha3_permute_block(S);
	}

	unsigned char *Z=malloc(64);

	strncpy(Z, S, 64);

	return Z;
}

unsigned char *sha3_pad(unsigned char *data){
	int i=0;
	int size=sizeof(data)/sizeof(data[0]);

	for(i=0; i<(76-size); i++){
		if(i==0){
			strcat(data, "\1");
		} else {
			size=sizeof(data)/sizeof(data[0]);
			if(i==((76-size)-1)){
				strcat(data, "\1");
			} else {
				strcat(data, "\0");
			}
		}
	}
}

unsigned char *sha3_permute_block(unsigned char *data){
	
}
