void r3d_encrypt_block(unsigned char plaintext_block[512], unsigned char key[512], unsigned char ciphertext_block[512]);
void r3d_decrypt_block(unsigned char ciphertext_block[512], unsigned char key[512], unsigned char plaintext_block[512]);

void r3d_encrypt_ecb(unsigned char *plaintext, unsigned char *key, unsigned char *ciphertext, int size);
void r3d_decrypt_ecb(unsigned char *ciphertext, unsigned char *key, unsigned char *plaintext, int size);

void r3d_encrypt_ctr(unsigned char *plaintext, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int size);
void r3d_decrypt_ctr(unsigned char *ciphertext, unsigned char *key, unsigned char *iv, unsigned char *plaintext, int size);
void r3d_encrypt_ctr_mt(unsigned char *plaintext, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int size);
void r3d_decrypt_ctr_mt(unsigned char *ciphertext, unsigned char *key, unsigned char *iv, unsigned char *plaintext, int size);

void r3d_encrypt_xex(unsigned char *plaintext, unsigned char *key, unsigned char *ciphertext, int size);
void r3d_decrypt_xex(unsigned char *ciphertext, unsigned char *key, unsigned char *plaintext, int size);
