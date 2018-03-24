/*
R3D Cipher
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

void r3d_encrypt_ecb(unsigned char *plaintext, unsigned char *key, unsigned char *ciphertext, int size);
void r3d_decrypt_ecb(unsigned char *ciphertext, unsigned char *key, unsigned char *plaintext, int size);

void r3d_encrypt_ctr(unsigned char *plaintext, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int size);
void r3d_decrypt_ctr(unsigned char *ciphertext, unsigned char *key, unsigned char *iv, unsigned char *plaintext, int size);

void r3d_encrypt_xex(unsigned char *plaintext, unsigned char *key, unsigned char *ciphertext, int size);
void r3d_decrypt_xex(unsigned char *ciphertext, unsigned char *key, unsigned char *plaintext, int size);

//TODO: Fix CTR mode multithreaded functions
void r3d_encrypt_ctr_mt(unsigned char *plaintext, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int size, int num_threads);
void r3d_decrypt_ctr_mt(unsigned char *ciphertext, unsigned char *key, unsigned char *iv, unsigned char *plaintext, int size, int num_threads);

void r3d_encrypt_xex_mt(unsigned char *plaintext, unsigned char *key, unsigned char *ciphertext, int size, int num_threads);
void r3d_decrypt_xex_mt(unsigned char *ciphertext, unsigned char *key, unsigned char *plaintext, int size, int num_threads);
