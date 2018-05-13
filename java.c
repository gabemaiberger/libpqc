/*
JNI Interface
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jni/java.h>

#include <r3d.h>

JNIEXPORT void JNICALL Java_LibPQC_LibPQC_r3d_1encrypt_1ecb
 (JNIEnv *env, jobject obj, jbyteArray plaintext, jbyteArray key, jbyteArray ciphertext){
	int size=(sizeof(&plaintext)/sizeof((&plaintext)[0]))+((sizeof(&plaintext)/sizeof((&plaintext)[0]))%512);

	unsigned char *plaintext_jni=malloc(size);
	unsigned char *key_jni=malloc(512);
	unsigned char *ciphertext_jni=malloc(size);

	(*env)->GetByteArrayRegion(env, plaintext, 0, size, (jbyte *)plaintext_jni);
	(*env)->GetByteArrayRegion(env, key, 0, 512, (jbyte *)key_jni);

	r3d_encrypt_ecb(plaintext_jni, key_jni, ciphertext_jni, size);

	(*env)->SetByteArrayRegion(env, ciphertext, 0, size, (jbyte *)ciphertext_jni);

	return;
}

JNIEXPORT void JNICALL Java_LibPQC_LibPQC_r3d_1decrypt_1ecb
  (JNIEnv *env, jobject obj, jbyteArray ciphertext, jbyteArray key, jbyteArray plaintext){
	int size=(sizeof(&ciphertext)/sizeof((&ciphertext)[0]))+((sizeof(&ciphertext)/sizeof((&ciphertext)[0]))%512);

	unsigned char *ciphertext_jni=malloc(size);
	unsigned char *key_jni=malloc(512);
	unsigned char *plaintext_jni=malloc(size);

	(*env)->GetByteArrayRegion(env, ciphertext, 0, size, (jbyte *)ciphertext_jni);
	(*env)->GetByteArrayRegion(env, key, 0, 512, (jbyte *)key_jni);

	r3d_decrypt_ecb(ciphertext_jni, key_jni, plaintext_jni, size);

	(*env)->SetByteArrayRegion(env, plaintext, 0, size, (jbyte *)plaintext_jni);

	return;
}

JNIEXPORT void JNICALL Java_LibPQC_LibPQC_r3d_1encrypt_1ctr
  (JNIEnv *env, jobject obj, jbyteArray plaintext, jbyteArray key, jbyteArray iv, jbyteArray ciphertext){
	int size=(sizeof(&plaintext)/sizeof((&plaintext)[0]))+((sizeof(&plaintext)/sizeof((&plaintext)[0]))%512);

	unsigned char *plaintext_jni=malloc(size);
	unsigned char *key_jni=malloc(512);
	unsigned char *iv_jni=malloc(512);
	unsigned char *ciphertext_jni=malloc(size);

	(*env)->GetByteArrayRegion(env, plaintext, 0, size, (jbyte *)plaintext_jni);
	(*env)->GetByteArrayRegion(env, key, 0, 512, (jbyte *)key_jni);
	(*env)->GetByteArrayRegion(env, iv, 0, 512, (jbyte *)key_jni);

	r3d_encrypt_ctr(plaintext_jni, key_jni, iv_jni, ciphertext_jni, size);

	(*env)->SetByteArrayRegion(env, ciphertext, 0, size, (jbyte *)ciphertext_jni);

	return;
}

JNIEXPORT void JNICALL Java_LibPQC_LibPQC_r3d_1decrypt_1ctr
  (JNIEnv *env, jobject obj, jbyteArray ciphertext, jbyteArray key, jbyteArray iv, jbyteArray plaintext){
	int size=(sizeof(&ciphertext)/sizeof((&ciphertext)[0]))+((sizeof(&ciphertext)/sizeof((&ciphertext)[0]))%512);

	unsigned char *ciphertext_jni=malloc(size);
	unsigned char *key_jni=malloc(512);
	unsigned char *iv_jni=malloc(512);
	unsigned char *plaintext_jni=malloc(size);

	(*env)->GetByteArrayRegion(env, ciphertext, 0, size, (jbyte *)ciphertext_jni);
	(*env)->GetByteArrayRegion(env, key, 0, 512, (jbyte *)key_jni);

	r3d_decrypt_ctr(ciphertext_jni, key_jni, iv_jni, plaintext_jni, size);

	(*env)->SetByteArrayRegion(env, plaintext, 0, size, (jbyte *)plaintext_jni);

	return;
}

JNIEXPORT void JNICALL Java_LibPQC_LibPQC_r3d_1encrypt_1ctr_1mt
  (JNIEnv *env, jobject obj, jbyteArray plaintext, jbyteArray key, jbyteArray iv, jbyteArray ciphertext, jint num_threads){
	int size=(sizeof(&plaintext)/sizeof((&plaintext)[0]))+((sizeof(&plaintext)/sizeof((&plaintext)[0]))%512);

	unsigned char *plaintext_jni=malloc(size);
	unsigned char *key_jni=malloc(512);
	unsigned char *iv_jni=malloc(512);
	unsigned char *ciphertext_jni=malloc(size);

	(*env)->GetByteArrayRegion(env, plaintext, 0, size, (jbyte *)plaintext_jni);
	(*env)->GetByteArrayRegion(env, key, 0, 512, (jbyte *)key_jni);
	(*env)->GetByteArrayRegion(env, iv, 0, 512, (jbyte *)key_jni);

	r3d_encrypt_ctr_mt(plaintext_jni, key_jni, iv_jni, ciphertext_jni, size, num_threads);

	(*env)->SetByteArrayRegion(env, ciphertext, 0, size, (jbyte *)ciphertext_jni);

	return;
}

JNIEXPORT void JNICALL Java_LibPQC_r3d_1decrypt_1ctr_1mt
  (JNIEnv *env, jobject obj, jbyteArray ciphertext, jbyteArray key, jbyteArray iv, jbyteArray plaintext, jint num_threads){
	int size=(sizeof(&ciphertext)/sizeof((&ciphertext)[0]))+((sizeof(&ciphertext)/sizeof((&ciphertext)[0]))%512);

	unsigned char *ciphertext_jni=malloc(size);
	unsigned char *key_jni=malloc(512);
	unsigned char *iv_jni=malloc(512);
	unsigned char *plaintext_jni=malloc(size);

	(*env)->GetByteArrayRegion(env, ciphertext, 0, size, (jbyte *)ciphertext_jni);
	(*env)->GetByteArrayRegion(env, key, 0, 512, (jbyte *)key_jni);

	r3d_decrypt_ctr_mt(ciphertext_jni, key_jni, iv_jni, plaintext_jni, size, num_threads);

	(*env)->SetByteArrayRegion(env, plaintext, 0, size, (jbyte *)plaintext_jni);

	return;
}

JNIEXPORT void JNICALL Java_LibPQC_LibPQC_r3d_1encrypt_1xex
  (JNIEnv *env, jobject obj, jbyteArray plaintext, jbyteArray key, jbyteArray ciphertext){
	int size=(sizeof(&plaintext)/sizeof((&plaintext)[0]))+((sizeof(&plaintext)/sizeof((&plaintext)[0]))%512);

	unsigned char *plaintext_jni=malloc(size);
	unsigned char *key_jni=malloc(512);
	unsigned char *ciphertext_jni=malloc(size);

	(*env)->GetByteArrayRegion(env, plaintext, 0, size, (jbyte *)plaintext_jni);
	(*env)->GetByteArrayRegion(env, key, 0, 512, (jbyte *)key_jni);

	r3d_encrypt_xex(plaintext_jni, key_jni, ciphertext_jni, size);

	(*env)->SetByteArrayRegion(env, ciphertext, 0, size, (jbyte *)ciphertext_jni);

	return;
}

JNIEXPORT void JNICALL Java_LibPQC_LibPQC_r3d_1decrypt_1xex
  (JNIEnv *env, jobject obj, jbyteArray ciphertext, jbyteArray key, jbyteArray plaintext){
	int size=(sizeof(&ciphertext)/sizeof((&ciphertext)[0]))+((sizeof(&ciphertext)/sizeof((&ciphertext)[0]))%512);

	unsigned char *ciphertext_jni=malloc(size);
	unsigned char *key_jni=malloc(512);
	unsigned char *plaintext_jni=malloc(size);

	(*env)->GetByteArrayRegion(env, ciphertext, 0, size, (jbyte *)ciphertext_jni);
	(*env)->GetByteArrayRegion(env, key, 0, 512, (jbyte *)key_jni);

	r3d_decrypt_xex(ciphertext_jni, key_jni, plaintext_jni, size);

	(*env)->SetByteArrayRegion(env, plaintext, 0, size, (jbyte *)plaintext_jni);

	return;
}

JNIEXPORT void JNICALL Java_LibPQC_LibPQC_r3d_1encrypt_1xex_1mt
  (JNIEnv *env, jobject obj, jbyteArray plaintext, jbyteArray key, jbyteArray ciphertext, jint num_threads){
	int size=(sizeof(&plaintext)/sizeof((&plaintext)[0]))+((sizeof(&plaintext)/sizeof((&plaintext)[0]))%512);

	unsigned char *plaintext_jni=malloc(size);
	unsigned char *key_jni=malloc(512);
	unsigned char *ciphertext_jni=malloc(size);

	(*env)->GetByteArrayRegion(env, plaintext, 0, size, (jbyte *)plaintext_jni);
	(*env)->GetByteArrayRegion(env, key, 0, 512, (jbyte *)key_jni);

	r3d_encrypt_xex_mt(plaintext_jni, key_jni, ciphertext_jni, size, num_threads);

	(*env)->SetByteArrayRegion(env, ciphertext, 0, size, (jbyte *)ciphertext_jni);

	return;
}

JNIEXPORT void JNICALL Java_LibPQC_LibPQC_r3d_1decrypt_1xex_1mt
  (JNIEnv *env, jobject obj, jbyteArray ciphertext, jbyteArray key, jbyteArray plaintext, jint num_threads){
	int size=(sizeof(&ciphertext)/sizeof((&ciphertext)[0]))+((sizeof(&ciphertext)/sizeof((&ciphertext)[0]))%512);

	unsigned char *ciphertext_jni=malloc(size);
	unsigned char *key_jni=malloc(512);
	unsigned char *plaintext_jni=malloc(size);

	(*env)->GetByteArrayRegion(env, ciphertext, 0, size, (jbyte *)ciphertext_jni);
	(*env)->GetByteArrayRegion(env, key, 0, 512, (jbyte *)key_jni);

	r3d_decrypt_xex_mt(ciphertext_jni, key_jni, plaintext_jni, size, num_threads);

	(*env)->SetByteArrayRegion(env, plaintext, 0, size, (jbyte *)plaintext_jni);	

	return;
}
