#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jni/java.h>

#include <r3d.h>

JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1encrypt_1ecb
 (JNIEnv *env, jobject obj, jbyteArray plaintext, jbyteArray key, jbyteArray ciphertext){
	int size=sizeof(&plaintext)/sizeof((&plaintext)[0]);

	unsigned char *plaintext_jni=malloc(size);
	unsigned char *key_jni=malloc(512);
	unsigned char *ciphertext_jni=malloc(size);

	(*env)->GetByteArrayRegion(env, plaintext, 0, size, (jbyte *)plaintext_jni);
	(*env)->GetByteArrayRegion(env, key, 0, size, (jbyte *)key_jni);

	r3d_encrypt_ecb(plaintext_jni, key_jni, ciphertext_jni, size);

	(*env)->SetByteArrayRegion(env, ciphertext, 0, size, (jbyte *)ciphertext_jni);

	return;
}

JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1decrypt_1ecb
  (JNIEnv *env, jobject obj, jbyteArray ciphertext, jbyteArray key, jbyteArray plaintext){
	int size=sizeof(&ciphertext)/sizeof((&ciphertext)[0]);

	unsigned char *ciphertext_jni=malloc(size);
	unsigned char *key_jni=malloc(512);
	unsigned char *plaintext_jni=malloc(size);

	(*env)->GetByteArrayRegion(env, ciphertext, 0, size, (jbyte *)ciphertext_jni);
	(*env)->GetByteArrayRegion(env, key, 0, size, (jbyte *)key_jni);

	r3d_decrypt_ecb(ciphertext_jni, key_jni, plaintext_jni, size);

	(*env)->SetByteArrayRegion(env, plaintext, 0, size, (jbyte *)plaintext_jni);

	return;
}

JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1encrypt_1ctr
  (JNIEnv *env, jobject obj, jbyteArray plaintext, jbyteArray key, jbyteArray iv, jbyteArray ciphertext){
	return;
}

JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1decrypt_1ctr
  (JNIEnv *env, jobject obj, jbyteArray ciphertext, jbyteArray key, jbyteArray iv, jbyteArray plaintext){
	return;
}

JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1encrypt_1ctr_1mt
  (JNIEnv *env, jobject obj, jbyteArray plaintext, jbyteArray key, jbyteArray iv, jbyteArray ciphertext, jint num_threads){
	return;
}

JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1decrypt_1ctr_1mt
  (JNIEnv *env, jobject obj, jbyteArray ciphertext, jbyteArray key, jbyteArray iv, jbyteArray plaintext, jint num_threads){
	return;
}

JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1encrypt_1xex
  (JNIEnv *env, jobject obj, jbyteArray plaintext, jbyteArray key, jbyteArray ciphertext){
	return;
}

JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1decrypt_1xex
  (JNIEnv *env, jobject obj, jbyteArray ciphertext, jbyteArray key, jbyteArray plaintext){
	return;
}

JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1encrypt_1xex_1mt
  (JNIEnv *env, jobject obj, jbyteArray plaintext, jbyteArray key, jbyteArray ciphertext, jint num_threads){
	return;
}

JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1decrypt_1xex_1mt
  (JNIEnv *env, jobject obj, jbyteArray ciphertext, jbyteArray key, jbyteArray plaintext, jint num_threads){
	return;
}
