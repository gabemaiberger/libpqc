#include <stdio.h>
#include <jni/java.h>

#include <r3d.h>

JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1encrypt_1ecb
 (JNIEnv *env, jobject obj, jbooleanArray plaintext, jbooleanArray key, jbooleanArray ciphertext){
	int size=sizeof(&plaintext)/sizeof((&plaintext)[0]);
	r3d_encrypt_ecb((unsigned char *)plaintext, (unsigned char *)key, (unsigned char *)ciphertext, size);
	return;
}

JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1decrypt_1ecb
  (JNIEnv *env, jobject obj, jbooleanArray ciphertext, jbooleanArray key, jbooleanArray plaintext){
	return;
}

JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1encrypt_1ctr
  (JNIEnv *env, jobject obj, jbooleanArray plaintext, jbooleanArray key, jbooleanArray iv, jbooleanArray ciphertext){
	return;
}

JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1decrypt_1ctr
  (JNIEnv *env, jobject obj, jbooleanArray ciphertext, jbooleanArray key, jbooleanArray iv, jbooleanArray plaintext){
	return;
}

JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1encrypt_1ctr_1mt
  (JNIEnv *env, jobject obj, jbooleanArray plaintext, jbooleanArray key, jbooleanArray iv, jbooleanArray ciphertext, jint num_threads){
	return;
}

JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1decrypt_1ctr_1mt
  (JNIEnv *env, jobject obj, jbooleanArray ciphertext, jbooleanArray key, jbooleanArray iv, jbooleanArray plaintext, jint num_threads){
	return;
}

JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1encrypt_1xex
  (JNIEnv *env, jobject obj, jbooleanArray plaintext, jbooleanArray key, jbooleanArray ciphertext){
	return;
}

JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1decrypt_1xex
  (JNIEnv *env, jobject obj, jbooleanArray ciphertext, jbooleanArray key, jbooleanArray plaintext){
	return;
}

JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1encrypt_1xex_1mt
  (JNIEnv *env, jobject obj, jbooleanArray plaintext, jbooleanArray key, jbooleanArray ciphertext, jint num_threads){
	return;
}

JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1decrypt_1xex_1mt
  (JNIEnv *env, jobject obj, jbooleanArray ciphertext, jbooleanArray key, jbooleanArray plaintext, jint num_threads){
	return;
}
