#include <stdio.h>
#include <jni/java.h>

#include <r3d.h>

JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1encrypt_1ecb
 (JNIEnv *env, jobject obj, jbyteArray plaintext, jbyteArray key, jbyteArray ciphertext){
	return;
}

JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1decrypt_1ecb
  (JNIEnv *env, jobject obj, jbyteArray ciphertext, jbyteArray key, jbyteArray plaintext){
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

JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1encrypt_1xex
  (JNIEnv *env, jobject obj, jbyteArray plaintext, jbyteArray key, jbyteArray ciphertext){
	return;
}

JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1decrypt_1xex
  (JNIEnv *env, jobject obj, jbyteArray ciphertext, jbyteArray key, jbyteArray plaintext){
	return;
}
