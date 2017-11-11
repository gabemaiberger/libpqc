/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class gabe_cryptography_LibPQC */

#ifndef _Included_gabe_cryptography_LibPQC
#define _Included_gabe_cryptography_LibPQC
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     gabe_cryptography_LibPQC
 * Method:    r3d_encrypt_ecb
 * Signature: ([Z[Z[Z)V
 */
JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1encrypt_1ecb
  (JNIEnv *, jobject, jbooleanArray, jbooleanArray, jbooleanArray);

/*
 * Class:     gabe_cryptography_LibPQC
 * Method:    r3d_decrypt_ecb
 * Signature: ([Z[Z[Z)V
 */
JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1decrypt_1ecb
  (JNIEnv *, jobject, jbooleanArray, jbooleanArray, jbooleanArray);

/*
 * Class:     gabe_cryptography_LibPQC
 * Method:    r3d_encrypt_ctr
 * Signature: ([Z[Z[Z[Z)V
 */
JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1encrypt_1ctr
  (JNIEnv *, jobject, jbooleanArray, jbooleanArray, jbooleanArray, jbooleanArray);

/*
 * Class:     gabe_cryptography_LibPQC
 * Method:    r3d_decrypt_ctr
 * Signature: ([Z[Z[Z[Z)V
 */
JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1decrypt_1ctr
  (JNIEnv *, jobject, jbooleanArray, jbooleanArray, jbooleanArray, jbooleanArray);

/*
 * Class:     gabe_cryptography_LibPQC
 * Method:    r3d_encrypt_ctr_mt
 * Signature: ([Z[Z[Z[ZI)V
 */
JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1encrypt_1ctr_1mt
  (JNIEnv *, jobject, jbooleanArray, jbooleanArray, jbooleanArray, jbooleanArray, jint);

/*
 * Class:     gabe_cryptography_LibPQC
 * Method:    r3d_decrypt_ctr_mt
 * Signature: ([Z[Z[Z[ZI)V
 */
JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1decrypt_1ctr_1mt
  (JNIEnv *, jobject, jbooleanArray, jbooleanArray, jbooleanArray, jbooleanArray, jint);

/*
 * Class:     gabe_cryptography_LibPQC
 * Method:    r3d_encrypt_xex
 * Signature: ([Z[Z[Z)V
 */
JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1encrypt_1xex
  (JNIEnv *, jobject, jbooleanArray, jbooleanArray, jbooleanArray);

/*
 * Class:     gabe_cryptography_LibPQC
 * Method:    r3d_decrypt_xex
 * Signature: ([Z[Z[Z)V
 */
JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1decrypt_1xex
  (JNIEnv *, jobject, jbooleanArray, jbooleanArray, jbooleanArray);

/*
 * Class:     gabe_cryptography_LibPQC
 * Method:    r3d_encrypt_xex_mt
 * Signature: ([Z[Z[ZI)V
 */
JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1encrypt_1xex_1mt
  (JNIEnv *, jobject, jbooleanArray, jbooleanArray, jbooleanArray, jint);

/*
 * Class:     gabe_cryptography_LibPQC
 * Method:    r3d_decrypt_xex_mt
 * Signature: ([Z[Z[ZI)V
 */
JNIEXPORT void JNICALL Java_gabe_cryptography_LibPQC_r3d_1decrypt_1xex_1mt
  (JNIEnv *, jobject, jbooleanArray, jbooleanArray, jbooleanArray, jint);

#ifdef __cplusplus
}
#endif
#endif
