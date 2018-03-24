package LibPQC;

public class LibPQC {
    public static void LibPQC(){
    }
    
    static {
            System.loadLibrary("pqc-java");
    }
    
    public native void r3d_encrypt_ecb(byte[] plaintext, byte[] key, byte[] ciphertext);
    public native void r3d_decrypt_ecb(byte[] ciphertext, byte[] key, byte[] plaintext);
    
    public native void r3d_encrypt_ctr(byte[] plaintext, byte[] key, byte[] iv, byte[] ciphertext);
    public native void r3d_decrypt_ctr(byte[] ciphertext, byte[] key, byte[] iv, byte[] plaintext);
    public native void r3d_encrypt_ctr_mt(byte[] plaintext, byte[] key, byte[] iv, byte[] ciphertext, int num_threads);
    public native void r3d_decrypt_ctr_mt(byte[] ciphertext, byte[] key, byte[] iv, byte[] plaintext, int num_threads);
    
    public native void r3d_encrypt_xex(byte[] plaintext, byte[] key, byte[] ciphertext);
    public native void r3d_decrypt_xex(byte[] ciphertext, byte[] key, byte[] plaintext);
    public native void r3d_encrypt_xex_mt(byte[] plaintext, byte[] key, byte[] ciphertext, int num_threads);
    public native void r3d_decrypt_xex_mt(byte[] ciphertext, byte[] key, byte[] plaintext, int num_threads);
}
