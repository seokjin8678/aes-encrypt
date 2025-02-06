package org.example.encrypt.cipher;

import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.SecretKey;

public interface AesCipher {

    byte[] encrypt(String plainText, SecretKey secretKey, AlgorithmParameterSpec parameterSpec);

    String decrypt(byte[] cipherText, SecretKey secretKey, AlgorithmParameterSpec parameterSpec);
}
