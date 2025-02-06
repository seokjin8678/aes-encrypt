package org.example.encrypt.encryptor;

public interface AesEncryptor {

    String encrypt(String plainText);

    String decrypt(String cipherText);
}
