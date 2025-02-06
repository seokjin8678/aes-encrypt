package org.example.encrypt.cipher;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import org.apache.commons.codec.DecoderException;

public class SimpleAesCipher extends AesCipherHelper implements AesCipher {

    private final Cipher cipher;

    public SimpleAesCipher(Cipher cipher) {
        this.cipher = cipher;
    }

    @Override
    public byte[] encrypt(String plainText, SecretKey secretKey, AlgorithmParameterSpec parameterSpec) {
        try {
            return encrypt(cipher, plainText, secretKey, parameterSpec);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | DecoderException e) {
            throw new IllegalArgumentException(e);
        } catch (GeneralSecurityException e) {
            return null;
        }
    }

    @Override
    public String decrypt(byte[] cipherText, SecretKey secretKey, AlgorithmParameterSpec parameterSpec) {
        try {
            return decrypt(cipher, cipherText, secretKey, parameterSpec);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | DecoderException e) {
            throw new IllegalArgumentException(e);
        } catch (GeneralSecurityException e) {
            return null;
        }
    }
}
