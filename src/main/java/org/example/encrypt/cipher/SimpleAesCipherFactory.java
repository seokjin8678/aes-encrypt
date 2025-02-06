package org.example.encrypt.cipher;

import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

public class SimpleAesCipherFactory implements AesCipherFactory {

    private final String transformation;

    public SimpleAesCipherFactory(String transformation) {
        this.transformation = transformation;
    }

    @Override
    public AesCipher get() {
        try {
            return new SimpleAesCipher(Cipher.getInstance(transformation));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
