package org.example.encrypt.cipher;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.pool2.ObjectPool;

public class ObjectPoolAesCipher extends AesCipherHelper implements AesCipher {

    private final ObjectPool<Cipher> cipherPool;

    public ObjectPoolAesCipher(ObjectPool<Cipher> cipherPool) {
        this.cipherPool = cipherPool;
    }

    @Override
    public byte[] encrypt(String plainText, SecretKey secretKey, AlgorithmParameterSpec parameterSpec) {
        Cipher cipher = null;
        try {
            cipher = borrowCipher();
            if (cipher == null) {
                return null;
            }
            return encrypt(cipher, plainText, secretKey, parameterSpec);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | DecoderException e) {
            throw new IllegalArgumentException(e);
        } catch (GeneralSecurityException e) {
            return null;
        } finally {
            if (cipher != null) {
                returnCipher(cipher);
            }
        }
    }

    private Cipher borrowCipher() {
        try {
            return cipherPool.borrowObject();
        } catch (Exception e) {
            return null;
        }
    }

    private void returnCipher(Cipher cipher) {
        try {
            cipherPool.returnObject(cipher);
        } catch (Exception ignore) {

        }
    }

    @Override
    public String decrypt(byte[] cipherText, SecretKey secretKey, AlgorithmParameterSpec parameterSpec) {
        Cipher cipher = null;
        try {
            cipher = borrowCipher();
            if (cipher == null) {
                return null;
            }
            return decrypt(cipher, cipherText, secretKey, parameterSpec);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | DecoderException e) {
            throw new IllegalArgumentException(e);
        } catch (GeneralSecurityException e) {
            return null;
        } finally {
            if (cipher != null) {
                returnCipher(cipher);
            }
        }
    }
}
