package org.example.encrypt.blog;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import org.apache.commons.codec.DecoderException;

public abstract class AesEncryptHelper {

    protected byte[] encrypt(
        Cipher cipher,
        String plainText,
        SecretKey secretKey,
        AlgorithmParameterSpec parameterSpec
    )
        throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, DecoderException {

        if (parameterSpec == null) {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        }
        return cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
    }

    protected String decrypt(
        Cipher cipher,
        byte[] cipherBytes,
        SecretKey secretKey,
        AlgorithmParameterSpec parameterSpec
    )
        throws InvalidKeyException, InvalidAlgorithmParameterException, DecoderException, IllegalBlockSizeException, BadPaddingException {

        if (parameterSpec == null) {
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
        }
        return new String(cipher.doFinal(cipherBytes), StandardCharsets.UTF_8);
    }
}
