package org.example.encrypt.cipher;

import javax.crypto.Cipher;
import org.apache.commons.pool2.BasePooledObjectFactory;
import org.apache.commons.pool2.PooledObject;
import org.apache.commons.pool2.impl.DefaultPooledObject;
import org.apache.commons.pool2.impl.GenericObjectPool;
import org.apache.commons.pool2.impl.GenericObjectPoolConfig;

public class ObjectPoolAesCipherFactory implements AesCipherFactory {

    private final ObjectPoolAesCipher objectPoolAesCipher;

    public ObjectPoolAesCipherFactory(String transformation) {
        GenericObjectPoolConfig<Cipher> config = new GenericObjectPoolConfig<>();
        config.setMaxTotal(20);
        config.setMaxIdle(5);
        config.setMinIdle(2);
        var cipherObjectPool = new GenericObjectPool<>(new AesCipherPooledObjectFactory(transformation), config);
        this.objectPoolAesCipher = new ObjectPoolAesCipher(cipherObjectPool);
    }

    @Override
    public AesCipher get() {
        return objectPoolAesCipher;
    }

    private static class AesCipherPooledObjectFactory extends BasePooledObjectFactory<Cipher> {

        private final String transformation;

        public AesCipherPooledObjectFactory(String transformation) {
            this.transformation = transformation;
        }

        @Override
        public Cipher create() throws Exception {
            return Cipher.getInstance(transformation);
        }

        @Override
        public PooledObject<Cipher> wrap(Cipher cipher) {
            return new DefaultPooledObject<>(cipher);
        }
    }
}
