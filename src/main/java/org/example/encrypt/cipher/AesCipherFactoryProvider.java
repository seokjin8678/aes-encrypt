package org.example.encrypt.cipher;

@FunctionalInterface
public interface AesCipherFactoryProvider {

    AesCipherFactory provide(String transformation);
}
