package io.peacemakr.example;

import io.peacemakr.crypto.Factory;
import io.peacemakr.crypto.ICrypto;
import io.peacemakr.crypto.impl.persister.InMemoryPersister;

class SimpleEncryptDecrypt {
    public static void main(String[] args) throws Exception {

        String apiKey = "your-api-key";
        InMemoryPersister persister = new InMemoryPersister();

    	ICrypto cryptoI = Factory.getCryptoSDK(apiKey, "simple encrypt decrypt", null, persister, null);
    	cryptoI.register();

    	String plaintext = "Hello world!";

    	byte[] encrypted = cryptoI.encrypt(plaintext.getBytes());
    	System.out.println("Encrypted: " + new String(encrypted));

    	byte[] decrypted = cryptoI.decrypt(encrypted);
        System.out.println("Decrypted: " + new String(decrypted));
    }
}

