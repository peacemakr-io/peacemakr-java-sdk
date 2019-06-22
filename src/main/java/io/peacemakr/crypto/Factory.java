package io.peacemakr.crypto;

import io.peacemakr.crypto.impl.crypto.ICryptoImpl;

import java.util.logging.Logger;

public class Factory {

    public static ICrypto getCryptoSDK(String apiKey, String clientName, String peacemakrHostname, Persister persister, Logger logger) {
        return new ICryptoImpl(apiKey, clientName, peacemakrHostname, persister, logger);
    }

}
