package io.peacemakr.crypto;

import io.peacemakr.crypto.exception.MissingAPIKey;
import io.peacemakr.crypto.exception.MissingClientName;
import io.peacemakr.crypto.exception.MissingPersister;
import io.peacemakr.crypto.exception.PeacemakrException;
import io.peacemakr.crypto.impl.crypto.ICryptoImpl;

import java.util.logging.Logger;

public class Factory {

    public static ICrypto getCryptoSDK(String apiKey, String clientName, String peacemakrHostname, Persister persister, Logger logger) throws PeacemakrException {

        if (apiKey == null) {
            throw new MissingAPIKey();
        }

        if (clientName == null) {
            throw new MissingClientName();
        }

        if (peacemakrHostname == null) {
            peacemakrHostname = "https://api.peacemakr.io";
        }

        if (persister == null) {
            throw new MissingPersister();
        }

        if (logger == null) {
            logger = Logger.getLogger("PeacemakrDefaultLogger");
        }

        return new ICryptoImpl(apiKey, clientName, peacemakrHostname, persister, logger);
    }

}
