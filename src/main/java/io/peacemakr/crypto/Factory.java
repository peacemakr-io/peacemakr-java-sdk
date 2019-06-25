package io.peacemakr.crypto;

import io.peacemakr.crypto.exception.MissingAPIKeyException;
import io.peacemakr.crypto.exception.MissingClientNameException;
import io.peacemakr.crypto.exception.MissingPersisterException;
import io.peacemakr.crypto.exception.PeacemakrException;
import io.peacemakr.crypto.impl.crypto.ICryptoImpl;

import java.util.logging.Logger;

public class Factory {

    public static ICrypto getCryptoSDK(String apiKey, String clientName, String peacemakrHostname, Persister persister, Logger logger) throws PeacemakrException {

        if (apiKey == null) {
            throw new MissingAPIKeyException();
        }

        if (clientName == null) {
            throw new MissingClientNameException();
        }

        if (peacemakrHostname == null) {
            peacemakrHostname = "https://api.peacemakr.io";
        }

        if (persister == null) {
            throw new MissingPersisterException();
        }

        if (logger == null) {
            logger = Logger.getLogger("PeacemakrDefaultLogger");
        }

        return new ICryptoImpl(apiKey, clientName, peacemakrHostname, persister, logger);
    }

}
