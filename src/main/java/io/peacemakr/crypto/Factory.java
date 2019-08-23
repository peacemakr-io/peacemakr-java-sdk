package io.peacemakr.crypto;

import io.peacemakr.crypto.exception.MissingAPIKeyException;
import io.peacemakr.crypto.exception.MissingClientNameException;
import io.peacemakr.crypto.exception.MissingPersisterException;
import io.peacemakr.crypto.exception.PeacemakrException;
import io.peacemakr.crypto.impl.crypto.ICryptoImpl;
import org.apache.log4j.Logger;

public class Factory {

    /**
     *
     * This factory constructs a Peacemakr SDK Clients.
     *
     * All Peacemakr SDK clients implmenet the ICrypto interface. Calling this produces a new
     * stateful client of Peacemakr.  Internally, this state includes a private asymmetric
     * key, local cache of symmetric keys downloaded from Peacemakr so far, ability to
     * communicate with the peacemakr service org. All persisted data is managed through
     * your provided Persister.
     *
     * Auth is handled through the provided apiKey. If you do not have one, please register
     * at https://admin.peacemakr.io as a new organization. If you have a peacemakr organization
     * already, but are not sure what your apiKey should be, please login
     * (https://admin.peacemakr.io) and navigate to "API Keys" tab, and select one of your apiKey's.
     * The same API Key may be re-used across different clients.
     *
     * Persisting local data is important features of Peacemakr Clients. To help make this
     * as easy and seamless as possible, this client will only ever read or write through
     * this simple provided interface. There are two implementations of this interface which
     * are already provided: FilePersister and InMemoryPersister.  They do exactly as their
     * names describe. If your specific application requires a different or special type of
     * persistence layer, you are welcomed to implement this interface in whichever fashion
     * best suites your needs, and even open a PR against our SDK to ensure that we continue
     * supporting your particular persistenc layer it as we update and improve the clients.
     *
     *
     * @param apiKey Required. Auth mechanism which permits this client to connect to your Peacemakr Organization.
     * @param clientName Required. Any string which may be used to identify this particular client.  Please do not use
     *                   any customer Personally Identifiable Information (PII) in this field.
     * @param peacemakrBaseURL Optional. The base url for Peacemakr's  Cloud Services. If null, the default value
     *                        (https://api.peacemakr.io) is used.
     * @param persister Required. This persister help the cleint persist data.
     * @param logger Optional. If null, we use a standard log4j logger, else, you are welcomed to provide your own
     *               logger solution for local visibility and debugging.
     * @return An ICrypto which is ready to be used.
     * @throws PeacemakrException Is thrown on any non-recoverable error.
     */
    public static ICrypto getCryptoSDK(String apiKey, String clientName, String peacemakrBaseURL, Persister persister, Logger logger) throws PeacemakrException {

        if (apiKey == null) {
            throw new MissingAPIKeyException();
        }

        if (clientName == null) {
            throw new MissingClientNameException();
        }

        if (peacemakrBaseURL == null) {
            peacemakrBaseURL = "https://api.peacemakr.io";
        }

        if (persister == null) {
            throw new MissingPersisterException();
        }

        if (logger == null) {
            logger = Logger.getLogger(ICrypto.class);
        }

        return new ICryptoImpl(apiKey, clientName, peacemakrBaseURL, persister, logger);
    }

}
