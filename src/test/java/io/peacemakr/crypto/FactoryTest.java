package io.peacemakr.crypto;

import io.peacemakr.crypto.exception.MissingAPIKeyException;
import io.peacemakr.crypto.exception.MissingClientNameException;
import io.peacemakr.crypto.exception.MissingPersisterException;
import io.peacemakr.crypto.exception.PeacemakrException;
import io.peacemakr.crypto.impl.persister.InMemoryPersister;
import org.junit.Test;

import java.util.logging.Logger;

public class FactoryTest {

    @Test(expected = MissingAPIKeyException.class)
    public void getCryptoSDKMissingAPIKey() throws PeacemakrException {
        Factory.getCryptoSDK(null, "", "", new InMemoryPersister(), Logger.getLogger("test"));
    }

    @Test(expected = MissingClientNameException.class)
    public void getCryptoSDKMissingClientName() throws PeacemakrException {
        Factory.getCryptoSDK("", null, "", new InMemoryPersister(), Logger.getLogger("test"));
    }

    @Test
    public void getCryptoSDKMissingHost() throws PeacemakrException {
        Factory.getCryptoSDK("", "", null, new InMemoryPersister(), Logger.getLogger("test"));
    }

    @Test(expected = MissingPersisterException.class)
    public void getCryptoSDKMissingPersister() throws PeacemakrException {
        Factory.getCryptoSDK("", "", "", null, Logger.getLogger("test"));
    }

    @Test
    public void getCryptoSDKMissingLogger() throws PeacemakrException {
        Factory.getCryptoSDK("", "", "", new InMemoryPersister(), null);
    }
}