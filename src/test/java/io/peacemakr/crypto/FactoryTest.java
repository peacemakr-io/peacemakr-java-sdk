package io.peacemakr.crypto;

import io.peacemakr.crypto.exception.MissingAPIKey;
import io.peacemakr.crypto.exception.MissingClientName;
import io.peacemakr.crypto.exception.MissingPersister;
import io.peacemakr.crypto.exception.PeacemakrException;
import io.peacemakr.crypto.impl.persister.InMemoryPersister;
import org.junit.Test;

import java.util.logging.Logger;

import static org.junit.Assert.*;

public class FactoryTest {

    @Test(expected = MissingAPIKey.class)
    public void getCryptoSDKMissingAPIKey() throws PeacemakrException {
        Factory.getCryptoSDK(null, "", "", new InMemoryPersister(), Logger.getLogger("test"));
    }

    @Test(expected = MissingClientName.class)
    public void getCryptoSDKMissingClientName() throws PeacemakrException {
        Factory.getCryptoSDK("", null, "", new InMemoryPersister(), Logger.getLogger("test"));
    }

    @Test
    public void getCryptoSDKMissingHost() throws PeacemakrException {
        Factory.getCryptoSDK("", "", null, new InMemoryPersister(), Logger.getLogger("test"));
    }

    @Test(expected = MissingPersister.class)
    public void getCryptoSDKMissingPersister() throws PeacemakrException {
        Factory.getCryptoSDK("", "", "", null, Logger.getLogger("test"));
    }

    @Test
    public void getCryptoSDKMissingLogger() throws PeacemakrException {
        Factory.getCryptoSDK("", "", "", new InMemoryPersister(), null);
    }
}