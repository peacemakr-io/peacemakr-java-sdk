package io.peacemakr.crypto;

import io.peacemakr.crypto.exception.PeacemakrException;
import io.peacemakr.crypto.impl.persister.InMemoryPersister;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class ICryptoTest {

    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void register() {
    }

    @Test
    public void sync() {
    }

    @Test
    public void encrypt() {
    }

    @Test
    public void encrypt1() {
    }

    @Test
    public void encryptInDomain() {
    }

    @Test
    public void encryptInDomain1() {
    }

    @Test
    public void decrypt() {
    }

    @Test
    public void decrypt1() {
    }

    @Test
    public void getDebugInfo() throws PeacemakrException {
        ICrypto sdk = Factory.getCryptoSDK("", "", null, new InMemoryPersister(), null);
        String debug = sdk.getDebugInfo();
        Assert.assertEquals("Peacemakr Java Sdk DebugInfo - orgId=UnknownOrgId clientId=UnkonwnClientId preferedKeyId=UnknownPreferedKeyId", debug);
    }
}