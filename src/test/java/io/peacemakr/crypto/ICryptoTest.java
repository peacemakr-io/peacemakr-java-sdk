package io.peacemakr.crypto;

import io.peacemakr.crypto.exception.PeacemakrException;
import io.peacemakr.crypto.impl.crypto.ICryptoImpl;
import io.peacemakr.crypto.impl.persister.InMemoryPersister;
import org.junit.*;

import static org.junit.Assert.*;

public class ICryptoTest {

    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }

    @Ignore // Until crypto is implemented.
    @Test
    public void register() throws PeacemakrException {

        // Violate abstration layer for access to internal state for more complete testing + asserting.
        ICryptoImpl sdk = (ICryptoImpl) Factory.getCryptoSDK(TestUtils.getApiKey(), "register test", TestUtils.getHostname(), new InMemoryPersister(), null);
        sdk.register();

        String debug = sdk.getDebugInfo();
        Assert.assertNotEquals("Peacemakr Java Sdk DebugInfo - orgId=UnknownOrgId clientId=UnkonwnClientId preferedKeyId=UnknownPreferedKeyId", debug);

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
        Assert.assertEquals("Peacemakr Java Sdk DebugInfo - orgId=UnknownOrgId clientId=UnknownClientId preferredKeyId=UnknownPreferredKeyId", debug);
    }
}