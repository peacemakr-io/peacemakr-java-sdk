package io.peacemakr.crypto.impl.crypto;

import io.peacemakr.corecrypto.AsymmetricCipher;
import io.peacemakr.crypto.Factory;
import io.peacemakr.crypto.ICrypto;
import io.peacemakr.crypto.exception.PeacemakrException;
import io.peacemakr.crypto.exception.ServerException;
import io.peacemakr.crypto.impl.persister.InMemoryPersister;
import io.peacemakr.crypto.swagger.client.ApiClient;
import io.peacemakr.crypto.swagger.client.ApiException;
import io.peacemakr.crypto.swagger.client.api.OrgApi;
import io.peacemakr.crypto.swagger.client.model.APIKey;
import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.junit.*;
import org.mockito.Mockito;

import java.util.Arrays;
import java.util.Map;
import java.util.Random;

public class ICryptoTest {

    private String testAPIKey = null;
    private String testOrgId = null;

    // For now, the tests expect to find peacemakr running on localhost:8080.
    private static final String DEFAULT_PEACEMAKR_TEST_HOSTNAME = "http://localhost:8080";

    private String getPeacemakrHostname() {
        Map<String, String> map = System.getenv();

        String hostname = map.get("PEACEMAKR_TEST_HOSTNAME");
        if (hostname != null) {
            return hostname;
        }

        return "";
    }

    private byte[] getRandomBytes() {
        Random rd = new Random();
        byte[] arr = new byte[1024];
        rd.nextBytes(arr);
        System.out.println(arr);
        return arr;
    }

    @Before
    public void setUp() throws Exception {

        LogManager.getRootLogger().setLevel(Level.ALL);

        Map<String, String> map = System.getenv();
        testAPIKey = map.get("PEACEMAKR_TEST_API_KEY");

        if (testAPIKey == null) {
            testAPIKey = "";
        }
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void register() throws PeacemakrException {

        // Violate abstraction layer for access to internal state for more complete testing + asserting.
        ICryptoImpl sdk = (ICryptoImpl) Factory.getCryptoSDK(this.testAPIKey, "java sdk - register", getPeacemakrHostname(), new InMemoryPersister(), null);
        sdk.register();

        String debug = sdk.getDebugInfo();
        Assert.assertNotEquals("Peacemakr Java Sdk DebugInfo - orgId=UnknownOrgId clientId=UnkonwnClientId preferedKeyId=UnknownPreferedKeyId", debug);

    }

    @Test
    public void sync() throws PeacemakrException {

        // Violate abstraction layer for access to internal state for more complete testing + asserting.
        ICryptoImpl sdk = (ICryptoImpl) Factory.getCryptoSDK(this.testAPIKey, "java sdk - sync", getPeacemakrHostname(), new InMemoryPersister(), null);
        sdk.register();

        String debug = sdk.getDebugInfo();
        Assert.assertNotEquals("Peacemakr Java Sdk DebugInfo - orgId=UnknownOrgId clientId=UnkonwnClientId preferedKeyId=UnknownPreferedKeyId", debug);

        sdk.sync();

    }



    @Test
    public void encryptDecryptWithOneClient_ECDH_P521() throws PeacemakrException {
        AsymmetricCipher fakedAsymmetricCipher = AsymmetricCipher.ECDH_P521;
        encryptDecryptOneClient(fakedAsymmetricCipher);
    }

    @Test
    public void encryptDecryptWithOneClient_ECDH_P384() throws PeacemakrException {
        AsymmetricCipher fakedAsymmetricCipher = AsymmetricCipher.ECDH_P384;
        encryptDecryptOneClient(fakedAsymmetricCipher);
    }

    @Test
    public void encryptDecryptWithOneClient_ECDH_P256() throws PeacemakrException {
        AsymmetricCipher fakedAsymmetricCipher = AsymmetricCipher.ECDH_P256;
        encryptDecryptOneClient(fakedAsymmetricCipher);
    }

    @Test
    public void encryptDecryptWithOneClient_RSA_2048() throws PeacemakrException {
        AsymmetricCipher fakedAsymmetricCipher = AsymmetricCipher.RSA_2048;
        encryptDecryptOneClient(fakedAsymmetricCipher);
    }

    @Test
    public void encryptDecryptWithOneClient_RSA_4096() throws PeacemakrException {
        AsymmetricCipher fakedAsymmetricCipher = AsymmetricCipher.RSA_4096;
        encryptDecryptOneClient(fakedAsymmetricCipher);
    }

    private void encryptDecryptOneClient(AsymmetricCipher fakedAsymmetricCipher) throws PeacemakrException {
        // Violate abstraction layer for access to internal state for more complete testing + asserting.
        ICryptoImpl sdk = (ICryptoImpl) Factory.getCryptoSDK(this.testAPIKey, "java sdk - encryptDecryptWithOneClient", getPeacemakrHostname(), new InMemoryPersister(), null);

        // Install a spy.
        ICryptoImpl sdkSpy = Mockito.spy(sdk);
        Mockito.doReturn(fakedAsymmetricCipher).when(sdkSpy).getAsymmetricCipher(Mockito.any(String.class), Mockito.anyInt());

        sdkSpy.register();

        String debug = sdkSpy.getDebugInfo();
        Assert.assertNotEquals("Peacemakr Java Sdk DebugInfo - orgId=UnknownOrgId clientId=UnkonwnClientId preferedKeyId=UnknownPreferedKeyId", debug);

        byte[] plaintextBytes = getRandomBytes();

        byte[] encrypted1 = sdkSpy.encrypt(plaintextBytes);
        Assert.assertFalse(Arrays.equals(plaintextBytes, encrypted1));

        byte[] encrypted2 = sdkSpy.encrypt(plaintextBytes);
        Assert.assertFalse(Arrays.equals(plaintextBytes, encrypted2));
        Assert.assertFalse(Arrays.equals(encrypted1, encrypted2));

        byte[] encrypted3 = sdkSpy.encryptInDomain(plaintextBytes, "default");
        Assert.assertFalse(Arrays.equals(plaintextBytes, encrypted3));
        Assert.assertFalse(Arrays.equals(encrypted1, encrypted3));
        Assert.assertFalse(Arrays.equals(encrypted2, encrypted3));

        byte[] encrypted4 = sdkSpy.encryptInDomain(plaintextBytes, "default");
        Assert.assertFalse(Arrays.equals(plaintextBytes, encrypted4));
        Assert.assertFalse(Arrays.equals(encrypted1, encrypted4));
        Assert.assertFalse(Arrays.equals(encrypted2, encrypted4));
        Assert.assertFalse(Arrays.equals(encrypted3, encrypted4));

        byte[] encrypted5 = sdkSpy.encryptInDomain(plaintextBytes, "domain-0");
        Assert.assertFalse(Arrays.equals(plaintextBytes, encrypted5));
        Assert.assertFalse(Arrays.equals(encrypted1, encrypted5));
        Assert.assertFalse(Arrays.equals(encrypted2, encrypted5));
        Assert.assertFalse(Arrays.equals(encrypted3, encrypted5));
        Assert.assertFalse(Arrays.equals(encrypted4, encrypted5));

        byte[] encrypted6 = sdkSpy.encryptInDomain(plaintextBytes, "domain-0");
        Assert.assertFalse(Arrays.equals(plaintextBytes, encrypted6));
        Assert.assertFalse(Arrays.equals(encrypted1, encrypted6));
        Assert.assertFalse(Arrays.equals(encrypted2, encrypted6));
        Assert.assertFalse(Arrays.equals(encrypted3, encrypted6));
        Assert.assertFalse(Arrays.equals(encrypted4, encrypted6));
        Assert.assertFalse(Arrays.equals(encrypted5, encrypted6));

        byte[] encrypted7 = sdkSpy.encryptInDomain(plaintextBytes, "domain-1");
        Assert.assertFalse(Arrays.equals(plaintextBytes, encrypted6));
        Assert.assertFalse(Arrays.equals(encrypted1, encrypted7));
        Assert.assertFalse(Arrays.equals(encrypted2, encrypted7));
        Assert.assertFalse(Arrays.equals(encrypted3, encrypted7));
        Assert.assertFalse(Arrays.equals(encrypted4, encrypted7));
        Assert.assertFalse(Arrays.equals(encrypted5, encrypted7));
        Assert.assertFalse(Arrays.equals(encrypted6, encrypted7));

        Assert.assertArrayEquals(sdkSpy.decrypt(encrypted1), plaintextBytes);
        Assert.assertArrayEquals(sdkSpy.decrypt(encrypted2), plaintextBytes);
        Assert.assertArrayEquals(sdkSpy.decrypt(encrypted3), plaintextBytes);
        Assert.assertArrayEquals(sdkSpy.decrypt(encrypted4), plaintextBytes);
        Assert.assertArrayEquals(sdkSpy.decrypt(encrypted5), plaintextBytes);
        Assert.assertArrayEquals(sdkSpy.decrypt(encrypted6), plaintextBytes);
        Assert.assertArrayEquals(sdkSpy.decrypt(encrypted7), plaintextBytes);
    }

    @Test
    public void encryptDecryptWithThreeClients() throws PeacemakrException {

        // Violate abstraction layer for access to internal state for more complete testing + asserting.
        ICryptoImpl sdk1 = (ICryptoImpl) Factory.getCryptoSDK(this.testAPIKey, "java sdk - encryptDecryptWithTwoClients 1", getPeacemakrHostname(), new InMemoryPersister(), null);
        sdk1.register();

        byte[] plaintextBytes = getRandomBytes();

        byte[] encrypted1 = sdk1.encrypt(plaintextBytes);
        Assert.assertFalse(Arrays.equals(plaintextBytes, encrypted1));

        byte[] encrypted2 = sdk1.encrypt(plaintextBytes);
        Assert.assertFalse(Arrays.equals(plaintextBytes, encrypted2));
        Assert.assertFalse(Arrays.equals(encrypted1, encrypted2));

        byte[] encrypted3 = sdk1.encryptInDomain(plaintextBytes, "default");
        Assert.assertFalse(Arrays.equals(plaintextBytes, encrypted3));
        Assert.assertFalse(Arrays.equals(encrypted1, encrypted3));
        Assert.assertFalse(Arrays.equals(encrypted2, encrypted3));

        byte[] encrypted4 = sdk1.encryptInDomain(plaintextBytes, "default");
        Assert.assertFalse(Arrays.equals(plaintextBytes, encrypted4));
        Assert.assertFalse(Arrays.equals(encrypted1, encrypted4));
        Assert.assertFalse(Arrays.equals(encrypted2, encrypted4));
        Assert.assertFalse(Arrays.equals(encrypted3, encrypted4));

        byte[] encrypted5 = sdk1.encryptInDomain(plaintextBytes, "domain-0");
        Assert.assertFalse(Arrays.equals(plaintextBytes, encrypted5));
        Assert.assertFalse(Arrays.equals(encrypted1, encrypted5));
        Assert.assertFalse(Arrays.equals(encrypted2, encrypted5));
        Assert.assertFalse(Arrays.equals(encrypted3, encrypted5));
        Assert.assertFalse(Arrays.equals(encrypted4, encrypted5));

        byte[] encrypted6 = sdk1.encryptInDomain(plaintextBytes, "domain-0");
        Assert.assertFalse(Arrays.equals(plaintextBytes, encrypted6));
        Assert.assertFalse(Arrays.equals(encrypted1, encrypted6));
        Assert.assertFalse(Arrays.equals(encrypted2, encrypted6));
        Assert.assertFalse(Arrays.equals(encrypted3, encrypted6));
        Assert.assertFalse(Arrays.equals(encrypted4, encrypted6));
        Assert.assertFalse(Arrays.equals(encrypted5, encrypted6));

        byte[] encrypted7 = sdk1.encryptInDomain(plaintextBytes, "domain-1");
        Assert.assertFalse(Arrays.equals(plaintextBytes, encrypted6));
        Assert.assertFalse(Arrays.equals(encrypted1, encrypted7));
        Assert.assertFalse(Arrays.equals(encrypted2, encrypted7));
        Assert.assertFalse(Arrays.equals(encrypted3, encrypted7));
        Assert.assertFalse(Arrays.equals(encrypted4, encrypted7));
        Assert.assertFalse(Arrays.equals(encrypted5, encrypted7));
        Assert.assertFalse(Arrays.equals(encrypted6, encrypted7));

        ICryptoImpl sdk2 = (ICryptoImpl) Factory.getCryptoSDK(this.testAPIKey, "java sdk - encryptDecryptWithTwoClients 2", getPeacemakrHostname(), new InMemoryPersister(), null);
        sdk2.register();
        Assert.assertArrayEquals(sdk2.decrypt(encrypted1), plaintextBytes);
        Assert.assertArrayEquals(sdk2.decrypt(encrypted2), plaintextBytes);
        Assert.assertArrayEquals(sdk2.decrypt(encrypted3), plaintextBytes);
        Assert.assertArrayEquals(sdk2.decrypt(encrypted4), plaintextBytes);
        Assert.assertArrayEquals(sdk2.decrypt(encrypted5), plaintextBytes);
        Assert.assertArrayEquals(sdk2.decrypt(encrypted6), plaintextBytes);
        Assert.assertArrayEquals(sdk2.decrypt(encrypted7), plaintextBytes);

        encrypted1 = sdk2.encrypt(plaintextBytes);
        Assert.assertFalse(Arrays.equals(plaintextBytes, encrypted1));
        encrypted2 = sdk2.encrypt(plaintextBytes);
        Assert.assertFalse(Arrays.equals(plaintextBytes, encrypted2));
        Assert.assertFalse(Arrays.equals(encrypted1, encrypted2));
        encrypted3 = sdk2.encryptInDomain(plaintextBytes, "default");
        Assert.assertFalse(Arrays.equals(plaintextBytes, encrypted3));
        Assert.assertFalse(Arrays.equals(encrypted1, encrypted3));
        Assert.assertFalse(Arrays.equals(encrypted2, encrypted3));
        encrypted4 = sdk2.encryptInDomain(plaintextBytes, "default");
        Assert.assertFalse(Arrays.equals(plaintextBytes, encrypted4));
        Assert.assertFalse(Arrays.equals(encrypted1, encrypted4));
        Assert.assertFalse(Arrays.equals(encrypted2, encrypted4));
        Assert.assertFalse(Arrays.equals(encrypted3, encrypted4));
        encrypted5 = sdk2.encryptInDomain(plaintextBytes, "domain-0");
        Assert.assertFalse(Arrays.equals(plaintextBytes, encrypted5));
        Assert.assertFalse(Arrays.equals(encrypted1, encrypted5));
        Assert.assertFalse(Arrays.equals(encrypted2, encrypted5));
        Assert.assertFalse(Arrays.equals(encrypted3, encrypted5));
        Assert.assertFalse(Arrays.equals(encrypted4, encrypted5));
        encrypted6 = sdk2.encryptInDomain(plaintextBytes, "domain-0");
        Assert.assertFalse(Arrays.equals(plaintextBytes, encrypted6));
        Assert.assertFalse(Arrays.equals(encrypted1, encrypted6));
        Assert.assertFalse(Arrays.equals(encrypted2, encrypted6));
        Assert.assertFalse(Arrays.equals(encrypted3, encrypted6));
        Assert.assertFalse(Arrays.equals(encrypted4, encrypted6));
        Assert.assertFalse(Arrays.equals(encrypted5, encrypted6));
        encrypted7 = sdk2.encryptInDomain(plaintextBytes, "domain-1");
        Assert.assertFalse(Arrays.equals(plaintextBytes, encrypted6));
        Assert.assertFalse(Arrays.equals(encrypted1, encrypted7));
        Assert.assertFalse(Arrays.equals(encrypted2, encrypted7));
        Assert.assertFalse(Arrays.equals(encrypted3, encrypted7));
        Assert.assertFalse(Arrays.equals(encrypted4, encrypted7));
        Assert.assertFalse(Arrays.equals(encrypted5, encrypted7));
        Assert.assertFalse(Arrays.equals(encrypted6, encrypted7));

        Assert.assertArrayEquals(sdk1.decrypt(encrypted1), plaintextBytes);
        Assert.assertArrayEquals(sdk1.decrypt(encrypted2), plaintextBytes);
        Assert.assertArrayEquals(sdk1.decrypt(encrypted3), plaintextBytes);
        Assert.assertArrayEquals(sdk1.decrypt(encrypted4), plaintextBytes);
        Assert.assertArrayEquals(sdk1.decrypt(encrypted5), plaintextBytes);
        Assert.assertArrayEquals(sdk1.decrypt(encrypted6), plaintextBytes);
        Assert.assertArrayEquals(sdk1.decrypt(encrypted7), plaintextBytes);

        Assert.assertArrayEquals(sdk2.decrypt(encrypted1), plaintextBytes);
        Assert.assertArrayEquals(sdk2.decrypt(encrypted2), plaintextBytes);
        Assert.assertArrayEquals(sdk2.decrypt(encrypted3), plaintextBytes);
        Assert.assertArrayEquals(sdk2.decrypt(encrypted4), plaintextBytes);
        Assert.assertArrayEquals(sdk2.decrypt(encrypted5), plaintextBytes);
        Assert.assertArrayEquals(sdk2.decrypt(encrypted6), plaintextBytes);
        Assert.assertArrayEquals(sdk2.decrypt(encrypted7), plaintextBytes);

        ICryptoImpl sdk3 = (ICryptoImpl) Factory.getCryptoSDK(this.testAPIKey, "java sdk - encryptDecryptWithTwoClients 3", getPeacemakrHostname(), new InMemoryPersister(), null);
        sdk3.register();
        Assert.assertArrayEquals(sdk3.decrypt(encrypted1), plaintextBytes);
        Assert.assertArrayEquals(sdk3.decrypt(encrypted2), plaintextBytes);
        Assert.assertArrayEquals(sdk3.decrypt(encrypted3), plaintextBytes);
        Assert.assertArrayEquals(sdk3.decrypt(encrypted4), plaintextBytes);
        Assert.assertArrayEquals(sdk3.decrypt(encrypted5), plaintextBytes);
        Assert.assertArrayEquals(sdk3.decrypt(encrypted6), plaintextBytes);
        Assert.assertArrayEquals(sdk3.decrypt(encrypted7), plaintextBytes);
    }

    @Test
    public void getDebugInfo() throws PeacemakrException {
        ICrypto sdk = Factory.getCryptoSDK("", "", null, new InMemoryPersister(), null);
        String debug = sdk.getDebugInfo();
        Assert.assertEquals("Peacemakr Java Sdk DebugInfo - orgId=UnknownOrgId clientId=UnknownClientId preferredKeyId=UnknownPreferredKeyId", debug);
    }
}