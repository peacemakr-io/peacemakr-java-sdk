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

import java.util.Map;

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

        return DEFAULT_PEACEMAKR_TEST_HOSTNAME;
    }

    @Before
    public void setUp() throws Exception {

        LogManager.getRootLogger().setLevel(Level.ALL);

        Map<String, String> map = System.getenv();
        testAPIKey = map.get("PEACEMAKR_TEST_API_KEY");

        if (testAPIKey == null) {

            ApiClient apiClient = new ApiClient();
            apiClient.setBasePath(getPeacemakrHostname() + "/api/v1");
            apiClient.setApiKey("");

            OrgApi orgApi = new OrgApi(apiClient);
            APIKey apiKey;
            try {
                apiKey = orgApi.getTestOrganizationAPIKey();
            } catch ( ApiException e) {
                System.out.println(e);
                throw new ServerException(e);
            }
            this.testAPIKey = apiKey.getKey();
            this.testOrgId = apiKey.getOrgId();
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

        String encrypted1 = sdkSpy.encrypt("This is a test.");
        Assert.assertNotEquals("This is a test.", encrypted1);

        String encrypted2 = sdkSpy.encrypt("This is a test.");
        Assert.assertNotEquals("This is a test.", encrypted2);
        Assert.assertNotEquals(encrypted1, encrypted2);

        String encrypted3 = sdkSpy.encryptInDomain("This is a test.", "default");
        Assert.assertNotEquals("This is a test.", encrypted3);
        Assert.assertNotEquals(encrypted1, encrypted3);
        Assert.assertNotEquals(encrypted2, encrypted3);

        String encrypted4 = sdkSpy.encryptInDomain("This is a test.", "default");
        Assert.assertNotEquals("This is a test.", encrypted4);
        Assert.assertNotEquals(encrypted1, encrypted4);
        Assert.assertNotEquals(encrypted2, encrypted4);
        Assert.assertNotEquals(encrypted3, encrypted4);

        String encrypted5 = sdkSpy.encryptInDomain("This is a test.", "domain-0");
        Assert.assertNotEquals("This is a test.", encrypted5);
        Assert.assertNotEquals(encrypted1, encrypted5);
        Assert.assertNotEquals(encrypted2, encrypted5);
        Assert.assertNotEquals(encrypted3, encrypted5);
        Assert.assertNotEquals(encrypted4, encrypted5);

        String encrypted6 = sdkSpy.encryptInDomain("This is a test.", "domain-0");
        Assert.assertNotEquals("This is a test.", encrypted6);
        Assert.assertNotEquals(encrypted1, encrypted6);
        Assert.assertNotEquals(encrypted2, encrypted6);
        Assert.assertNotEquals(encrypted3, encrypted6);
        Assert.assertNotEquals(encrypted4, encrypted6);
        Assert.assertNotEquals(encrypted5, encrypted6);

        String encrypted7 = sdkSpy.encryptInDomain("This is a test.", "domain-1");
        Assert.assertNotEquals("This is a test.", encrypted6);
        Assert.assertNotEquals(encrypted1, encrypted7);
        Assert.assertNotEquals(encrypted2, encrypted7);
        Assert.assertNotEquals(encrypted3, encrypted7);
        Assert.assertNotEquals(encrypted4, encrypted7);
        Assert.assertNotEquals(encrypted5, encrypted7);
        Assert.assertNotEquals(encrypted6, encrypted7);

        Assert.assertEquals(sdkSpy.decrypt(encrypted1), "This is a test.");
        Assert.assertEquals(sdkSpy.decrypt(encrypted2), "This is a test.");
        Assert.assertEquals(sdkSpy.decrypt(encrypted3), "This is a test.");
        Assert.assertEquals(sdkSpy.decrypt(encrypted4), "This is a test.");
        Assert.assertEquals(sdkSpy.decrypt(encrypted5), "This is a test.");
        Assert.assertEquals(sdkSpy.decrypt(encrypted6), "This is a test.");
        Assert.assertEquals(sdkSpy.decrypt(encrypted7), "This is a test.");
    }

    @Test
    public void encryptDecryptWithThreeClients() throws PeacemakrException {

        // Violate abstraction layer for access to internal state for more complete testing + asserting.
        ICryptoImpl sdk1 = (ICryptoImpl) Factory.getCryptoSDK(this.testAPIKey, "java sdk - encryptDecryptWithTwoClients 1", getPeacemakrHostname(), new InMemoryPersister(), null);
        sdk1.register();

        String encrypted1 = sdk1.encrypt("This is a test.");
        Assert.assertNotEquals("This is a test.", encrypted1);

        String encrypted2 = sdk1.encrypt("This is a test.");
        Assert.assertNotEquals("This is a test.", encrypted2);
        Assert.assertNotEquals(encrypted1, encrypted2);

        String encrypted3 = sdk1.encryptInDomain("This is a test.", "default");
        Assert.assertNotEquals("This is a test.", encrypted3);
        Assert.assertNotEquals(encrypted1, encrypted3);
        Assert.assertNotEquals(encrypted2, encrypted3);

        String encrypted4 = sdk1.encryptInDomain("This is a test.", "default");
        Assert.assertNotEquals("This is a test.", encrypted4);
        Assert.assertNotEquals(encrypted1, encrypted4);
        Assert.assertNotEquals(encrypted2, encrypted4);
        Assert.assertNotEquals(encrypted3, encrypted4);

        String encrypted5 = sdk1.encryptInDomain("This is a test.", "domain-0");
        Assert.assertNotEquals("This is a test.", encrypted5);
        Assert.assertNotEquals(encrypted1, encrypted5);
        Assert.assertNotEquals(encrypted2, encrypted5);
        Assert.assertNotEquals(encrypted3, encrypted5);
        Assert.assertNotEquals(encrypted4, encrypted5);

        String encrypted6 = sdk1.encryptInDomain("This is a test.", "domain-0");
        Assert.assertNotEquals("This is a test.", encrypted6);
        Assert.assertNotEquals(encrypted1, encrypted6);
        Assert.assertNotEquals(encrypted2, encrypted6);
        Assert.assertNotEquals(encrypted3, encrypted6);
        Assert.assertNotEquals(encrypted4, encrypted6);
        Assert.assertNotEquals(encrypted5, encrypted6);

        String encrypted7 = sdk1.encryptInDomain("This is a test.", "domain-1");
        Assert.assertNotEquals("This is a test.", encrypted6);
        Assert.assertNotEquals(encrypted1, encrypted7);
        Assert.assertNotEquals(encrypted2, encrypted7);
        Assert.assertNotEquals(encrypted3, encrypted7);
        Assert.assertNotEquals(encrypted4, encrypted7);
        Assert.assertNotEquals(encrypted5, encrypted7);
        Assert.assertNotEquals(encrypted6, encrypted7);

        ICryptoImpl sdk2 = (ICryptoImpl) Factory.getCryptoSDK(this.testAPIKey, "java sdk - encryptDecryptWithTwoClients 2", getPeacemakrHostname(), new InMemoryPersister(), null);
        sdk2.register();
        Assert.assertEquals(sdk2.decrypt(encrypted1), "This is a test.");
        Assert.assertEquals(sdk2.decrypt(encrypted2), "This is a test.");
        Assert.assertEquals(sdk2.decrypt(encrypted3), "This is a test.");
        Assert.assertEquals(sdk2.decrypt(encrypted4), "This is a test.");
        Assert.assertEquals(sdk2.decrypt(encrypted5), "This is a test.");
        Assert.assertEquals(sdk2.decrypt(encrypted6), "This is a test.");
        Assert.assertEquals(sdk2.decrypt(encrypted7), "This is a test.");

        encrypted1 = sdk2.encrypt("This is a test.");
        Assert.assertNotEquals("This is a test.", encrypted1);
        encrypted2 = sdk2.encrypt("This is a test.");
        Assert.assertNotEquals("This is a test.", encrypted2);
        Assert.assertNotEquals(encrypted1, encrypted2);
        encrypted3 = sdk2.encryptInDomain("This is a test.", "default");
        Assert.assertNotEquals("This is a test.", encrypted3);
        Assert.assertNotEquals(encrypted1, encrypted3);
        Assert.assertNotEquals(encrypted2, encrypted3);
        encrypted4 = sdk2.encryptInDomain("This is a test.", "default");
        Assert.assertNotEquals("This is a test.", encrypted4);
        Assert.assertNotEquals(encrypted1, encrypted4);
        Assert.assertNotEquals(encrypted2, encrypted4);
        Assert.assertNotEquals(encrypted3, encrypted4);
        encrypted5 = sdk2.encryptInDomain("This is a test.", "domain-0");
        Assert.assertNotEquals("This is a test.", encrypted5);
        Assert.assertNotEquals(encrypted1, encrypted5);
        Assert.assertNotEquals(encrypted2, encrypted5);
        Assert.assertNotEquals(encrypted3, encrypted5);
        Assert.assertNotEquals(encrypted4, encrypted5);
        encrypted6 = sdk2.encryptInDomain("This is a test.", "domain-0");
        Assert.assertNotEquals("This is a test.", encrypted6);
        Assert.assertNotEquals(encrypted1, encrypted6);
        Assert.assertNotEquals(encrypted2, encrypted6);
        Assert.assertNotEquals(encrypted3, encrypted6);
        Assert.assertNotEquals(encrypted4, encrypted6);
        Assert.assertNotEquals(encrypted5, encrypted6);
        encrypted7 = sdk2.encryptInDomain("This is a test.", "domain-1");
        Assert.assertNotEquals("This is a test.", encrypted6);
        Assert.assertNotEquals(encrypted1, encrypted7);
        Assert.assertNotEquals(encrypted2, encrypted7);
        Assert.assertNotEquals(encrypted3, encrypted7);
        Assert.assertNotEquals(encrypted4, encrypted7);
        Assert.assertNotEquals(encrypted5, encrypted7);
        Assert.assertNotEquals(encrypted6, encrypted7);

        Assert.assertEquals(sdk1.decrypt(encrypted1), "This is a test.");
        Assert.assertEquals(sdk1.decrypt(encrypted2), "This is a test.");
        Assert.assertEquals(sdk1.decrypt(encrypted3), "This is a test.");
        Assert.assertEquals(sdk1.decrypt(encrypted4), "This is a test.");
        Assert.assertEquals(sdk1.decrypt(encrypted5), "This is a test.");
        Assert.assertEquals(sdk1.decrypt(encrypted6), "This is a test.");
        Assert.assertEquals(sdk1.decrypt(encrypted7), "This is a test.");

        Assert.assertEquals(sdk2.decrypt(encrypted1), "This is a test.");
        Assert.assertEquals(sdk2.decrypt(encrypted2), "This is a test.");
        Assert.assertEquals(sdk2.decrypt(encrypted3), "This is a test.");
        Assert.assertEquals(sdk2.decrypt(encrypted4), "This is a test.");
        Assert.assertEquals(sdk2.decrypt(encrypted5), "This is a test.");
        Assert.assertEquals(sdk2.decrypt(encrypted6), "This is a test.");
        Assert.assertEquals(sdk2.decrypt(encrypted7), "This is a test.");

        ICryptoImpl sdk3 = (ICryptoImpl) Factory.getCryptoSDK(this.testAPIKey, "java sdk - encryptDecryptWithTwoClients 3", getPeacemakrHostname(), new InMemoryPersister(), null);
        sdk3.register();
        Assert.assertEquals(sdk3.decrypt(encrypted1), "This is a test.");
        Assert.assertEquals(sdk3.decrypt(encrypted2), "This is a test.");
        Assert.assertEquals(sdk3.decrypt(encrypted3), "This is a test.");
        Assert.assertEquals(sdk3.decrypt(encrypted4), "This is a test.");
        Assert.assertEquals(sdk3.decrypt(encrypted5), "This is a test.");
        Assert.assertEquals(sdk3.decrypt(encrypted6), "This is a test.");
        Assert.assertEquals(sdk3.decrypt(encrypted7), "This is a test.");
    }

    @Test
    public void getDebugInfo() throws PeacemakrException {
        ICrypto sdk = Factory.getCryptoSDK("", "", null, new InMemoryPersister(), null);
        String debug = sdk.getDebugInfo();
        Assert.assertEquals("Peacemakr Java Sdk DebugInfo - orgId=UnknownOrgId clientId=UnknownClientId preferredKeyId=UnknownPreferredKeyId", debug);
    }
}