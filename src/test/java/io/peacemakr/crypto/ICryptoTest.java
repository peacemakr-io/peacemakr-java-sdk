package io.peacemakr.crypto;

import io.peacemakr.crypto.exception.PeacemakrException;
import io.peacemakr.crypto.exception.ServerException;
import io.peacemakr.crypto.impl.crypto.ICryptoImpl;
import io.peacemakr.crypto.impl.persister.InMemoryPersister;
import io.swagger.client.ApiClient;
import io.swagger.client.ApiException;
import io.swagger.client.api.OrgApi;
import io.swagger.client.model.APIKey;
import io.swagger.client.model.Organization;
import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.junit.*;

import java.util.Map;

import static org.junit.Assert.*;

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
        ICryptoImpl sdk = (ICryptoImpl) Factory.getCryptoSDK(this.testAPIKey, "register test", getPeacemakrHostname(), new InMemoryPersister(), null);
        sdk.register();

        String debug = sdk.getDebugInfo();
        Assert.assertNotEquals("Peacemakr Java Sdk DebugInfo - orgId=UnknownOrgId clientId=UnkonwnClientId preferedKeyId=UnknownPreferedKeyId", debug);

    }

    @Test
    public void sync() throws PeacemakrException {

        // Violate abstraction layer for access to internal state for more complete testing + asserting.
        ICryptoImpl sdk = (ICryptoImpl) Factory.getCryptoSDK(this.testAPIKey, "register test", getPeacemakrHostname(), new InMemoryPersister(), null);
        sdk.register();

        String debug = sdk.getDebugInfo();
        Assert.assertNotEquals("Peacemakr Java Sdk DebugInfo - orgId=UnknownOrgId clientId=UnkonwnClientId preferedKeyId=UnknownPreferedKeyId", debug);

        sdk.sync();

    }

    @Test
    public void encrypt() throws PeacemakrException {
        // Violate abstraction layer for access to internal state for more complete testing + asserting.
        ICryptoImpl sdk = (ICryptoImpl) Factory.getCryptoSDK(this.testAPIKey, "register test", getPeacemakrHostname(), new InMemoryPersister(), null);
        sdk.register();

        String debug = sdk.getDebugInfo();
        Assert.assertNotEquals("Peacemakr Java Sdk DebugInfo - orgId=UnknownOrgId clientId=UnkonwnClientId preferedKeyId=UnknownPreferedKeyId", debug);

        String encrypted1 = sdk.encrypt("This is a test.");
        Assert.assertNotEquals("This is a test.", encrypted1);

        String encrypted2 = sdk.encrypt("This is a test.");
        Assert.assertNotEquals("This is a test.", encrypted2);
        Assert.assertNotEquals(encrypted1, encrypted2);

        String encrypted3 = sdk.encryptInDomain("This is a test.", "default");
        Assert.assertNotEquals("This is a test.", encrypted3);
        Assert.assertNotEquals(encrypted1, encrypted3);
        Assert.assertNotEquals(encrypted2, encrypted3);

        String encrypted4 = sdk.encryptInDomain("This is a test.", "default");
        Assert.assertNotEquals("This is a test.", encrypted4);
        Assert.assertNotEquals(encrypted1, encrypted4);
        Assert.assertNotEquals(encrypted2, encrypted4);
        Assert.assertNotEquals(encrypted3, encrypted4);

        String encrypted5 = sdk.encryptInDomain("This is a test.", "domain-");
        Assert.assertNotEquals("This is a test.", encrypted5);
        Assert.assertNotEquals(encrypted1, encrypted5);
        Assert.assertNotEquals(encrypted2, encrypted5);
        Assert.assertNotEquals(encrypted3, encrypted5);
        Assert.assertNotEquals(encrypted4, encrypted5);

        String encrypted6 = sdk.encryptInDomain("This is a test.", "domain-");
        Assert.assertNotEquals("This is a test.", encrypted6);
        Assert.assertNotEquals(encrypted1, encrypted6);
        Assert.assertNotEquals(encrypted2, encrypted6);
        Assert.assertNotEquals(encrypted3, encrypted6);
        Assert.assertNotEquals(encrypted4, encrypted6);
        Assert.assertNotEquals(encrypted5, encrypted6);

        Assert.assertEquals(sdk.decrypt(encrypted1), "This is a test.");
        Assert.assertEquals(sdk.decrypt(encrypted2), "This is a test.");
        Assert.assertEquals(sdk.decrypt(encrypted3), "This is a test.");
        Assert.assertEquals(sdk.decrypt(encrypted4), "This is a test.");
        Assert.assertEquals(sdk.decrypt(encrypted5), "This is a test.");
        Assert.assertEquals(sdk.decrypt(encrypted6), "This is a test.");
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