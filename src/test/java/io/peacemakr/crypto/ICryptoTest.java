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

        sdk.encrypt("This is a test.");

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