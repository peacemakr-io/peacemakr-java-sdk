package io.peacemakr.crypto.impl.crypto;

import io.peacemakr.corecrypto.AsymmetricKey;
import io.peacemakr.corecrypto.Crypto;
import io.peacemakr.crypto.ICrypto;
import io.peacemakr.crypto.Persister;
import io.peacemakr.crypto.exception.PeacemakrException;
import io.peacemakr.crypto.exception.ServerException;
import io.peacemakr.crypto.exception.UnrecoverableClockSkewDetectedException;
import io.swagger.client.ApiClient;
import io.swagger.client.ApiException;
import io.swagger.client.api.ClientApi;
import io.swagger.client.api.CryptoConfigApi;
import io.swagger.client.api.OrgApi;
import io.swagger.client.auth.Authentication;
import io.swagger.client.model.Client;
import io.swagger.client.model.CryptoConfig;
import io.swagger.client.model.Organization;
import io.swagger.client.model.PublicKey;

import java.util.logging.Logger;

public class ICryptoImpl implements ICrypto {

  private static final String JAVA_SDK_VERSION = "0.0.1";
  private static final String PERSISTER_PRIV_KEY = "Priv";
  private static final String PERSISTER_PUB_KEY = "Pub";
  private static final String PERSISTER_CLIENTID_KEY = "ClientId";
  private static final String PERSISTER_PREFERRED_KEYID = "PreferredKeyId";
  private static final String PERSISTER_APIKEY_KEY = "ApiKey";


  private final String apiKey;
  private final String clientName;
  private final String sdkVersion;
  private final String peacemakrHostname;
  private Organization org;
  private CryptoConfig cryptoConfig;
  private Client client;
  private ApiClient apiClient;
  private Authentication authentication;
  private Persister persister;
  private Logger logger;
  private long lastUpdatedAt;


  public ICryptoImpl(String apiKey, String clientName, String peacemakrHostname, Persister persister, Logger logger) {
    this.apiKey = apiKey;
    this.clientName = clientName;
    this.sdkVersion = JAVA_SDK_VERSION;
    this.peacemakrHostname = peacemakrHostname;
    this.org = null;
    this.cryptoConfig = null;
    this.persister = persister;
    this.logger = logger;
    this.lastUpdatedAt = 0;
  }

  private synchronized String getApiKey() throws PeacemakrException {
    if (apiKey == null) {
      throw new PeacemakrException("Missing api key, please provide apiKey when constructing the SDK.");
    }
    return apiKey;
  }

  private synchronized ApiClient getClient() throws PeacemakrException {

    if (this.apiClient != null) {
      return apiClient;
    }

    apiClient = new ApiClient();
    apiClient.setBasePath(peacemakrHostname + "/api/v1");
    apiClient.setApiKey(getApiKey());

    // Save this for later.
    persister.save(PERSISTER_APIKEY_KEY, apiKey);

    // Return.
    return apiClient;
  }

  private synchronized void doBootstrap() throws PeacemakrException {

    // If it's already bootstrapped, don't do it agian.
    if (isBootstraped()) {
      return;
    }

    ApiClient apiClient = getClient();

    // Populate Org.

    OrgApi orgApi = new OrgApi(apiClient);
    Organization myOrg;
    try {
      myOrg = orgApi.getOrganizationFromAPIKey(apiKey);
    } catch (ApiException e) {
      throw new ServerException(e);
    }
    this.org = myOrg;

    // Populate Crypto config,

    CryptoConfigApi cryptoConfigApi = new CryptoConfigApi(apiClient);
    CryptoConfig cryptoConfig = null;
    try {
      cryptoConfig = cryptoConfigApi.getCryptoConfig(org.getCryptoConfigId());
    } catch (ApiException e) {
      throw new ServerException(e);
    }
    this.cryptoConfig = cryptoConfig;
  }

  private boolean isBootstraped() {
    return org != null && cryptoConfig != null && client != null;
  }

  private void verifyIsBootstrappedAndRegistered() throws PeacemakrException {
    if (!isBootstraped() || !isRegisterd()) {
      throw new PeacemakrException("SDK was not registered, please register before using other SDK operations.");
    }
  }

  private boolean isRegisterd() {
    return persister.exists( PERSISTER_PREFERRED_KEYID) &&
            persister.exists(PERSISTER_CLIENTID_KEY) &&
            persister.exists( PERSISTER_PREFERRED_KEYID) &&
            persister.exists(PERSISTER_PRIV_KEY) &&
            persister.exists(PERSISTER_PUB_KEY);
  }

  @Override
  public synchronized void register() throws PeacemakrException {

    if (isRegisterd()) {
      return;
    }

    doBootstrap();

    Crypto.AsymmetricCryptoTypes clientKeyType;
    switch (this.cryptoConfig.getClientKeyType()) {

      case "rsa":
        switch (this.cryptoConfig.getClientKeyBitlength()) {
          case 2048:
            clientKeyType = Crypto.AsymmetricCryptoTypes.RSA_2048;
            break;
          case 4096:
          default:
            clientKeyType = Crypto.AsymmetricCryptoTypes.RSA_4096;
            break;
        }
        break;
      case "ec":
        switch (this.cryptoConfig.getClientKeyBitlength()) {
          case 256:
            clientKeyType = Crypto.AsymmetricCryptoTypes.EC_256;
            break;
          case 384:
            clientKeyType = Crypto.AsymmetricCryptoTypes.EC_384;
            break;
          case 521:
          default:
            clientKeyType = Crypto.AsymmetricCryptoTypes.EC_521;
            break;
        }
        break;
      default:
        clientKeyType = Crypto.AsymmetricCryptoTypes.EC_521;
    }
    AsymmetricKey clientKey = Crypto.genKeypairFromPRNG(clientKeyType);
    String publicKeyPEM = clientKey.getPubPem();
    String privateKeyPEM = clientKey.petPemPriv();

    this.persister.save(PERSISTER_PRIV_KEY, privateKeyPEM);
    this.persister.save(PERSISTER_PUB_KEY, publicKeyPEM);

    PublicKey publicKey = new PublicKey();
    long seconds = System.currentTimeMillis() / 1000;
    if (seconds > Integer.MAX_VALUE) {
      throw new UnrecoverableClockSkewDetectedException("Failed to detect a valid time for local asymmetric key creation time," +
              " time expected to be less than " + Integer.MAX_VALUE);
    }
    publicKey.setCreationTime((int)seconds);
    publicKey.setEncoding("pem");
    publicKey.setId("");
    publicKey.setKey(publicKeyPEM);
    publicKey.setKeyType(cryptoConfig.getClientKeyType());

    Client newClient = new Client();
    newClient.setId("");
    newClient.addPublicKeysItem(publicKey);
    newClient.setSdk(JAVA_SDK_VERSION);

    ClientApi clientApi = new ClientApi(getClient());
    try {
      // The response from the server will populate our clientId field.
      newClient = clientApi.addClient(newClient);
    } catch (ApiException e) {
      throw new ServerException(e);
    }

    if (newClient == null) {
      throw new ServerException("Failed to get new client, null returned from server");
    }

    this.client = newClient;

    if (this.client.getId() == null || this.client.getId().isEmpty()) {
      throw new ServerException("Failed to register a new clientId during client registration");
    }

    if (this.client.getPublicKeys().isEmpty()) {
      throw new ServerException("Failed to register new public keys during client registration");
    }

    if (this.client.getPublicKeys().get(0) == null) {
      throw new ServerException("Failed to register, null public key detected during client registration");
    }

    if (this.client.getPublicKeys().get(0).getId() == null || this.client.getPublicKeys().get(0).getId().isEmpty()) {
      throw new ServerException("Failed to register, missing public key id detected during client registration");
    }

    this.persister.save(PERSISTER_CLIENTID_KEY, this.client.getId());
    this.persister.save( PERSISTER_PREFERRED_KEYID, this.client.getPublicKeys().get(0).getId());
  }

  @Override
  public void sync() throws PeacemakrException {
    verifyIsBootstrappedAndRegistered();

  }

  @Override
  public String encrypt(String plainText) throws PeacemakrException {
    verifyIsBootstrappedAndRegistered();

    return null;
  }

  @Override
  public byte[] encrypt(byte[] plainText) throws PeacemakrException {
    verifyIsBootstrappedAndRegistered();

    return new byte[0];
  }

  @Override
  public String encryptInDomain(String plainText, String useDomainName) throws PeacemakrException {
    verifyIsBootstrappedAndRegistered();

    return null;
  }

  @Override
  public byte[] encryptInDomain(byte[] plainText, String useDomainName) throws PeacemakrException {
    verifyIsBootstrappedAndRegistered();

    return new byte[0];
  }

  @Override
  public String decrypt(String cipherText) throws PeacemakrException {
    verifyIsBootstrappedAndRegistered();

    return null;
  }

  @Override
  public byte[] decrypt(byte[] cipherText) throws PeacemakrException {
    verifyIsBootstrappedAndRegistered();

    return new byte[0];
  }

  @Override
  public String getDebugInfo() {
    String orgId;
    String clientId;
    String preferredKeyId;

    orgId = "UnknownOrgId";
    if (org != null && org.getId() != null) {
      orgId = org.getId();
    }

    preferredKeyId = "Unknown" + PERSISTER_PREFERRED_KEYID;
    if (persister != null && persister.exists( PERSISTER_PREFERRED_KEYID)) {
      preferredKeyId = persister.load( PERSISTER_PREFERRED_KEYID);
    }

    clientId = "Unknown" + PERSISTER_CLIENTID_KEY;
    if (client != null && client.getId() != null) {
      clientId = client.getId();
    } else if (persister != null && persister.exists(PERSISTER_CLIENTID_KEY)) {
      clientId = persister.load(PERSISTER_CLIENTID_KEY);
    }

    return "Peacemakr Java Sdk DebugInfo - orgId=" + orgId + " clientId=" + clientId + " preferredKeyId=" + preferredKeyId;
  }
}
