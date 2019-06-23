package io.peacemakr.crypto.impl.crypto;

import com.squareup.okhttp.OkHttpClient;
import io.peacemakr.crypto.ICrypto;
import io.peacemakr.crypto.Persister;
import io.peacemakr.crypto.exception.PeacemakrException;
import io.peacemakr.crypto.exception.ServerError;
import io.peacemakr.crypto.exception.UnrecoverableClockSkewDetected;
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

import java.net.http.HttpClient;
import java.util.logging.Logger;

public class ICryptoImpl implements ICrypto {

  private static final String JAVA_SDK_VERSION = "0.0.1";
  private static final String PERSISTER_PREFERED_KEYID = "PreferedKeyId";


  final String apiKey;
  final String clientName;
  final String sdkVersion;
  final String peacemakrHostname;
  Organization org;
  CryptoConfig cryptoConfig;
  Client client;
  Authentication authentication;
  Persister persister;
  Logger logger;
  long lastUpdatedAt;

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

  @Override
  public void register() throws PeacemakrException {

    if (org != null) {
      return;
    }

    ApiClient apiClient = new ApiClient();
    apiClient.setBasePath(peacemakrHostname + "/api/v1");
    apiClient.setApiKey(apiKey);

    // Populate Org.

    OrgApi orgApi = new OrgApi(apiClient);
    Organization myOrg;
    try {
      myOrg = orgApi.getOrganizationFromAPIKey(apiKey);
    } catch (ApiException e) {
      throw new ServerError(e);
    }
    this.org = myOrg;

    // Populate Crypto config,

    CryptoConfigApi cryptoConfigApi = new CryptoConfigApi(apiClient);
    CryptoConfig cryptoConfig = null;
    try {
      cryptoConfig = cryptoConfigApi.getCryptoConfig(org.getCryptoConfigId());
    } catch (ApiException e) {
      throw new ServerError(e);
    }
    this.cryptoConfig = cryptoConfig;


    // TODO: Actually Dervier a key.  Needed: crypto lib

    PublicKey publicKey = new PublicKey();
    long seconds = System.currentTimeMillis() / 1000;
    if (seconds > Integer.MAX_VALUE) {
      throw new UnrecoverableClockSkewDetected("Failed to detect a valid time for local asymmetric key creation time," +
              " time expected to be less than " + Integer.MAX_VALUE);
    }
    publicKey.setCreationTime((int)seconds);
    publicKey.setEncoding("pem");
    publicKey.setId("x");
    publicKey.setKey("x");
    publicKey.setKeyType(cryptoConfig.getClientKeyType());

    Client newClient = new Client();
    newClient.setId("x");
    newClient.setPublicKey(publicKey);
    newClient.setSdk(JAVA_SDK_VERSION);

    ClientApi clientApi = new ClientApi(apiClient);
    try {
      // The response from the server will populate our clientId field.
      newClient = clientApi.addClient(newClient);
    } catch (ApiException e) {
      throw new ServerError(e);
    }

    if (newClient == null) {
      throw new ServerError("Failed to get new client, null returned from server");
    }

    this.client = newClient;

    // Go off and get the.


  }

  @Override
  public void sync() {

  }

  @Override
  public String encrypt(String plainText) {
    return null;
  }

  @Override
  public byte[] encrypt(byte[] plainText) {
    return new byte[0];
  }

  @Override
  public String encryptInDomain(String plainText, String useDomainName) {
    return null;
  }

  @Override
  public byte[] encryptInDomain(byte[] plainText, String useDomainName) {
    return new byte[0];
  }

  @Override
  public String decrypt(String cipherText) {
    return null;
  }

  @Override
  public byte[] decrypt(byte[] cipherText) {
    return new byte[0];
  }

  @Override
  public String getDebugInfo() {
    String orgId;
    String clientId;
    String preferedKeyId;

    if (org == null || org.getId() == null) {
      orgId = "UnknownOrgId";
    } else {
      orgId = org.getId();
    }

    if (persister == null || !persister.exists(PERSISTER_PREFERED_KEYID)) {
      preferedKeyId = "Unknown" + PERSISTER_PREFERED_KEYID;
    } else {
      preferedKeyId = persister.load(PERSISTER_PREFERED_KEYID);
    }

    if (client == null || client.getId() == null) {
      clientId = "UnkonwnClientId";
    } else {
      clientId = client.getId();
    }

    return "Peacemakr Java Sdk DebugInfo - orgId=" + orgId + " clientId=" + clientId + " preferedKeyId=" + preferedKeyId;
  }
}
