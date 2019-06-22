package io.peacemakr.crypto.impl.crypto;

import io.peacemakr.crypto.ICrypto;
import io.peacemakr.crypto.Persister;
import io.peacemakr.crypto.exception.ServerError;
import io.swagger.client.ApiClient;
import io.swagger.client.ApiException;
import io.swagger.client.api.ClientApi;
import io.swagger.client.api.OrgApi;
import io.swagger.client.auth.Authentication;
import io.swagger.client.model.Client;
import io.swagger.client.model.CryptoConfig;
import io.swagger.client.model.Organization;
import io.swagger.client.model.PublicKey;

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
  public void register() throws ServerError {

    if (org != null) {
      return;
    }

    OrgApi orgApi = new OrgApi(new ApiClient());
    Organization myOrg;
    try {
      myOrg = orgApi.getOrganization(null);
    } catch (ApiException e) {
      throw new ServerError(e.getMessage());
    }

    this.org = myOrg;

    // TODO: GET CRYPTO CONFIG, DERIVE KEY OF APPROPRIATE TYPE, AND REGISTER THE CLIENT

    Client newClient = new Client();
    newClient.setId("");
    newClient.setPublicKey(null); // We
    newClient.setSdk(JAVA_SDK_VERSION);

    ClientApi clientApi = new ClientApi(new ApiClient());
    try {
      // The response from the server will populate our clientId field.
      newClient = clientApi.addClient(newClient);
    } catch (ApiException e) {
      throw new ServerError(e.getMessage());
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
