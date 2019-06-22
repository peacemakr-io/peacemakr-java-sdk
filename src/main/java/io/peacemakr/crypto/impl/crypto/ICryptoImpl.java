package io.peacemakr.crypto.impl.crypto;

import io.peacemakr.crypto.ICrypto;
import io.peacemakr.crypto.Persister;
import io.swagger.client.auth.Authentication;
import io.swagger.client.model.CryptoConfig;
import io.swagger.client.model.Organization;

import java.util.logging.Logger;

public class ICryptoImpl implements ICrypto {

  private static final String JAVA_SDK_VERSION = "0.0.1";
  final String apiKey;
  final String clientName;
  final String sdkVersion;
  final String peacemakrHostname;
  Organization org;
  CryptoConfig cryptoConfig;
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
  public void register() {

    if (org != null) {
      return;
    }



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
  public void getDebugInfo() {

  }
}
