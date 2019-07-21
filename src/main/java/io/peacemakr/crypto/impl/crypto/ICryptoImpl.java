package io.peacemakr.crypto.impl.crypto;

import io.peacemakr.corecrypto.AsymmetricCipher;
import io.peacemakr.corecrypto.AsymmetricKey;
import io.peacemakr.corecrypto.Crypto;
import io.peacemakr.corecrypto.SymmetricCipher;
import io.peacemakr.crypto.ICrypto;
import io.peacemakr.crypto.Persister;
import io.peacemakr.crypto.exception.*;
import io.swagger.client.ApiClient;
import io.swagger.client.ApiException;
import io.swagger.client.api.ClientApi;
import io.swagger.client.api.CryptoConfigApi;
import io.swagger.client.api.KeyServiceApi;
import io.swagger.client.api.OrgApi;
import io.swagger.client.auth.Authentication;
import io.swagger.client.model.*;
import org.apache.log4j.Logger;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

public class ICryptoImpl implements ICrypto {

  private static final String JAVA_SDK_VERSION = "0.0.1";
  private static final String PERSISTER_PRIV_KEY = "Priv";
  private static final String PERSISTER_PUB_KEY = "Pub";
  private static final String PERSISTER_CLIENTID_KEY = "ClientId";
  private static final String PERSISTER_PREFERRED_KEYID = "PreferredKeyId";
  private static final String PERSISTER_APIKEY_KEY = "ApiKey";

  private static final AsymmetricCipher UGLY_HACK_UNTIL_PEM_WORKS = AsymmetricCipher.RSA_4096;


  private static final String Chacha20Poly1305 = "Peacemakr.Symmetric.CHACHA20_POLY1305";
  private static final String Aes128gcm        = "Peacemakr.Symmetric.AES_128_GCM";
  private static final String Aes192gcm        = "Peacemakr.Symmetric.AES_192_GCM";
  private static final String Aes256gcm        = "Peacemakr.Symmetric.AES_256_GCM";
  private static final SymmetricCipher DEFAULT_SYMMETRIC_CIPHER = SymmetricCipher.CHACHA20_POLY1305;

  private static final String Sha224 = "Peacemakr.Digest.SHA_224";
  private static final String Sha256 = "Peacemakr.Digest.SHA_256";
  private static final String Sha384 = "Peacemakr.Digest.SHA_384";
  private static final String Sha512 = "Peacemakr.Digest.SHA_512";
  private static final Crypto.MessageDigest DEFAULT_MESSAGE_DIGEST = Crypto.MessageDigest.SHA_256;

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
  private AsymmetricKey loadedPrivatePreferredKey;


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

  // Why protected? For use with testing.
  protected synchronized ApiClient getClient() throws PeacemakrException {

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

    // Loads the crypto lib, if not done so already.
    try {
      Crypto.init();
    } catch (java.lang.UnsatisfiedLinkError e) {
      throw new PeacemakrException("Failed to link peacemakr core cryptolib: " + e.getMessage());
    }


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

    AsymmetricCipher clientKeyType;
    switch (this.cryptoConfig.getClientKeyType()) {

      case "rsa":
        switch (this.cryptoConfig.getClientKeyBitlength()) {
          case 2048:
            clientKeyType = AsymmetricCipher.RSA_2048;
            break;
          case 4096:
          default:
            clientKeyType = AsymmetricCipher.RSA_4096;
            break;
        }
        break;
      case "ec":
        switch (this.cryptoConfig.getClientKeyBitlength()) {
          case 256:
            clientKeyType = AsymmetricCipher.ECDH_P256;
            break;
          case 384:
            clientKeyType = AsymmetricCipher.ECDH_P384;
            break;
          case 521:
          default:
            clientKeyType = AsymmetricCipher.ECDH_P521;
            break;
        }
        break;
      default:
        clientKeyType = AsymmetricCipher.ECDH_P521;
    }

    clientKeyType = UGLY_HACK_UNTIL_PEM_WORKS;
    logger.error("DUE TO A UGLY HACK, you get a key type of " + UGLY_HACK_UNTIL_PEM_WORKS);


    SymmetricCipher thisIsNeverUsed = SymmetricCipher.CHACHA20_POLY1305;
    AsymmetricKey clientKey = AsymmetricKey.fromPRNG(clientKeyType, thisIsNeverUsed);
    String publicKeyPEM = clientKey.getPubPemStr();
    String privateKeyPEM = clientKey.getPrivPemStr();

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

  private void decryptAndSave(List<EncryptedSymmetricKey> allKeys) {
    // TODO: yea, do this.
  }

  private void updateLocalCryptoConfig(CryptoConfig newConfig) {
    // TODO: yea, do this too.
  }

  @Override
  public void sync() throws PeacemakrException {
    verifyIsBootstrappedAndRegistered();

    CryptoConfigApi cryptoConfigApi = new CryptoConfigApi(getClient());
    try {
      CryptoConfig newConfig = cryptoConfigApi.getCryptoConfig(this.cryptoConfig.getId());
      if (newConfig.equals(this.cryptoConfig)) {
        // Do nothing.
      } else {
        updateLocalCryptoConfig(newConfig);
      }
    } catch ( ApiException e) {
      throw new ServerException(e);
    }

    downloadAndSaveAllKeys(null);

  }

  private void downloadAndSaveAllKeys(List<String> requiredKeyIds) throws PeacemakrException {
    KeyServiceApi keyServiceApi = new KeyServiceApi(getClient());
    try {
      // The response from the server will populate our clientId field.
      List<EncryptedSymmetricKey> allKeys = keyServiceApi.getAllEncryptedKeys(this.client.getPreferredPublicKeyId(), requiredKeyIds);
      decryptAndSave(allKeys);
    } catch (ApiException e) {
      throw new ServerException(e);
    }
  }

  @Override
  public String encrypt(String plainText) throws PeacemakrException {
    verifyIsBootstrappedAndRegistered();
    return new String(encrypt(plainText.getBytes( StandardCharsets.UTF_8)));
  }

  private boolean domainIsValidForEncryption(SymmetricKeyUseDomain domain) {
    return domain.getCreationTime() + domain.getSymmetricKeyEncryptionUseTTL() < (System.currentTimeMillis() / 1000);
  }

  private String selectUseDomainName() {

    List<SymmetricKeyUseDomain> validForEncryption = new ArrayList<>();

    for (SymmetricKeyUseDomain domain : this.cryptoConfig.getSymmetricKeyUseDomains()) {
      if (domainIsValidForEncryption(domain)) {
        validForEncryption.add(domain);
      }
    }

    // No use domains available.
    if (validForEncryption.isEmpty()) {
      return null;
    }

    return validForEncryption.get(ThreadLocalRandom.current().nextInt(validForEncryption.size())).getName();
  }

  @Override
  public byte[] encrypt(byte[] plainText) throws PeacemakrException {
    verifyIsBootstrappedAndRegistered();
    String useDomainName = selectUseDomainName();
    return encryptInDomain(plainText, useDomainName);
  }

  @Override
  public String encryptInDomain(String plainText, String useDomainName) throws PeacemakrException {
    verifyIsBootstrappedAndRegistered();
    return new String(encryptInDomain(plainText.getBytes( StandardCharsets.UTF_8), useDomainName));
  }

  private SymmetricKeyUseDomain getValidUseDomainForEncryption(String useDomain) throws NoValidUseDomainsForEncryptionOperation {

      List<SymmetricKeyUseDomain> useDomains = this.cryptoConfig.getSymmetricKeyUseDomains();
      List<SymmetricKeyUseDomain> validDomainWithThisName = new ArrayList<>();

      SymmetricKeyUseDomain selectedDomain = null;

      for (SymmetricKeyUseDomain domain : useDomains) {
        if (!domain.getName().equals(useDomain)) {
          continue;
        }
        if (!domainIsValidForEncryption(domain)) {
          continue;
        }
        if (!domain.getEncryptionKeyIds().isEmpty()) {
          continue;
        }
        validDomainWithThisName.add(domain);
      }

      if (validDomainWithThisName.isEmpty()) {
        throw new NoValidUseDomainsForEncryptionOperation();
      }

      return validDomainWithThisName.get(ThreadLocalRandom.current().nextInt(validDomainWithThisName.size()));
  }

  private String getEncryptionKeyId(SymmetricKeyUseDomain useDomain) {

    int randomId = ThreadLocalRandom.current().nextInt(useDomain.getEncryptionKeyIds().size());

    return useDomain.getEncryptionKeyIds().get(randomId);
  }

  private byte[] getKey(String keyId) throws UnsupportedEncodingException, PeacemakrException {

    if (this.persister.exists(keyId)) {
      String key = this.persister.load(keyId);
      return Base64.getDecoder().decode(key.getBytes("UTF-8"));
    }

    List<String> requiredKeys = new ArrayList<>();
    requiredKeys.add(keyId);
    downloadAndSaveAllKeys(requiredKeys);

    if (!this.persister.exists(keyId)) {
      throw new FailedToDownloadKey("KeyId: " + keyId);
    }

    String key = this.persister.load(keyId);
    return Base64.getDecoder().decode(key.getBytes("UTF-8"));
  }

  private SymmetricCipher getSymmetricCipher(String symmetricKeyEncryptionAlg) {
    switch (symmetricKeyEncryptionAlg) {
      case Chacha20Poly1305:
        return SymmetricCipher.CHACHA20_POLY1305;
      case Aes128gcm:
        return SymmetricCipher.AES_128_GCM;
      case Aes192gcm:
        return SymmetricCipher.AES_192_GCM;
      case Aes256gcm:
        return SymmetricCipher.AES_256_GCM;
      default:
        logger.warn("unrecognized symmetric cipher from server: " + symmetricKeyEncryptionAlg + ", defaulting to " + DEFAULT_SYMMETRIC_CIPHER);
        return DEFAULT_SYMMETRIC_CIPHER;
    }
  }

  private Crypto.MessageDigest getDigestAlg(String digestAlgorithm) {

    switch (digestAlgorithm) {
      case Sha224:
        return Crypto.MessageDigest.SHA_224;
      case Sha256:
        return Crypto.MessageDigest.SHA_256;
      case Sha384:
        return Crypto.MessageDigest.SHA_384;
      case Sha512:
        return Crypto.MessageDigest.SHA_512;
      default:
        logger.warn("Unknown digest alg " + digestAlgorithm + ", so using the default of " + DEFAULT_MESSAGE_DIGEST);
        return DEFAULT_MESSAGE_DIGEST;
    }

  }

  private AsymmetricKey getSigningKey(SymmetricKeyUseDomain useDomain) {

    // If this is null, no message signing.
    if (useDomain.getDigestAlgorithm() == null) {
      return null;
    }

    // If we've already loaded this, just re-use it.
    if (this.loadedPrivatePreferredKey != null) {
      return this.loadedPrivatePreferredKey;
    }

    // Create it.
    String privatePem = this.persister.load(PERSISTER_PRIV_KEY);
    this.loadedPrivatePreferredKey = AsymmetricKey.fromPrivPem(UGLY_HACK_UNTIL_PEM_WORKS, SymmetricCipher.CHACHA20_POLY1305, privatePem);

    return this.loadedPrivatePreferredKey;
  }

  @Override
  public byte[] encryptInDomain(byte[] plainText, String useDomainName) throws PeacemakrException {
    verifyIsBootstrappedAndRegistered();

    SymmetricKeyUseDomain useDomainForEncrytpion = getValidUseDomainForEncryption(useDomainName);

    String encryptionKeyIdforEncryption = getEncryptionKeyId(useDomainForEncrytpion);

    byte[] key = null;
    try {
      key = getKey(encryptionKeyIdforEncryption);
    } catch (UnsupportedEncodingException e) {
      logger.error("Failed to get key due to ", e);
      throw new PersistenceLayerCorruptionDetected(e);
    }

    SymmetricCipher symmetricCipher = getSymmetricCipher(useDomainForEncrytpion.getSymmetricKeyEncryptionAlg());
    AsymmetricKey signingKey = getSigningKey(useDomainForEncrytpion);
    Crypto.MessageDigest digest = getDigestAlg(useDomainForEncrytpion.getDigestAlgorithm());

    byte[] encryptedBlob = Crypto.encryptSymmetric(key, symmetricCipher, signingKey, plainText, new byte[]{}, digest);
    return encryptedBlob;
  }

  @Override
  public String decrypt(String cipherText) throws PeacemakrException {
    verifyIsBootstrappedAndRegistered();
    return new String(decrypt(cipherText.getBytes(StandardCharsets.UTF_8)));
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
