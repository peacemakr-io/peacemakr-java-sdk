package io.peacemakr.crypto.impl.crypto;

import com.google.gson.Gson;
import io.peacemakr.corecrypto.*;
import io.peacemakr.crypto.ICrypto;
import io.peacemakr.crypto.Persister;
import io.peacemakr.crypto.exception.*;
import io.peacemakr.crypto.impl.crypto.models.CiphertextAAD;
import io.peacemakr.crypto.impl.persister.InMemoryPersister;
import io.swagger.client.ApiClient;
import io.swagger.client.ApiException;
import io.swagger.client.api.ClientApi;
import io.swagger.client.api.CryptoConfigApi;
import io.swagger.client.api.KeyServiceApi;
import io.swagger.client.api.OrgApi;
import io.swagger.client.auth.Authentication;
import io.swagger.client.model.*;
import org.apache.log4j.Logger;

import javax.crypto.Cipher;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

public class ICryptoImpl implements ICrypto {

  private static final String JAVA_SDK_VERSION = "0.0.1";
  private static final String PERSISTER_PRIV_KEY = "Priv";
  private static final String PERSISTER_PUB_KEY = "Pub";
  private static final String PERSISTER_ASYM_TYPE = "AsymmetricKeyType";
  private static final String PERSISTER_ASYM_CREATED_DATE_EPOCH = "AsymmetricKeyCreated";
  private static final String PERSISTER_ASYM_BITLEN = "AsymmetricKeyCreated";
  private static final String PERSISTER_CLIENTID_KEY = "ClientId";
  private static final String PERSISTER_PREFERRED_KEYID = "PreferredKeyId";
  private static final String PERSISTER_APIKEY_KEY = "ApiKey";


  private static final String Chacha20Poly1305 = "Peacemakr.Symmetric.CHACHA20_POLY1305";
  private static final String Aes128gcm        = "Peacemakr.Symmetric.AES_128_GCM";
  private static final String Aes192gcm        = "Peacemakr.Symmetric.AES_192_GCM";
  private static final String Aes256gcm        = "Peacemakr.Symmetric.AES_256_GCM";
  private static final SymmetricCipher DEFAULT_SYMMETRIC_CIPHER = SymmetricCipher.CHACHA20_POLY1305;

  private static final String Sha224 = "Peacemakr.Digest.SHA_224";
  private static final String Sha256 = "Peacemakr.Digest.SHA_256";
  private static final String Sha384 = "Peacemakr.Digest.SHA_384";
  private static final String Sha512 = "Peacemakr.Digest.SHA_512";
  private static final MessageDigest DEFAULT_MESSAGE_DIGEST = MessageDigest.SHA_256;

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

    // 30 second timeouts.
    apiClient.setConnectTimeout(30*1000);
    apiClient.setReadTimeout(30*1000);
    apiClient.setWriteTimeout(30*1000);

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

    PublicKey publicKey = genNewAsymmetricKeypair(this.persister);

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
    this.persister.save(PERSISTER_PREFERRED_KEYID, this.client.getPublicKeys().get(0).getId());
  }

  private AsymmetricCipher getAsymmetricCipher(String asymmetricCipher) {
    AsymmetricCipher clientKeyType;
    switch (asymmetricCipher) {

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
    return clientKeyType;
  }

  private CiphertextAAD parseCiphertextAAD(String aad) {
    Gson gson = new Gson();
    return gson.fromJson(aad, CiphertextAAD.class);
  }

  private AsymmetricKey getOrDownloadPublicKey(String keyId) throws PeacemakrException {

    if (persister.exists(keyId)) {
      return AsymmetricKey.fromPubPem(DEFAULT_SYMMETRIC_CIPHER, persister.load(keyId));
    }

    KeyServiceApi keyServiceApi = new KeyServiceApi(getClient());
    PublicKey publicKey;
    try {
      publicKey = keyServiceApi.getPublicKey(keyId);
    } catch (ApiException e) {
      logger.error("Failed to get public key keyId " + keyId, e);
      throw new ServerException(e);
    }

    persister.save(keyId, publicKey.getKey());
    return AsymmetricKey.fromPubPem(DEFAULT_SYMMETRIC_CIPHER, publicKey.getKey());

  }

  private void decryptAndSave(List<EncryptedSymmetricKey> allKeys) throws PeacemakrException {
    loadedPrivatePreferredKey = AsymmetricKey.fromPrivPem(DEFAULT_SYMMETRIC_CIPHER, persister.load(PERSISTER_PRIV_KEY));
    for (EncryptedSymmetricKey key : allKeys) {

      if (key == null) {
        continue;
      }

      String rawCiphertextStr = key.getPackagedCiphertext();
      if (rawCiphertextStr == null) {
        logger.error("Failed to get raw ciphertext str from EncryptedSymmetricKey " + key);
        continue;
      }

      byte[] extractedAad = Crypto.getCiphertextAAD(rawCiphertextStr.getBytes(StandardCharsets.UTF_8));
      if (extractedAad == null) {
        throw new CoreCryptoException("Failed to extract aad from the ciphertext: " + rawCiphertextStr);
      }
      String aadStr = new String(extractedAad);
      CiphertextAAD aad = parseCiphertextAAD(aadStr);

      AsymmetricKey verificationKey = getOrDownloadPublicKey(aad.senderKeyID);

      // TODO: handle ECDH keys here too.

      byte[] plaintext = Crypto.decryptAsymmetric(loadedPrivatePreferredKey, verificationKey, rawCiphertextStr.getBytes(StandardCharsets.UTF_8));

      int keyLen = key.getKeyLength();
      int offset = 0;
      for (String keyId : key.getKeyIds()) {
        byte[] currentKeyPlaintext = Arrays.copyOfRange(plaintext, offset, offset + keyLen);
        persister.save(keyId, Base64.getEncoder().encodeToString(currentKeyPlaintext));
        offset = offset + keyLen;
        logger.debug("Decrypted and saved keyId " + keyId);
      }

    }
  }

  private void updateLocalCryptoConfig(CryptoConfig newConfig) throws PeacemakrException {

    String curAsymmetricKeyType = persister.load(PERSISTER_ASYM_TYPE);
    if (!newConfig.getClientKeyType().equals(curAsymmetricKeyType)) {
      logger.info("Detected a new asymmetric client key type of " + newConfig.getClientKeyType() + " instead of " + curAsymmetricKeyType);
      this.cryptoConfig = newConfig;
      genAndRegisterNewPreferredClientKey();
      return;
    }

    String curAsymmetricKeyCreationTime = persister.load(PERSISTER_ASYM_CREATED_DATE_EPOCH);
    long asymmetricKeyCreationTime = Long.parseLong(curAsymmetricKeyCreationTime);
    if (newConfig.getClientKeyTTL() + asymmetricKeyCreationTime > (System.currentTimeMillis() / 1000)) {
      logger.info("Detected an expired local asymmetric client key");
      this.cryptoConfig = newConfig;
      genAndRegisterNewPreferredClientKey();
      return;
    }

    String curAsymmetricKeyBitLenS =  persister.load(PERSISTER_ASYM_BITLEN);
    int asymmetricKeyBitLen = Integer.parseInt(curAsymmetricKeyBitLenS);
    if (asymmetricKeyBitLen != newConfig.getClientKeyBitlength()) {
      logger.info("Detected an updated local asymmetric client key bitlength requirement of " + newConfig.getClientKeyBitlength() + " insteads of the previous " + curAsymmetricKeyBitLenS);
      this.cryptoConfig = newConfig;
      genAndRegisterNewPreferredClientKey();
      return;
    }

    // Otherwise, it's a passive update, just update it.
    this.cryptoConfig = newConfig;
  }

  private void saveNewAsymmetricKeyPair(Persister from, Persister to) {
    to.save(PERSISTER_PRIV_KEY, from.load(PERSISTER_PRIV_KEY));
    to.save(PERSISTER_PUB_KEY, from.load(PERSISTER_PUB_KEY));
    to.save(PERSISTER_ASYM_TYPE, from.load(PERSISTER_ASYM_TYPE));
    to.save(PERSISTER_ASYM_CREATED_DATE_EPOCH, from.load(PERSISTER_ASYM_CREATED_DATE_EPOCH));
    to.save(PERSISTER_ASYM_BITLEN, from.load(PERSISTER_ASYM_BITLEN));
  }

  private PublicKey genNewAsymmetricKeypair(Persister p) throws UnrecoverableClockSkewDetectedException {
    AsymmetricCipher clientKeyType  = getAsymmetricCipher(this.cryptoConfig.getClientKeyType());
    SymmetricCipher thisIsNeverUsed = SymmetricCipher.CHACHA20_POLY1305;

    AsymmetricKey clientKey = AsymmetricKey.fromPRNG(clientKeyType, thisIsNeverUsed);
    String publicKeyPEM = clientKey.getPubPemStr();
    String privateKeyPEM = clientKey.getPrivPemStr();

    p.save(PERSISTER_PRIV_KEY, privateKeyPEM);
    p.save(PERSISTER_PUB_KEY, publicKeyPEM);
    p.save(PERSISTER_ASYM_TYPE, this.cryptoConfig.getClientKeyType());
    p.save(PERSISTER_ASYM_CREATED_DATE_EPOCH, "" + (System.currentTimeMillis() / 1000));
    p.save(PERSISTER_ASYM_BITLEN, "" + this.cryptoConfig.getClientKeyBitlength());

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

    return publicKey;
  }

  private synchronized void genAndRegisterNewPreferredClientKey() throws PeacemakrException {
    logger.info("Generating a new preferred client key");
    InMemoryPersister tempInMemoryPerister=  new InMemoryPersister();
    PublicKey publicKey = genNewAsymmetricKeypair(tempInMemoryPerister);

    logger.info("Registering the new public key");
    ClientApi clientApi = new ClientApi(getClient());
    try {
      publicKey = clientApi.addClientPublicKey(this.client.getId(), publicKey);
    } catch (ApiException e) {
      logger.error("Failed to register a new public key", e);
      throw new ServerException(e);
    }
    logger.info("Successfully registered new public key as client prefered key");
    saveNewAsymmetricKeyPair(tempInMemoryPerister, this.persister);
    this.persister.save(PERSISTER_PREFERRED_KEYID, publicKey.getId());
    logger.info("Successfully saved new public key as client preferred key");

  }

  @Override
  public void sync() throws PeacemakrException {
    verifyIsBootstrappedAndRegistered();

    CryptoConfigApi cryptoConfigApi = new CryptoConfigApi(getClient());
    try {
      CryptoConfig newConfig = cryptoConfigApi.getCryptoConfig(this.cryptoConfig.getId());
      if (newConfig.equals(this.cryptoConfig)) {
        // Do nothing.
        logger.info("No changes to crypto configs.");
      } else {
        updateLocalCryptoConfig(newConfig);
      }
    } catch ( ApiException e) {
      logger.error("failed to pull new crypto config from server during sync due to", e);
      throw new ServerException(e);
    }

    downloadAndSaveAllKeys(null);

  }

  private void downloadAndSaveAllKeys(List<String> requiredKeyIds) throws PeacemakrException {
    KeyServiceApi keyServiceApi = new KeyServiceApi(getClient());
    try {
      // The response from the server will populate our clientId field.
      List<EncryptedSymmetricKey> allKeys = keyServiceApi.getAllEncryptedKeys(this.client.getPreferredPublicKeyId(), requiredKeyIds);
      logger.info("Downloaded " + allKeys.size() + " encrypted symmetric keys.");
      decryptAndSave(allKeys);
    } catch (ApiException e) {
      logger.error("Failed to download all keys", e);
      throw new ServerException(e);
    }
  }

  @Override
  public String encrypt(String plainText) throws PeacemakrException {
    verifyIsBootstrappedAndRegistered();
    byte[] encrypted = encrypt(plainText.getBytes( StandardCharsets.UTF_8));
    return new String(encrypted);
  }

  private boolean domainIsValidForEncryption(SymmetricKeyUseDomain domain) {
    long nowInSeconds = (System.currentTimeMillis() / 1000);
    return (long) domain.getCreationTime() + (long)domain.getSymmetricKeyEncryptionUseTTL() > nowInSeconds &&
            (long) domain.getCreationTime() + (long)domain.getSymmetricKeyInceptionTTL() <= nowInSeconds;
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

      logger.debug("Looking for the domain " + useDomain + " in a total of " + useDomains.size() + " use domains.");

      for (SymmetricKeyUseDomain domain : useDomains) {
        if (!domain.getName().equals(useDomain)) {
          continue;
        }
        if (!domainIsValidForEncryption(domain)) {
          continue;
        }
        if (domain.getEncryptionKeyIds().isEmpty()) {
          continue;
        }
        validDomainWithThisName.add(domain);
      }

      if (validDomainWithThisName.isEmpty()) {
        throw new NoValidUseDomainsForEncryptionOperation("No valid use domain for encryption found, with the name " + useDomain);
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
      return Base64.getDecoder().decode(key);
    }

    List<String> requiredKeys = new ArrayList<>();
    requiredKeys.add(keyId);
    downloadAndSaveAllKeys(requiredKeys);

    if (!this.persister.exists(keyId)) {
      throw new FailedToDownloadKey("KeyId: " + keyId);
    }

    String key = this.persister.load(keyId);
    return Base64.getDecoder().decode(key);
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

  private MessageDigest getDigestAlg(String digestAlgorithm) {

    switch (digestAlgorithm) {
      case Sha224:
        return MessageDigest.SHA_224;
      case Sha256:
        return MessageDigest.SHA_256;
      case Sha384:
        return MessageDigest.SHA_384;
      case Sha512:
        return MessageDigest.SHA_512;
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
    this.loadedPrivatePreferredKey = AsymmetricKey.fromPrivPem(SymmetricCipher.CHACHA20_POLY1305, privatePem);

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
    MessageDigest digest = getDigestAlg(useDomainForEncrytpion.getDigestAlgorithm());

    CiphertextAAD aad = new CiphertextAAD();
    aad.cryptoKeyID = encryptionKeyIdforEncryption;
    // Key ID for verification
    aad.senderKeyID = persister.load(PERSISTER_PREFERRED_KEYID);
    Gson gson = new Gson();

    return Crypto.encryptSymmetric(key, symmetricCipher, signingKey, plainText, gson.toJson(aad).getBytes(StandardCharsets.UTF_8), digest);
  }

  @Override
  public String decrypt(String cipherText) throws PeacemakrException {
    verifyIsBootstrappedAndRegistered();
    return new String(decrypt(cipherText.getBytes(StandardCharsets.UTF_8)));
  }

  @Override
  public byte[] decrypt(byte[] cipherText) throws PeacemakrException {
    verifyIsBootstrappedAndRegistered();
    CiphertextAAD aad = parseCiphertextAAD(new String(Crypto.getCiphertextAAD(cipherText), StandardCharsets.UTF_8));

    byte[] key = null;
    try {
      key = getKey(aad.cryptoKeyID);
    } catch (UnsupportedEncodingException e) {
      logger.error("Failed to get key due to ", e);
      throw new PersistenceLayerCorruptionDetected(e);
    }

    AsymmetricKey verificationKey = getOrDownloadPublicKey(aad.senderKeyID);

    return Crypto.decryptSymmetric(key, verificationKey, cipherText);
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
