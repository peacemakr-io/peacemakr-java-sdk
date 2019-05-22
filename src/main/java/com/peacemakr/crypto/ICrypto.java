package com.peacemakr.crypto;

/**
 * Created by interstellarPotato on 05/15/2019.
 */
public interface ICrypto {
    /**
     * Registers to PeaceMakr as a client. The persister is used to detect prior registrations on this client, so safe
     * to call multiple times. Once a successful invocation of Register is executed once, subsequent calls become a
     * noop. One successful call is required before any cryptographic use of this SDK.
     *
     * Registration may fail with invalid apiKey, missing network connectivity, or an invalid persister. On failure,
     * take corrections action and invoke again.
     */
    void register();

    /**
     * Pre-Load all available keys for this client. This invocation will help performance of subsequent encryption
     * and decryption calls.
     *
     * Pre-Loading may fail, if registration was not invoked, if there's network connectivity issues, or
     * unexpected authorization issues.
     */
    void preLoad();

    /**
     * Encrypt the plaintext.
     *
     * @param plainText Plaintext to encrypt.
     * @return Base64 encoded ciphertext blob on success, else returns an error.
     */
    String encryptStr(String plainText);

    /**
     * Encrypt the plaintext.
     *
     * @param plainText Plaintext to encrypt.
     * @return Opaquely packaged ciphertext.
     */
    byte[] encrypt(byte[] plainText);

    /**
     * Encrypt the plaintext, but restrict which keys may be used to a Use Domain of this specific name. Names of Use
     * Domains are not unique, and this non-unique property of your Organization's Use Domains allows for graceful
     * rotation of encryption keys off of old (retiring, stale, or compromised) Use Domains, simply by creating a new
     * Use Domain with the same name. The transitional purity, both Use Domains may be selected for encryption use by
     * clients restricted to one particular name. Then, retiring of one of the two Use Domains is possible without
     * disrupting your deployed application.
     *
     * @param plainText Plaintext to encrypt.
     * @param useDomainName Non-unique User Domain of your organization's.
     * @return Base64 encoded ciphertext blob on success, else returns an error.
     */
    String encryptStrInDomain(String plainText, String useDomainName);

    /**
     * Encrypt the plaintext, but restrict which keys may be used to a Use Domain of this specific name.
     *
     * @param plainText Plaintext to encrypt.
     * @param useDomainName Non-unique User Domain of your organization's.
     */
    byte[] encryptInDomain(byte[] plainText, String useDomainName);

    /**
     * Signs the original plaintext. Provide non-repudiation for content set by a client.
     * @param plaintext Plaintext to sign.
     * @return Signature of the plaintext. The signature is verified as having come from the client of origin.
     */
    String sign(String plaintext);

    /**
     * Signs the original plaintext. Provide non-repudiation for content set by a client.
     * @param plaintext Plaintext to sign.
     * @return Signature of the plaintext. The signature is verified as having come from the client of origin.
     */
    byte[] sign(byte[] plaintext);

    /**
     * Verifies the signature of the plaintext.
     * @param plaintext Plaintext which was signed.
     * @param signature Signature to verify.
     * @return Returns true when the signature was successfully verified.
     */
    boolean verify(byte[] plaintext, byte[] signature);

    /**
     * Verifies the signature of the plaintext.
     * @param plaintext Plaintext which was signed.
     * @param signature Signature to verify.
     * @return Returns true when the signature was successfully verified.
     */
    boolean verify(String plaintext, String signature);

    /**
     * Decrypt the opaquely packaged ciphertext and return the original plain text.
     * @param cipherText CipherText to decrypt.
     */
    String decryptStr(String cipherText);

    /**
     * Decrypt the opaquely packaged ciphertext and return the original plain text.
     * @param cipherText CipherText to decrypt.
     */
    byte[] decrypt(byte[] cipherText);

    /**
     * For visibility or debugging purposes, identify which client and configuration this client is running.
     * Also forwards debug info to peacemakr if phonehome enabled.
     */
    public void getDebugInfo();
}