package io.peacemakr.crypto;

import io.peacemakr.crypto.exception.PeacemakrException;

import java.io.UnsupportedEncodingException;

/**
 * Created by interstellarPotato on 05/15/2019.
 */
public interface ICrypto {
  /**
   * Registers to PeaceMakr as a client. The persister is used to detect prior registrations on this client, so safe
   * to call multiple times. Once a successful invocation of Register is executed once, subsequent calls become a
   * noop. One successful call is required before any cryptographic use of this SDK.
   * <p>
   * @throws PeacemakrException if an exception occurs during the registration. Registration may fail with invalid
   * apiKey, missing network connectivity, or an invalid persister. On failure, take corrections action and invoke again.
   */
  void register() throws PeacemakrException;

  /**
   * Sync all available keys for this client. This invocation will help performance of subsequent encryption
   * and decryption calls.
   * <p>
   * @throws PeacemakrException if an exception occurs during the sync. Sync may fail, if registration was not invoked,
   * if there's network connectivity issues, or unexpected authorization issues.
   */
  void sync() throws PeacemakrException;

  /**
   * Encrypt the plaintext, using a random available usedomain.
   * <p>
   * @param plainText Plaintext bytes to encrypt.
   * @return Opaquely packaged ciphertext.
   * @throws PeacemakrException On any error (network connectivity issues, authN issues, etc)
   */
  byte[] encrypt(byte[] plainText) throws PeacemakrException;

  /**
   * Encrypt the plaintext, but restrict which keys may be used to a Use Domain of this specific name. Names of Use
   * Domains are not unique, and this non-unique property of your Organization's Use Domains allows for graceful
   * rotation of encryption keys off of old (retiring, stale, or compromised) Use Domains, simply by creating a new
   * Use Domain with the same name. The transitional purity, both Use Domains may be selected for encryption use by
   * clients restricted to one particular name. Then, retiring of one of the two Use Domains is possible without
   * disrupting your deployed application.
   * <p>
   * @param plainText     Plaintext to encrypt.
   * @param useDomainName Non-unique User Domain of your organization's.
   * @return Opaquely packaged ciphertext.
   * @throws PeacemakrException if an exception occurs during the encryption.
   * @throws UnsupportedEncodingException if unsupported encoding has been used.
   */
  byte[] encryptInDomain(byte[] plainText, String useDomainName) throws PeacemakrException, UnsupportedEncodingException;

  /**
   * Decrypt the opaquely packaged ciphertext and return the original plain text.
   * <p>
   * @param cipherText CipherText to decrypt.
   * @return original plain text.
   * @throws PeacemakrException if an exception occurs during the decryption.
   */
  byte[] decrypt(byte[] cipherText) throws PeacemakrException;

  /**
   * For visibility or debugging purposes, returns a string whihc identifies which
   * client and configuration this client is running.
   * @return a debug info.
   */
  String getDebugInfo();
}