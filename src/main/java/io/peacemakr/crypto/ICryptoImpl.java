package io.peacemakr.crypto;

public class ICryptoImpl implements ICrypto {
  @Override
  public void register() {

  }

  @Override
  public void preLoad() {

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
  public String sign(String plaintext) {
    return null;
  }

  @Override
  public byte[] sign(byte[] plaintext) {
    return new byte[0];
  }

  @Override
  public boolean verify(byte[] plaintext, byte[] signature) {
    return false;
  }

  @Override
  public boolean verify(String plaintext, String signature) {
    return false;
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
