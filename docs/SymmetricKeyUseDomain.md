
# SymmetricKeyUseDomain

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**id** | **String** |  | 
**ownerOrgId** | **String** | the org id of the organization that owns these symmetric keys | 
**name** | **String** |  |  [optional]
**creationTime** | **Integer** |  | 
**symmetricKeyInceptionTTL** | **Integer** | number of seconds since key creation that the key will be available for encryption | 
**symmetricKeyEncryptionUseTTL** | **Integer** | number of seconds since key creation that the key will be available for encryption | 
**symmetricKeyEncryptionAllowed** | **Boolean** | whether this use domain is available for encryption; if false, these keys should not be used for encrypting new messages |  [optional]
**symmetricKeyDecryptionUseTTL** | **Integer** | number of seconds since key creation that the key will be available for decryption | 
**symmetricKeyDecryptionAllowed** | **Boolean** | whether this use domain is available for decryption; if false, these keys should not be used for decrypting messages |  [optional]
**symmetricKeyRetentionUseTTL** | **Integer** | number of seconds since key creation that the key will be available for retention purposes | 
**symmetricKeyLength** | **Integer** | the number of bits of all symmetric keys in this use domain | 
**symmetricKeyEncryptionAlg** | **String** | the specific encryption alg to encrypt new plaintexts for application layer encryption operations | 
**encryptingPackagedCiphertextVersion** | **Integer** | after encrypting new plaintexts, package the ciphertext with this version of the packaged ciphertext | 
**symmetricKeyDerivationServiceId** | **String** | the symmetric key derivation serivce id that can derive and wrap these keys | 
**encryptionKeyIds** | **List&lt;String&gt;** | these are the semmetric key id&#39;s that belong to this use domain - these keys never belong to any other use domain | 
**endableKDSFallbackToCloud** | **Boolean** | if all registered kds service become unreachable, then incoming requests for new and existing keys may fallback to the cloud provided KDS | 
**requireSignedKeyDelivery** | **Boolean** | if required, all clients must receive these keys in a signed symmetric key delivery from the key deriver | 
**digestAlgorithm** | **String** | The digest algorithm to use for signing messages in this use domain |  [optional]



