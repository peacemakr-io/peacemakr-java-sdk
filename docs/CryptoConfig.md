
# CryptoConfig

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**id** | **String** |  | 
**symmetricKeyUseDomains** | [**List&lt;SymmetricKeyUseDomain&gt;**](SymmetricKeyUseDomain.md) | every application layer encryption must select a key to use from one specific active semmetric key encryption domain. this is an array of encryption domains id&#39;s that are currently available for encryption | 
**symmetricKeyUseDomainSelectorScheme** | **String** | to guide SDK&#39;s on how to select an encryption domain, a selectorScheme helps an SDK map a encryption request to a set of keys and encryption algoritm | 
**ownerOrgId** | **String** | the org id of the organization that owns these symmetric keys | 
**clientKeyType** | **String** | the type of key that should be associated with clients, for example, rsa | 
**clientKeyBitlength** | **Integer** | the bit length of all new client keys, for example, 2048 | 
**clientKeyTTL** | **Integer** | the TTL on the client&#39;s local asymetric key | 



