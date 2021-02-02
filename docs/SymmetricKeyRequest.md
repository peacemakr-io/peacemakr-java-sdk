
# SymmetricKeyRequest

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**id** | **String** | Id of the symmetric key request. | 
**deriveSymmetricKeyIds** | **List&lt;String&gt;** | These are the keyId&#39;s of for the symmetric keys to actually derive. | 
**deliveryPublicKeyIds** | **List&lt;String&gt;** | These are the keyId&#39;s to deliver all of the derived symmetric keys. | 
**keyDerivationServiceId** | **String** | The serviceId that must generate these keys. | 
**creationTime** | **Integer** | Epoch time of the symmetric key requestion request time. | 
**symmetricKeyLength** | **Integer** | Length in bytes of the derived symmetric keys. | 
**packagedCiphertextVersion** | **Integer** | After deriving symmetric keys, this determines the ciphertext packaging scheme required for encrypted key delivery. | 
**mustSignDeliveredSymmetricKeys** | **Boolean** | If true the key deriver must sign delivered symmetric keys ciphertext blobs | 



