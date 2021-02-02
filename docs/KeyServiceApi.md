# KeyServiceApi

All URIs are relative to *http://api.peacemakr.io/api/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**getAllEncryptedKeys**](KeyServiceApi.md#getAllEncryptedKeys) | **GET** /crypto/symmetric/{encryptingKeyId} | Get all encrypted symmetric keys that are encrypted with this encrypting keyId, optionally limiting the request to a set of symmetric key domains
[**getPublicKey**](KeyServiceApi.md#getPublicKey) | **GET** /crypto/asymmetric/{keyID} | Get the public key associated with the passed-in key ID
[**postNewEncryptedKeys**](KeyServiceApi.md#postNewEncryptedKeys) | **POST** /crypto/symmetric/{encryptingKeyId} | Add a new encrypted key. The encrypting key that protects the encrypted key is identified with encryptingKeyId. Request must come from a registered key manager.


<a name="getAllEncryptedKeys"></a>
# **getAllEncryptedKeys**
> List&lt;EncryptedSymmetricKey&gt; getAllEncryptedKeys(encryptingKeyId, symmetricKeyIds)

Get all encrypted symmetric keys that are encrypted with this encrypting keyId, optionally limiting the request to a set of symmetric key domains

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.KeyServiceApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

KeyServiceApi apiInstance = new KeyServiceApi();
String encryptingKeyId = "encryptingKeyId_example"; // String | 
List<String> symmetricKeyIds = Arrays.asList("symmetricKeyIds_example"); // List<String> | 
try {
    List<EncryptedSymmetricKey> result = apiInstance.getAllEncryptedKeys(encryptingKeyId, symmetricKeyIds);
    System.out.println(result);
} catch (ApiException e) {
    System.err.println("Exception when calling KeyServiceApi#getAllEncryptedKeys");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **encryptingKeyId** | **String**|  |
 **symmetricKeyIds** | [**List&lt;String&gt;**](String.md)|  | [optional]

### Return type

[**List&lt;EncryptedSymmetricKey&gt;**](EncryptedSymmetricKey.md)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="getPublicKey"></a>
# **getPublicKey**
> PublicKey getPublicKey(keyID)

Get the public key associated with the passed-in key ID

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.KeyServiceApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

KeyServiceApi apiInstance = new KeyServiceApi();
String keyID = "keyID_example"; // String | 
try {
    PublicKey result = apiInstance.getPublicKey(keyID);
    System.out.println(result);
} catch (ApiException e) {
    System.err.println("Exception when calling KeyServiceApi#getPublicKey");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **keyID** | **String**|  |

### Return type

[**PublicKey**](PublicKey.md)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="postNewEncryptedKeys"></a>
# **postNewEncryptedKeys**
> postNewEncryptedKeys(encryptingKeyId, encryptedSymmetricKey)

Add a new encrypted key. The encrypting key that protects the encrypted key is identified with encryptingKeyId. Request must come from a registered key manager.

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.KeyServiceApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

KeyServiceApi apiInstance = new KeyServiceApi();
String encryptingKeyId = "encryptingKeyId_example"; // String | 
List<EncryptedSymmetricKey> encryptedSymmetricKey = Arrays.asList(new EncryptedSymmetricKey()); // List<EncryptedSymmetricKey> | 
try {
    apiInstance.postNewEncryptedKeys(encryptingKeyId, encryptedSymmetricKey);
} catch (ApiException e) {
    System.err.println("Exception when calling KeyServiceApi#postNewEncryptedKeys");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **encryptingKeyId** | **String**|  |
 **encryptedSymmetricKey** | [**List&lt;EncryptedSymmetricKey&gt;**](EncryptedSymmetricKey.md)|  |

### Return type

null (empty response body)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

