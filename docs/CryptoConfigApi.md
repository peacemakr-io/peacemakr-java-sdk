# CryptoConfigApi

All URIs are relative to *http://api.peacemakr.io/api/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**addExistingUseDomain**](CryptoConfigApi.md#addExistingUseDomain) | **POST** /crypto/config/{cryptoConfigId}/useDomain/{useDomainId} | Add an existing use domain to another crypto config.
[**addUseDomain**](CryptoConfigApi.md#addUseDomain) | **POST** /crypto/config/{cryptoConfigId}/useDomain | Add a new active use domain and attached it to the crypto config.
[**getCryptoConfig**](CryptoConfigApi.md#getCryptoConfig) | **GET** /crypto/config/{cryptoConfigId} | Get the crypto configurations
[**rapidRotationUseDomain**](CryptoConfigApi.md#rapidRotationUseDomain) | **POST** /crypto/useDomain/{useDomainId}/rapidRotation | Rapid expiration of existing use doamin and immediately replacment with an identical use domain containing fresh keys
[**removeUseDomain**](CryptoConfigApi.md#removeUseDomain) | **DELETE** /crypto/useDomain/{useDomainId} | Delete a fully expired use domain
[**updateCryptoConfig**](CryptoConfigApi.md#updateCryptoConfig) | **POST** /crypto/config/{cryptoConfigId} | Update the crypto configuration, ONLY the clientKeyType clientKeyBitlength, and clientKeyTTL fields.
[**updateCryptoConfigFallbackToCloud**](CryptoConfigApi.md#updateCryptoConfigFallbackToCloud) | **PUT** /crypto/useDomain/{useDomainId}/enableKDSFallbackToCloud | Update an existing crypto config&#39;s asymmetricKeyTTL
[**updateCryptoConfigSelectorScheme**](CryptoConfigApi.md#updateCryptoConfigSelectorScheme) | **PUT** /crypto/config/{cryptoConfigId}/domainSelectorScheme | Update an existing crypto config&#39;s domainSelectorScheme
[**updateExpireUseDomain**](CryptoConfigApi.md#updateExpireUseDomain) | **POST** /crypto/useDomain/{useDomainId}/updateExpire | Chnage expiration of a use domain


<a name="addExistingUseDomain"></a>
# **addExistingUseDomain**
> addExistingUseDomain(cryptoConfigId, useDomainId)

Add an existing use domain to another crypto config.

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.CryptoConfigApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

CryptoConfigApi apiInstance = new CryptoConfigApi();
String cryptoConfigId = "cryptoConfigId_example"; // String | 
String useDomainId = "useDomainId_example"; // String | 
try {
    apiInstance.addExistingUseDomain(cryptoConfigId, useDomainId);
} catch (ApiException e) {
    System.err.println("Exception when calling CryptoConfigApi#addExistingUseDomain");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **cryptoConfigId** | **String**|  |
 **useDomainId** | **String**|  |

### Return type

null (empty response body)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="addUseDomain"></a>
# **addUseDomain**
> SymmetricKeyUseDomain addUseDomain(cryptoConfigId, newUseDomain)

Add a new active use domain and attached it to the crypto config.

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.CryptoConfigApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

CryptoConfigApi apiInstance = new CryptoConfigApi();
String cryptoConfigId = "cryptoConfigId_example"; // String | 
SymmetricKeyUseDomain newUseDomain = new SymmetricKeyUseDomain(); // SymmetricKeyUseDomain | 
try {
    SymmetricKeyUseDomain result = apiInstance.addUseDomain(cryptoConfigId, newUseDomain);
    System.out.println(result);
} catch (ApiException e) {
    System.err.println("Exception when calling CryptoConfigApi#addUseDomain");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **cryptoConfigId** | **String**|  |
 **newUseDomain** | [**SymmetricKeyUseDomain**](SymmetricKeyUseDomain.md)|  |

### Return type

[**SymmetricKeyUseDomain**](SymmetricKeyUseDomain.md)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="getCryptoConfig"></a>
# **getCryptoConfig**
> CryptoConfig getCryptoConfig(cryptoConfigId)

Get the crypto configurations

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.CryptoConfigApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

CryptoConfigApi apiInstance = new CryptoConfigApi();
String cryptoConfigId = "cryptoConfigId_example"; // String | 
try {
    CryptoConfig result = apiInstance.getCryptoConfig(cryptoConfigId);
    System.out.println(result);
} catch (ApiException e) {
    System.err.println("Exception when calling CryptoConfigApi#getCryptoConfig");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **cryptoConfigId** | **String**|  |

### Return type

[**CryptoConfig**](CryptoConfig.md)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="rapidRotationUseDomain"></a>
# **rapidRotationUseDomain**
> rapidRotationUseDomain(useDomainId, optionalNextKeyDerivationServiceId)

Rapid expiration of existing use doamin and immediately replacment with an identical use domain containing fresh keys

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.CryptoConfigApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

CryptoConfigApi apiInstance = new CryptoConfigApi();
String useDomainId = "useDomainId_example"; // String | 
String optionalNextKeyDerivationServiceId = "optionalNextKeyDerivationServiceId_example"; // String | 
try {
    apiInstance.rapidRotationUseDomain(useDomainId, optionalNextKeyDerivationServiceId);
} catch (ApiException e) {
    System.err.println("Exception when calling CryptoConfigApi#rapidRotationUseDomain");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **useDomainId** | **String**|  |
 **optionalNextKeyDerivationServiceId** | **String**|  | [optional]

### Return type

null (empty response body)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="removeUseDomain"></a>
# **removeUseDomain**
> removeUseDomain(useDomainId)

Delete a fully expired use domain

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.CryptoConfigApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

CryptoConfigApi apiInstance = new CryptoConfigApi();
String useDomainId = "useDomainId_example"; // String | 
try {
    apiInstance.removeUseDomain(useDomainId);
} catch (ApiException e) {
    System.err.println("Exception when calling CryptoConfigApi#removeUseDomain");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **useDomainId** | **String**|  |

### Return type

null (empty response body)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="updateCryptoConfig"></a>
# **updateCryptoConfig**
> CryptoConfig updateCryptoConfig(cryptoConfigId, updatedCryptoConfig)

Update the crypto configuration, ONLY the clientKeyType clientKeyBitlength, and clientKeyTTL fields.

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.CryptoConfigApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

CryptoConfigApi apiInstance = new CryptoConfigApi();
String cryptoConfigId = "cryptoConfigId_example"; // String | 
CryptoConfig updatedCryptoConfig = new CryptoConfig(); // CryptoConfig | 
try {
    CryptoConfig result = apiInstance.updateCryptoConfig(cryptoConfigId, updatedCryptoConfig);
    System.out.println(result);
} catch (ApiException e) {
    System.err.println("Exception when calling CryptoConfigApi#updateCryptoConfig");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **cryptoConfigId** | **String**|  |
 **updatedCryptoConfig** | [**CryptoConfig**](CryptoConfig.md)|  |

### Return type

[**CryptoConfig**](CryptoConfig.md)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="updateCryptoConfigFallbackToCloud"></a>
# **updateCryptoConfigFallbackToCloud**
> updateCryptoConfigFallbackToCloud(useDomainId, fallbackToCloud)

Update an existing crypto config&#39;s asymmetricKeyTTL

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.CryptoConfigApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

CryptoConfigApi apiInstance = new CryptoConfigApi();
String useDomainId = "useDomainId_example"; // String | 
Boolean fallbackToCloud = true; // Boolean | 
try {
    apiInstance.updateCryptoConfigFallbackToCloud(useDomainId, fallbackToCloud);
} catch (ApiException e) {
    System.err.println("Exception when calling CryptoConfigApi#updateCryptoConfigFallbackToCloud");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **useDomainId** | **String**|  |
 **fallbackToCloud** | **Boolean**|  |

### Return type

null (empty response body)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="updateCryptoConfigSelectorScheme"></a>
# **updateCryptoConfigSelectorScheme**
> updateCryptoConfigSelectorScheme(cryptoConfigId, newSelectorScheme)

Update an existing crypto config&#39;s domainSelectorScheme

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.CryptoConfigApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

CryptoConfigApi apiInstance = new CryptoConfigApi();
String cryptoConfigId = "cryptoConfigId_example"; // String | 
String newSelectorScheme = "newSelectorScheme_example"; // String | 
try {
    apiInstance.updateCryptoConfigSelectorScheme(cryptoConfigId, newSelectorScheme);
} catch (ApiException e) {
    System.err.println("Exception when calling CryptoConfigApi#updateCryptoConfigSelectorScheme");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **cryptoConfigId** | **String**|  |
 **newSelectorScheme** | **String**|  |

### Return type

null (empty response body)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="updateExpireUseDomain"></a>
# **updateExpireUseDomain**
> updateExpireUseDomain(useDomainId, inceptionTTL, encryptionTTL, decryptionTTL, retentionTTL)

Chnage expiration of a use domain

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.CryptoConfigApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

CryptoConfigApi apiInstance = new CryptoConfigApi();
String useDomainId = "useDomainId_example"; // String | 
Integer inceptionTTL = 56; // Integer | 
Integer encryptionTTL = 56; // Integer | 
Integer decryptionTTL = 56; // Integer | 
Integer retentionTTL = 56; // Integer | 
try {
    apiInstance.updateExpireUseDomain(useDomainId, inceptionTTL, encryptionTTL, decryptionTTL, retentionTTL);
} catch (ApiException e) {
    System.err.println("Exception when calling CryptoConfigApi#updateExpireUseDomain");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **useDomainId** | **String**|  |
 **inceptionTTL** | **Integer**|  |
 **encryptionTTL** | **Integer**|  |
 **decryptionTTL** | **Integer**|  |
 **retentionTTL** | **Integer**|  |

### Return type

null (empty response body)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

