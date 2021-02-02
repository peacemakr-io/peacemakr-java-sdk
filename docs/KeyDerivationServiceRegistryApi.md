# KeyDerivationServiceRegistryApi

All URIs are relative to *http://api.peacemakr.io/api/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**addKeyDerivationServiceInstance**](KeyDerivationServiceRegistryApi.md#addKeyDerivationServiceInstance) | **POST** /crypto/deriver/instance | Register a new KeyDerivationServiceInstance
[**deleteKeyDerivationServiceInstance**](KeyDerivationServiceRegistryApi.md#deleteKeyDerivationServiceInstance) | **DELETE** /crypto/deriver/instance/{keyDerivationInstanceId} | Activate or deactivate an existing KeyDerivationServiceInstance
[**getAllOrgKeyDerivationServiceInstances**](KeyDerivationServiceRegistryApi.md#getAllOrgKeyDerivationServiceInstances) | **GET** /crypto/deriver/all-org-instances | Get the all key derivers registerd to org
[**getAllSharedKeyDerivationServiceInstances**](KeyDerivationServiceRegistryApi.md#getAllSharedKeyDerivationServiceInstances) | **GET** /crypto/deriver/all-shared-instances | Get the all key derivers that the org has access to - including shared cloud instances
[**getKeyDerivationServiceInstance**](KeyDerivationServiceRegistryApi.md#getKeyDerivationServiceInstance) | **GET** /crypto/deriver/instance/{keyDerivationInstanceId} | Get the keyderiver details by id
[**heartbeatKeyDerivationServiceInstance**](KeyDerivationServiceRegistryApi.md#heartbeatKeyDerivationServiceInstance) | **GET** /crypto/deriver/instance/{keyDerivationInstanceId}/heartbeat | Heatbeat from the given key derivation service instance


<a name="addKeyDerivationServiceInstance"></a>
# **addKeyDerivationServiceInstance**
> KeyDerivationInstance addKeyDerivationServiceInstance(keyDerivationInstance)

Register a new KeyDerivationServiceInstance

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.KeyDerivationServiceRegistryApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

KeyDerivationServiceRegistryApi apiInstance = new KeyDerivationServiceRegistryApi();
KeyDerivationInstance keyDerivationInstance = new KeyDerivationInstance(); // KeyDerivationInstance | 
try {
    KeyDerivationInstance result = apiInstance.addKeyDerivationServiceInstance(keyDerivationInstance);
    System.out.println(result);
} catch (ApiException e) {
    System.err.println("Exception when calling KeyDerivationServiceRegistryApi#addKeyDerivationServiceInstance");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **keyDerivationInstance** | [**KeyDerivationInstance**](KeyDerivationInstance.md)|  | [optional]

### Return type

[**KeyDerivationInstance**](KeyDerivationInstance.md)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="deleteKeyDerivationServiceInstance"></a>
# **deleteKeyDerivationServiceInstance**
> deleteKeyDerivationServiceInstance(keyDerivationInstanceId, active)

Activate or deactivate an existing KeyDerivationServiceInstance

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.KeyDerivationServiceRegistryApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

KeyDerivationServiceRegistryApi apiInstance = new KeyDerivationServiceRegistryApi();
String keyDerivationInstanceId = "keyDerivationInstanceId_example"; // String | 
String active = "active_example"; // String | 
try {
    apiInstance.deleteKeyDerivationServiceInstance(keyDerivationInstanceId, active);
} catch (ApiException e) {
    System.err.println("Exception when calling KeyDerivationServiceRegistryApi#deleteKeyDerivationServiceInstance");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **keyDerivationInstanceId** | **String**|  |
 **active** | **String**|  |

### Return type

null (empty response body)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="getAllOrgKeyDerivationServiceInstances"></a>
# **getAllOrgKeyDerivationServiceInstances**
> List&lt;KeyDerivationInstance&gt; getAllOrgKeyDerivationServiceInstances()

Get the all key derivers registerd to org

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.KeyDerivationServiceRegistryApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

KeyDerivationServiceRegistryApi apiInstance = new KeyDerivationServiceRegistryApi();
try {
    List<KeyDerivationInstance> result = apiInstance.getAllOrgKeyDerivationServiceInstances();
    System.out.println(result);
} catch (ApiException e) {
    System.err.println("Exception when calling KeyDerivationServiceRegistryApi#getAllOrgKeyDerivationServiceInstances");
    e.printStackTrace();
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**List&lt;KeyDerivationInstance&gt;**](KeyDerivationInstance.md)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="getAllSharedKeyDerivationServiceInstances"></a>
# **getAllSharedKeyDerivationServiceInstances**
> List&lt;KeyDerivationInstance&gt; getAllSharedKeyDerivationServiceInstances()

Get the all key derivers that the org has access to - including shared cloud instances

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.KeyDerivationServiceRegistryApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

KeyDerivationServiceRegistryApi apiInstance = new KeyDerivationServiceRegistryApi();
try {
    List<KeyDerivationInstance> result = apiInstance.getAllSharedKeyDerivationServiceInstances();
    System.out.println(result);
} catch (ApiException e) {
    System.err.println("Exception when calling KeyDerivationServiceRegistryApi#getAllSharedKeyDerivationServiceInstances");
    e.printStackTrace();
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**List&lt;KeyDerivationInstance&gt;**](KeyDerivationInstance.md)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="getKeyDerivationServiceInstance"></a>
# **getKeyDerivationServiceInstance**
> KeyDerivationInstance getKeyDerivationServiceInstance(keyDerivationInstanceId)

Get the keyderiver details by id

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.KeyDerivationServiceRegistryApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

KeyDerivationServiceRegistryApi apiInstance = new KeyDerivationServiceRegistryApi();
String keyDerivationInstanceId = "keyDerivationInstanceId_example"; // String | 
try {
    KeyDerivationInstance result = apiInstance.getKeyDerivationServiceInstance(keyDerivationInstanceId);
    System.out.println(result);
} catch (ApiException e) {
    System.err.println("Exception when calling KeyDerivationServiceRegistryApi#getKeyDerivationServiceInstance");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **keyDerivationInstanceId** | **String**|  |

### Return type

[**KeyDerivationInstance**](KeyDerivationInstance.md)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="heartbeatKeyDerivationServiceInstance"></a>
# **heartbeatKeyDerivationServiceInstance**
> HeatbeatResponse heartbeatKeyDerivationServiceInstance(keyDerivationInstanceId)

Heatbeat from the given key derivation service instance

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.KeyDerivationServiceRegistryApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

KeyDerivationServiceRegistryApi apiInstance = new KeyDerivationServiceRegistryApi();
String keyDerivationInstanceId = "keyDerivationInstanceId_example"; // String | 
try {
    HeatbeatResponse result = apiInstance.heartbeatKeyDerivationServiceInstance(keyDerivationInstanceId);
    System.out.println(result);
} catch (ApiException e) {
    System.err.println("Exception when calling KeyDerivationServiceRegistryApi#heartbeatKeyDerivationServiceInstance");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **keyDerivationInstanceId** | **String**|  |

### Return type

[**HeatbeatResponse**](HeatbeatResponse.md)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

