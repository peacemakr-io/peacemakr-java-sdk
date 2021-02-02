# ClientApi

All URIs are relative to *http://api.peacemakr.io/api/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**addClient**](ClientApi.md#addClient) | **POST** /client | Register a new client
[**addClientPublicKey**](ClientApi.md#addClientPublicKey) | **POST** /client/{clientId}/addPublicKey | Register a new public key for the client
[**deleteClient**](ClientApi.md#deleteClient) | **DELETE** /client/{clientId} | Remove an existing organization
[**getClient**](ClientApi.md#getClient) | **GET** /client/{clientId} | Get an existing client


<a name="addClient"></a>
# **addClient**
> Client addClient(client)

Register a new client

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.ClientApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

ClientApi apiInstance = new ClientApi();
Client client = new Client(); // Client | 
try {
    Client result = apiInstance.addClient(client);
    System.out.println(result);
} catch (ApiException e) {
    System.err.println("Exception when calling ClientApi#addClient");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **client** | [**Client**](Client.md)|  |

### Return type

[**Client**](Client.md)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="addClientPublicKey"></a>
# **addClientPublicKey**
> PublicKey addClientPublicKey(clientId, newPublicKey)

Register a new public key for the client

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.ClientApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

ClientApi apiInstance = new ClientApi();
String clientId = "clientId_example"; // String | 
PublicKey newPublicKey = new PublicKey(); // PublicKey | 
try {
    PublicKey result = apiInstance.addClientPublicKey(clientId, newPublicKey);
    System.out.println(result);
} catch (ApiException e) {
    System.err.println("Exception when calling ClientApi#addClientPublicKey");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **clientId** | **String**|  |
 **newPublicKey** | [**PublicKey**](PublicKey.md)|  |

### Return type

[**PublicKey**](PublicKey.md)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="deleteClient"></a>
# **deleteClient**
> Client deleteClient(clientId)

Remove an existing organization

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.ClientApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

ClientApi apiInstance = new ClientApi();
String clientId = "clientId_example"; // String | 
try {
    Client result = apiInstance.deleteClient(clientId);
    System.out.println(result);
} catch (ApiException e) {
    System.err.println("Exception when calling ClientApi#deleteClient");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **clientId** | **String**|  |

### Return type

[**Client**](Client.md)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="getClient"></a>
# **getClient**
> Client getClient(clientId)

Get an existing client

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.ClientApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

ClientApi apiInstance = new ClientApi();
String clientId = "clientId_example"; // String | 
try {
    Client result = apiInstance.getClient(clientId);
    System.out.println(result);
} catch (ApiException e) {
    System.err.println("Exception when calling ClientApi#getClient");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **clientId** | **String**|  |

### Return type

[**Client**](Client.md)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

