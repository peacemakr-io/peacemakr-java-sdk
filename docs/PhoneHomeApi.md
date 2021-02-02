# PhoneHomeApi

All URIs are relative to *http://api.peacemakr.io/api/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**logPost**](PhoneHomeApi.md#logPost) | **POST** /log | Used to report back to server a logged event


<a name="logPost"></a>
# **logPost**
> logPost(log)

Used to report back to server a logged event

Returns 200 ok if successfully persisted

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.PhoneHomeApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

PhoneHomeApi apiInstance = new PhoneHomeApi();
Log log = new Log(); // Log | 
try {
    apiInstance.logPost(log);
} catch (ApiException e) {
    System.err.println("Exception when calling PhoneHomeApi#logPost");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **log** | [**Log**](Log.md)|  |

### Return type

null (empty response body)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: Not defined

