# ServerManagementApi

All URIs are relative to *http://api.peacemakr.io/api/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**healthGet**](ServerManagementApi.md#healthGet) | **GET** /health | See if the server is healthy


<a name="healthGet"></a>
# **healthGet**
> healthGet()

See if the server is healthy

Returns 200 if the server is healthy

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.api.ServerManagementApi;


ServerManagementApi apiInstance = new ServerManagementApi();
try {
    apiInstance.healthGet();
} catch (ApiException e) {
    System.err.println("Exception when calling ServerManagementApi#healthGet");
    e.printStackTrace();
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

null (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined

