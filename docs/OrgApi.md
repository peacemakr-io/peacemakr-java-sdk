# OrgApi

All URIs are relative to *http://api.peacemakr.io/api/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**addAPIKeyToOrg**](OrgApi.md#addAPIKeyToOrg) | **POST** /org/key | Add a new API Key to an org
[**addAdminToOrg**](OrgApi.md#addAdminToOrg) | **POST** /org/admin | Add a new admin to this org
[**addOrganization**](OrgApi.md#addOrganization) | **POST** /org | Create a new organization. Must be an authenticated request with a valid id_token from a trusted IdP.
[**deleteAPIKeyFromOrg**](OrgApi.md#deleteAPIKeyFromOrg) | **DELETE** /org/key/{apikey} | Remove an existing API Key
[**deleteAdminFromOrg**](OrgApi.md#deleteAdminFromOrg) | **DELETE** /org/admin/{email} | Remove an existing admin from the org (You can not remove the last admin. It will faile with a Bad Request response.)
[**deleteOrganization**](OrgApi.md#deleteOrganization) | **DELETE** /org/{orgId} | Remove an existing organization
[**getCloudOrganizationAPIKey**](OrgApi.md#getCloudOrganizationAPIKey) | **GET** /org/key/sharedCloud | Get an access key for the peacemakr shared cloud org (all cloud key derivers must use this)
[**getOrganization**](OrgApi.md#getOrganization) | **GET** /org/{orgId} | Get an existing organization
[**getOrganizationFromAPIKey**](OrgApi.md#getOrganizationFromAPIKey) | **GET** /org/key/{apikey} | Get an existing Organization
[**getTestOrganizationAPIKey**](OrgApi.md#getTestOrganizationAPIKey) | **GET** /org/key/test | Get an ephemeral test org api key
[**updateStripeCustomerId**](OrgApi.md#updateStripeCustomerId) | **POST** /org/stripeId | Update the stripe customer Id associated with this account


<a name="addAPIKeyToOrg"></a>
# **addAPIKeyToOrg**
> APIKey addAPIKeyToOrg()

Add a new API Key to an org

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.OrgApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

OrgApi apiInstance = new OrgApi();
try {
    APIKey result = apiInstance.addAPIKeyToOrg();
    System.out.println(result);
} catch (ApiException e) {
    System.err.println("Exception when calling OrgApi#addAPIKeyToOrg");
    e.printStackTrace();
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**APIKey**](APIKey.md)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="addAdminToOrg"></a>
# **addAdminToOrg**
> Contact addAdminToOrg(contact)

Add a new admin to this org

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.OrgApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

OrgApi apiInstance = new OrgApi();
Contact contact = new Contact(); // Contact | 
try {
    Contact result = apiInstance.addAdminToOrg(contact);
    System.out.println(result);
} catch (ApiException e) {
    System.err.println("Exception when calling OrgApi#addAdminToOrg");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **contact** | [**Contact**](Contact.md)|  |

### Return type

[**Contact**](Contact.md)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="addOrganization"></a>
# **addOrganization**
> Organization addOrganization(idToken, stripeCustomerId, orgName, contact)

Create a new organization. Must be an authenticated request with a valid id_token from a trusted IdP.

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.OrgApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

OrgApi apiInstance = new OrgApi();
String idToken = "idToken_example"; // String | 
String stripeCustomerId = "stripeCustomerId_example"; // String | 
String orgName = "orgName_example"; // String | 
Contact contact = new Contact(); // Contact | 
try {
    Organization result = apiInstance.addOrganization(idToken, stripeCustomerId, orgName, contact);
    System.out.println(result);
} catch (ApiException e) {
    System.err.println("Exception when calling OrgApi#addOrganization");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **idToken** | **String**|  |
 **stripeCustomerId** | **String**|  |
 **orgName** | **String**|  |
 **contact** | [**Contact**](Contact.md)|  |

### Return type

[**Organization**](Organization.md)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="deleteAPIKeyFromOrg"></a>
# **deleteAPIKeyFromOrg**
> deleteAPIKeyFromOrg(apikey)

Remove an existing API Key

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.OrgApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

OrgApi apiInstance = new OrgApi();
String apikey = "apikey_example"; // String | 
try {
    apiInstance.deleteAPIKeyFromOrg(apikey);
} catch (ApiException e) {
    System.err.println("Exception when calling OrgApi#deleteAPIKeyFromOrg");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **apikey** | **String**|  |

### Return type

null (empty response body)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="deleteAdminFromOrg"></a>
# **deleteAdminFromOrg**
> deleteAdminFromOrg(email)

Remove an existing admin from the org (You can not remove the last admin. It will faile with a Bad Request response.)

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.OrgApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

OrgApi apiInstance = new OrgApi();
String email = "email_example"; // String | 
try {
    apiInstance.deleteAdminFromOrg(email);
} catch (ApiException e) {
    System.err.println("Exception when calling OrgApi#deleteAdminFromOrg");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **email** | **String**|  |

### Return type

null (empty response body)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="deleteOrganization"></a>
# **deleteOrganization**
> deleteOrganization(orgId)

Remove an existing organization

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.OrgApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

OrgApi apiInstance = new OrgApi();
String orgId = "orgId_example"; // String | 
try {
    apiInstance.deleteOrganization(orgId);
} catch (ApiException e) {
    System.err.println("Exception when calling OrgApi#deleteOrganization");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **orgId** | **String**|  |

### Return type

null (empty response body)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="getCloudOrganizationAPIKey"></a>
# **getCloudOrganizationAPIKey**
> APIKey getCloudOrganizationAPIKey()

Get an access key for the peacemakr shared cloud org (all cloud key derivers must use this)

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.OrgApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

OrgApi apiInstance = new OrgApi();
try {
    APIKey result = apiInstance.getCloudOrganizationAPIKey();
    System.out.println(result);
} catch (ApiException e) {
    System.err.println("Exception when calling OrgApi#getCloudOrganizationAPIKey");
    e.printStackTrace();
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**APIKey**](APIKey.md)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

<a name="getOrganization"></a>
# **getOrganization**
> Organization getOrganization(orgId)

Get an existing organization

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.OrgApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

OrgApi apiInstance = new OrgApi();
String orgId = "orgId_example"; // String | 
try {
    Organization result = apiInstance.getOrganization(orgId);
    System.out.println(result);
} catch (ApiException e) {
    System.err.println("Exception when calling OrgApi#getOrganization");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **orgId** | **String**|  |

### Return type

[**Organization**](Organization.md)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="getOrganizationFromAPIKey"></a>
# **getOrganizationFromAPIKey**
> Organization getOrganizationFromAPIKey(apikey)

Get an existing Organization

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.OrgApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

OrgApi apiInstance = new OrgApi();
String apikey = "apikey_example"; // String | 
try {
    Organization result = apiInstance.getOrganizationFromAPIKey(apikey);
    System.out.println(result);
} catch (ApiException e) {
    System.err.println("Exception when calling OrgApi#getOrganizationFromAPIKey");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **apikey** | **String**|  |

### Return type

[**Organization**](Organization.md)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="getTestOrganizationAPIKey"></a>
# **getTestOrganizationAPIKey**
> APIKey getTestOrganizationAPIKey()

Get an ephemeral test org api key

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.api.OrgApi;


OrgApi apiInstance = new OrgApi();
try {
    APIKey result = apiInstance.getTestOrganizationAPIKey();
    System.out.println(result);
} catch (ApiException e) {
    System.err.println("Exception when calling OrgApi#getTestOrganizationAPIKey");
    e.printStackTrace();
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**APIKey**](APIKey.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

<a name="updateStripeCustomerId"></a>
# **updateStripeCustomerId**
> APIKey updateStripeCustomerId(stripeCustomerId)

Update the stripe customer Id associated with this account

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.OrgApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

OrgApi apiInstance = new OrgApi();
String stripeCustomerId = "stripeCustomerId_example"; // String | 
try {
    APIKey result = apiInstance.updateStripeCustomerId(stripeCustomerId);
    System.out.println(result);
} catch (ApiException e) {
    System.err.println("Exception when calling OrgApi#updateStripeCustomerId");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **stripeCustomerId** | **String**|  |

### Return type

[**APIKey**](APIKey.md)

### Authorization

[header](../README.md#header)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

