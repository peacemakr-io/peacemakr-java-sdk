# LoginApi

All URIs are relative to *http://api.peacemakr.io/api/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**login**](LoginApi.md#login) | **GET** /login | After aquiring and OAuth2 openId id_token from IdP (like google login), present it here and proceed with the required flow.  If this is a new user, they&#39;ll have to create an org, else, they will just get their org details, and an APIKey associated with their org.
[**loginInviteUser**](LoginApi.md#loginInviteUser) | **POST** /login/inviteUser | Invite (bind) an existing user that is not already bound to an org, to your org
[**loginUninviteUser**](LoginApi.md#loginUninviteUser) | **DELETE** /login/inviteUser | Uninvite (remove) an existing user that is part of your org


<a name="login"></a>
# **login**
> LoginResponse login(idToken)

After aquiring and OAuth2 openId id_token from IdP (like google login), present it here and proceed with the required flow.  If this is a new user, they&#39;ll have to create an org, else, they will just get their org details, and an APIKey associated with their org.

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.api.LoginApi;


LoginApi apiInstance = new LoginApi();
String idToken = "idToken_example"; // String | 
try {
    LoginResponse result = apiInstance.login(idToken);
    System.out.println(result);
} catch (ApiException e) {
    System.err.println("Exception when calling LoginApi#login");
    e.printStackTrace();
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **idToken** | **String**|  |

### Return type

[**LoginResponse**](LoginResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

<a name="loginInviteUser"></a>
# **loginInviteUser**
> loginInviteUser(email)

Invite (bind) an existing user that is not already bound to an org, to your org

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.LoginApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

LoginApi apiInstance = new LoginApi();
String email = "email_example"; // String | 
try {
    apiInstance.loginInviteUser(email);
} catch (ApiException e) {
    System.err.println("Exception when calling LoginApi#loginInviteUser");
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

<a name="loginUninviteUser"></a>
# **loginUninviteUser**
> loginUninviteUser(email)

Uninvite (remove) an existing user that is part of your org

### Example
```java
// Import classes:
//import io.peacemakr.crypto.swagger.client.ApiClient;
//import io.peacemakr.crypto.swagger.client.ApiException;
//import io.peacemakr.crypto.swagger.client.Configuration;
//import io.peacemakr.crypto.swagger.client.auth.*;
//import io.peacemakr.crypto.swagger.client.api.LoginApi;

ApiClient defaultClient = Configuration.getDefaultApiClient();

// Configure API key authorization: header
ApiKeyAuth header = (ApiKeyAuth) defaultClient.getAuthentication("header");
header.setApiKey("YOUR API KEY");
// Uncomment the following line to set a prefix for the API key, e.g. "Token" (defaults to null)
//header.setApiKeyPrefix("Token");

LoginApi apiInstance = new LoginApi();
String email = "email_example"; // String | 
try {
    apiInstance.loginUninviteUser(email);
} catch (ApiException e) {
    System.err.println("Exception when calling LoginApi#loginUninviteUser");
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

