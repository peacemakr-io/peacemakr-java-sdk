
# KeyDerivationInstance

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**id** | **String** | instance id (concrete instance) | 
**serviceIds** | **List&lt;String&gt;** | service id (virtual service id) | 
**active** | **Boolean** | currently online and accepting requests for key derivation | 
**version** | **String** |  | 
**baseUrl** | **String** | base URL from which this key deriver instance will respond to new key derivation job requests |  [optional]
**isPublic** | **Boolean** | if true then the key deriver is visible to every other organization |  [optional]



