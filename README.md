<p align="center">
  <br>
    <img src="https://admin.peacemakr.io/images/PeacemakrP-Golden.png" width="150"/>
  <br>
</p>

# Peacemakr Java SDK

This SDK provides simple, backward compatible, and secure Application Layer Cryptography with built in Key Lifecycle Management.

## Quick Start, Integrate this SDK

- Navigate to the latest release.
- Download the `jar`'s from the release tab.
- Include the jar's in your project's `CLASSPATH`
- Obtain your APIKey, using your admin poral (https://admin.peacemakr.io).
- Construct a new instance of the Peacemakr Java SDK, using your APIKey,
   - `ICrypto peacemakrSDK = Factory.getCryptoSDK(myAPIKey, "my client name", null, new FilePersister("~/.peacemakr"), null);`
- Start Encrypting and Decrypting, for example,
   - `byte[] encrypted = peacemakrSDK.encrypt(plaintext);`
   - `byte[] decrypted = peacemakrSDK.decrypt(encrypted);`

## Example Integration
 - See `example` folder for a encryption / decryption sample app.

```
class SimpleEncryptDecrypt {
    public static void main(String[] args) throws Exception {

        String apiKey = "your-api-key";
        InMemoryPersister persister = new InMemoryPersister();

      ICrypto cryptoI = Factory.getCryptoSDK(apiKey, "simple encrypt decrypt", null, persister, null);
      cryptoI.register();

      String plaintext = "Hello world!";

      byte[] encrypted = cryptoI.encrypt(plaintext.getBytes());
      System.out.println("Encrypted: " + new String(encrypted));

      byte[] decrypted = cryptoI.decrypt(encrypted);
        System.out.println("Decrypted: " + new String(decrypted));
    }
}
```

## Integration Details

 - The Facotry, and constructing a client.
```
    /**
     *
     * This factory constructs a Peacemakr SDK Client.  All Peacemakr SDK clients
     * implement the ICrypto interface.
     *
     * All clients are stateful.  Internally, this state includes a private asymmetric
     * key, local cache of symmetric keys downloaded from Peacemakr so far, ability to
     * communicate with the peacemakr service org. All state is persisted through
     * your provided Persister. This mechanism allows for a single client to re-use
     * a previously registered api client (and not incur additional overhead due to
     * re-registering the same client over and over again).
     *
     * Auth is handled through the provided apiKey. If you do not have one, please register
     * at https://admin.peacemakr.io as a new organization. If you have a peacemakr organization
     * already, but are not sure what your apiKey should be, please login
     * (https://admin.peacemakr.io) and navigate to "API Keys" tab, and select one of your apiKey's.
     * The same API Key may be re-used across different clients.
     *
     * Persisting local data is important features of Peacemakr Clients. To help make this
     * as easy and seamless as possible, this client will only ever read or write through
     * this simple provided interface. There are two implementations of this interface which
     * are already provided: FilePersister and InMemoryPersister.  They do exactly as their
     * names describe. If your specific application requires a different or special type of
     * persistence layer, you are welcomed to implement this interface in whichever fashion
     * best suites your needs, and even open a PR against our SDK to ensure that we continue
     * supporting your particular persistenc layer it as we update and improve the clients.
     *
     *
     * @param apiKey Required. Auth mechanism which permits this client to connect to your Peacemakr Organization.
     * @param clientName Required. Any string which may be used to identify this particular client.  Please do not use
     *                   any customer Personally Identifiable Information (PII) in this field.
     * @param peacemakrBaseURL Optional. The base url for Peacemakr's  Cloud Services. If null, the default value
     *                        (https://api.peacemakr.io) is used.
     * @param persister Required. This persister help the cleint persist data.
     * @param logger Optional. If null, we use a standard log4j logger, else, you are welcomed to provide your own
     *               logger solution for local visibility and debugging.
     * @return An ICrypto which is ready to be used.
     * @throws PeacemakrException Is thrown on any non-recoverable error.
     */
    public static ICrypto getCryptoSDK(String apiKey, String clientName, String peacemakrBaseURL, Persister persister, Logger logger) throws PeacemakrException;
```

  - The interface in this SDK for Application Layer Cryptography:
```
public interface ICrypto {
  /**
   * Registers to PeaceMakr as a client. The persister is used to detect prior registrations on this client, so safe
   * to call multiple times. Once a successful invocation of Register is executed once, subsequent calls become a
   * noop. One successful call is required before any cryptographic use of this SDK.
   * 
   * Registration may fail with invalid apiKey, missing network connectivity, or an invalid persister. On failure,
   * take corrections action and invoke again.
   */
  void register() throws PeacemakrException;

  /**
   * Sync all available keys for this client. This invocation will help performance of subsequent encryption
   * and decryption calls.
   * 
   * Sync may fail, if registration was not invoked, if there's network connectivity issues, or
   * unexpected authorization issues.
   */
  void sync() throws PeacemakrException;

  /**
   * Encrypt the plaintext, using a random available usedomain.
   *
   * @param plainText Plaintext bytes to encrypt.
   * @return Opaquely packaged ciphertext.
   * @throws PeacemakrException On any error (network connectivity issues, authN issues, etc)
   */
  byte[] encrypt(byte[] plainText) throws PeacemakrException;

  /**
   * Encrypt the plaintext, but restrict which keys may be used to a Use Domain of this specific name. Names of Use
   * Domains are not unique, and this non-unique property of your Organization's Use Domains allows for graceful
   * rotation of encryption keys off of old (retiring, stale, or compromised) Use Domains, simply by creating a new
   * Use Domain with the same name. The transitional purity, both Use Domains may be selected for encryption use by
   * clients restricted to one particular name. Then, retiring of one of the two Use Domains is possible without
   * disrupting your deployed application.
   *
   * @param plainText     Plaintext to encrypt.
   * @param useDomainName Non-unique User Domain of your organization's.
   */
  byte[] encryptInDomain(byte[] plainText, String useDomainName) throws PeacemakrException, UnsupportedEncodingException;

  /**
   * Decrypt the opaquely packaged ciphertext and return the original plain text.
   *
   * @param cipherText CipherText to decrypt.
   */
  byte[] decrypt(byte[] cipherText) throws PeacemakrException;

  /**
   * For visibility or debugging purposes, returns a string whihc identifies which
   * client and configuration this client is running.
   */
  String getDebugInfo();
}
```

## Contributions

Peacemakr welcomes open and active contributions to this SDK. As long as they're in the spirit of project, we will most likely accept them. However, you may want to get our opinion on proposed changes before investing time, so we can work together to solve problems you encounter that make sense for the future direction we have planned.

## Testing

We use the usual fork and PR mechanisms, and in this section, here are some basic guidelines on how to setup a development environment. Without being a member of peacemakr, you will not have full access to the testing infrastructure required for complete code coverage, but our CircleCI build and test pipeline can be used to provide this level of visibility and provide feedback.

## Development Environment

### Dependencies:
 - Download and install openjdk: https://jdk.java.net/12/
 - Untar the download, and install it, for example on a mac: `sudo mv jdk-12.0.1.jdk /Library/Java/JavaVirtualMachines/`
 - `export JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk-12.0.1.jdk/Contents/Home` to your `~/.bash_profile`
 - Install IntelliJ CE

### How to build:
- `aws ecr get-login --no-include-email --region us-east-2 --profile peacemakr` || true
- `docker-compose up` (just let this run in a separate window while building, integration tests depend on it locally)
- `./build.sh`

### How to release version x.y.z:
- Delete your folder `./build` to ensure a fresh build of all artifacts.
- Build everything (see above).  Make sure it completes successfully before proceeding.
- Update all refernces to previous version, to new version. (use `git grep 0.0.1` for example)
- Commit version updates.
- `git tag vx.y.z`
- `git push origin vx.y.z`
- Login to github. Browse to the project's release section.  Manually upload the 2 jars (CoreCrypto jar and SDK jar's) built from released tag. Update release notes on build release 

### Hot to release to maven local
- ./gradlew install

### How to release to maven central
- 'vi ~/.gradle/gradle.properties'
- fill in all secrets in the local gradle.properties (for 'signing.keyId' provide last 8 chars of the signing key)
- set you gradle build to use local gradle.properties 'export GRADLE_USER_HOME=$(echo ~/.gradle)'
- ./gradlew uploadArchives