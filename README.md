# Peacemakr Java SDK

A cloud or on-prem backed SDK that which provides simple, backward compatible, and secure Crypto with built in Key Lifecycle Management.

## QuickStart: Integrating with this SDK

- Navigate to the latest release.
- Download the `jar`'s from the release tab.
- Include the jar's in your project's `CLASSPATH`
- Obtain your APIKey, using your admin poral (https://admin.peacemakr.io).
- Construct a new instance of the Peacemakr Java SDK, using your APIKey,
   - `ICrypto peacemakrSDK = Factory.getCryptoSDK(myAPIKey, "my client name", null, new FilePersister("~/.peacemakr"), null);`
- Start Encrypting and Decrypting, for example,
   - `byte[] encrypted = peacemakrSDK.encrypt(plaintext);`
   - `byte[] decrypted = peacemakrSDK.decrypt(encrypted);`

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
