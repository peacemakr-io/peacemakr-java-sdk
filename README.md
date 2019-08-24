# Peacemakr Java SDK

A cloud or on-prem backed SDK that which provides simple, backward compatible, and secure Crypto with built in Key Lifecycle Management.

## QuickStart: Integrating with this SDK

## Development and Contributions

Dependencies:
 - download and install openjdk: https://jdk.java.net/12/
 - untar the download, and install it: `sudo mv jdk-12.0.1.jdk /Library/Java/JavaVirtualMachines/`
 - Update your JAVA_HOME in bash_profile
 - Install intelliJ
 
Tricks:
 - Easy switch between java versions on your mac: 
 `brew install jenv`
  Add the following lines to ~/.bash_profile or ~/.zshrc:
 `# Init jenv
  if which jenv > /dev/null; then eval "$(jenv init -)"; fi`
  Add all java version for the on your machine:
  `jenv add  /Library/Java/JavaVirtualMachines/jdk-12.0.1.jdk/Contents/Home/`\
  Your current version:
  `jenv versions`
  Set global version:
  `jenv global openjdk64-12.0.1`

How to build:
- `aws ecr get-login --no-include-email --region us-east-2 --profile peacemakr` || true
- `docker-compose up` (just let this run in a separate window while building, integration tests depend on it locally)
- `./build.sh`

How to release version x.y.z:
- Delete your folder `./build` to ensure a fresh build of all artifacts.
- Build everything (see above).  Make sure it completes successfully before proceeding.
- Update all refernces to previous version, to new version. (use `git grep 0.0.1` for example)
- Commit version updates.
- `git tag vx.y.z`
- `git push origin vx.y.z`
- Login to github. Browse to the project's release section.  Manually upload the 2 jars (CoreCrypto jar and SDK jar's) built from released tag. Update release notes on build release 
