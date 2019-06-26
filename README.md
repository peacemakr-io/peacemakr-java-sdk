# Peacemakr Java SDK

A cloud or on-prem backed service that which provides simple, backward compatible, and secure key lifecycle management.

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
- ./build_sdk.sh