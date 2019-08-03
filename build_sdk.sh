#!/bin/sh

set -ex

`aws ecr get-login --no-include-email --region us-east-2 --profile peacemakr` || true

rm -rf ./src/main/java/io/swagger/client/ || true
rm -rf ./src/test/java/io/swagger/client/ || true
./generate-stub-client.sh
./gradlew clean build --info
