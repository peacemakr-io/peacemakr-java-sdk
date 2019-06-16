#!/bin/sh

set -ex

rm -rf ./src/main/java/io/swagger/client/ || true
rm -rf ./src/test/java/io/swagger/client/ || true
./generate-stub-client.sh
./gradlew build