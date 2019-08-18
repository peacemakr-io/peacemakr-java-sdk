#!/bin/sh

set -ex

docker run --rm -v ${PWD}:/local swaggerapi/swagger-codegen-cli:2.4.5 generate \
    -i local/peacemakr-services.yml \
    -l java \
    -o local \
	--api-package io.peacemakr.crypto.swagger.client.api