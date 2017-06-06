#!/bin/bash -e

apt-get update
apt-get install -y wget

DOCKERIZE_VERSION=v0.3.0

wget https://github.com/jwilder/dockerize/releases/download/$DOCKERIZE_VERSION/dockerize-linux-amd64-$DOCKERIZE_VERSION.tar.gz
tar -C /usr/local/bin -xzvf dockerize-linux-amd64-$DOCKERIZE_VERSION.tar.gz
rm dockerize-linux-amd64-$DOCKERIZE_VERSION.tar.gz
