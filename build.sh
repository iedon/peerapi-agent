#!/bin/sh
set -e
echo "Building peerapi-agent for Linux AMD64..."

export GOOS=linux
export GOARCH=amd64

rm -rf dist || true
mkdir dist

cd src
go mod tidy
go build -o ../dist/peerapi-agent -ldflags="-X github.com/iedon/peerapi-agent/version.GIT_COMMIT=$(git rev-parse --short HEAD)"

cd ..
cp config.json ./dist/config.json

echo "Build completed."
