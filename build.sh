#!/bin/bash

set -e

cd "$(dirname $0)"

git submodule update --init --recursive

docker build -t tlsanvil .
echo "TLS-Anvil was built as a Docker image named 'tlsanvil'"
echo "It can be started using:"
echo "    docker run --rm -it -v $(pwd):/output tlsanvil [CLI options]"
