#!/usr/bin/env bash

set -ex -o pipefail

PUBLIC_LISTEN_PORT=${1:-12345}

service docker start
docker build --tag batcomputer .
docker run --tty --interactive --cap-add sys_ptrace \
    --publish ${PUBLIC_LISTEN_PORT}:4444 --publish 8000:8000 batcomputer
