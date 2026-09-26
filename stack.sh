#!/bin/bash

set -e

STACK_LTS_CONFIG="stack-lts-24.yaml"
stack --stack-yaml="$STACK_LTS_CONFIG" $@
