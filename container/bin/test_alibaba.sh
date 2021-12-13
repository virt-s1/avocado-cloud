#/bin/bash

# Description: Run containerized avocado-cloud testing on Alibaba Cloud.
# Maintainer: Charles Shih <schrht@gmail.com>

set -e

CODEPATH=$(dirname $0)

# Run general setup
$CODEPATH/general_setup.sh

# Run tests
$CODEPATH/run_tests.py --platform alibaba

exit $?

