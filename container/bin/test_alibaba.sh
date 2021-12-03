#/bin/bash

# Description: Run containerized avocado-cloud testing on Alibaba Cloud.
# Maintainer: Charles Shih <schrht@gmail.com>

set -e

# Run general setup
./general_setup.sh

# run tests
/app/run.py --platform alibaba

exit 0
