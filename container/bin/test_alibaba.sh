#/bin/bash

# Run Alibaba testing.

set -e

# init Alibaba testing
/app/container/bin/setup_alibaba.sh

# run tests
/app/run.py --platform alibaba

exit 0
