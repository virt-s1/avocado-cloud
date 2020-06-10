#/bin/bash

# Run Alibaba testing.

set -e

# init Alibaba testing
/app/container/bin/setup_alibaba.sh

# update script
sed -i 's/distro = "azure"/distro = "alibaba"/' /app/order_run.py

# run tests
export PYTHONPATH=. && /app/order_run.py

exit 0
