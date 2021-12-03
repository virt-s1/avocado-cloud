#/bin/bash

# Description: Prepare environment for the containerized avocado-cloud (idempotent)
# Maintainer: Charles Shih <schrht@gmail.com>

# Setup ssh credentials for container environment
if [ "$(ls /data/*.pem | wc -l 2>/dev/null)" = "1" ];then
    f=$(ls /data/*.pem)
    chmod 400 $f
    rm -f /root/.ssh/sshkey.pem
    ln -s $f /root/.ssh/sshkey.pem
else
    echo "Error: found 0 or more than 1 pem file(s) under /data/, please check!"
    exit 1
fi

exit 0
