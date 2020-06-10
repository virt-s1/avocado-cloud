#/bin/bash

# Init Alibaba testing. (idempotent)

# setup ssh credentials
if [ "$(ls /data/*.pem | wc -l 2>/dev/null)" = "1" ];then
    f=$(ls /data/*.pem)
    chmod 400 $f
    rm -f /root/.ssh/sshkey.pem
    ln -s $f /root/.ssh/sshkey.pem
else
    echo "Error: found 0 or more than 1 pem file(s) under /data/, please check!"
    exit 1
fi

# link user data
flist="alibaba_common.yaml alibaba_flavors.yaml alibaba_testcases.yaml"
for f in $flist; do
    [ ! -e "/data/$f" ] && cp /app/config/$f /data/
    rm -f /app/config/$f
    ln -s /data/$f /app/config/$f
done

exit 0
