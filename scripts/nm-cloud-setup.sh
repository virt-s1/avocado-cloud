#!/bin/bash
PATH=~/workspace/bin:/usr/sbin:/usr/local/bin:$PATH
PROVIDER=$1

rpm -q NetworkManager-cloud-setup || yum -y install NetworkManager-cloud-setup

SYSTEMD_EDITOR=tee systemctl edit nm-cloud-setup.service <<EOF
[Service]
Environment=NM_CLOUD_SETUP_${PROVIDER}=yes
EOF

systemctl daemon-reload
systemctl start nm-cloud-setup.service

exit 0
