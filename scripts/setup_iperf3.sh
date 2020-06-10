#!/bin/bash

# Description:
# This script is used to ensure iperf3 is available.

PATH=~/workspace/bin:/usr/sbin:/usr/local/bin:$PATH

cd ~/workspace

type iperf3 >/dev/null 2>&1 && echo "Already Installed." && exit 0

if [ "$(os_type.sh)" = "redhat" ]; then
	# setup epel repos
	#wget http://dl.fedoraproject.org/pub/epel/7/x86_64/e/epel-release-7-10.noarch.rpm
	#sudo rpm -ivh epel-release-7-10.noarch.rpm
	#
	# setup iperf3
	#sudo yum install -y iperf3 --enablerepo=epel

	# download rpm and install
	curl -O https://iperf.fr/download/fedora/iperf3-3.1.3-1.fc24.x86_64.rpm
	sudo rpm -ivh iperf3-3.1.3-1.fc24.x86_64.rpm

	rpm -qa | grep iperf3
else
	sudo apt install -y iperf3
	dpkg -s iperf3
fi

exit 0

