#!/bin/bash

# Description:
# This script is used to ensure sysbench is available.

PATH=~/workspace/bin:/usr/sbin:/usr/local/bin:$PATH

die() { echo "$@"; exit 1; }

cd ~/workspace

type sysbench &>/dev/null && echo "Sysbench already Installed." && exit 0

result=`bash os_type.sh`
if [ "${result}" = "redhat" ]; then	# Install on RHEL6+
	# Prepare installation
	sudo yum install -y wget gcc
	sudo yum install -y make automake libtool pkgconfig libaio-devel
	sudo yum install -y postgresql-devel	# For PostgreSQL support

	# Download the tarball
	wget https://github.com/akopytov/sysbench/archive/1.0.12.tar.gz || die "Fail to download tarball."

	# Install
	tar -xvf ./1.0.12.tar.gz && cd ./sysbench-1.0.12/ || die "Fail to deal with the tarball"
	./autogen.sh || die "Fail to run ./autogen.sh"
	./configure --with-pgsql --without-mysql || die "Fail to run ./configure"
	make -j || die "Fail to run 'make'"
	sudo make install || die "Fail to run 'make install'"

	# Ensure sysbench can be run by sudo command
	sudo sysbench --version &>/dev/null || sudo ln -s /usr/local/bin/sysbench /usr/bin/

	# Check and report
	echo -e "\n=============================="
	sudo sysbench --version
	if [ $? -eq 0 ]; then
		echo -e "\nSysbench has been successfully installed."
		exit 0
	else
		echo -e "\nFailed to install sysbench."
		exit 1
	fi
else
	# To be supported
	exit 1
fi

exit 0

