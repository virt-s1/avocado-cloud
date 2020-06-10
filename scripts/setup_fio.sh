#!/bin/bash

# Description:
# This script is used to ensure fio is available.

PATH=~/workspace/bin:/usr/sbin:/usr/local/bin:$PATH

die() { echo "$@"; exit 1; }

cd ~/workspace

type fio &>/dev/null && echo "Fio already Installed." && exit 0

result=`bash os_type.sh`
if [ "${result}" = "redhat" ]; then	# Install on RHEL6+

	# Prepare installation
	sudo yum install -y wget gcc
	sudo yum install -y libaio-devel	# For libaio support

	# Download the tarball
	wget https://github.com/axboe/fio/archive/fio-3.3.tar.gz || die "Fail to download tarball."
	
	# Install
	tar -xvf ./fio*.tar.gz && cd ./fio-fio* || die "Fail to deal with the tarball"
	./configure || die "Fail to run ./configure"
	make || die "Fail to run 'make'"
	sudo make install || die "Fail to run 'make install'"

	# Ensure fio can be run by sudo command
	sudo fio --version &>/dev/null || sudo ln -s /usr/local/bin/*fio* /usr/bin/

	# Check and report
	echo -e "\n=============================="
	sudo fio --version
	if [ $? -eq 0 ]; then
		echo -e "\nFio has been successfully installed."
		exit 0
	else
		echo -e "\nFailed to install fio."
		exit 1
	fi
else
	sudo apt install -y git gcc libaio-devel

	git clone https://github.com/axboe/fio/

	cd fio
	./configure && make && sudo make install || exit 1
fi

exit 0

