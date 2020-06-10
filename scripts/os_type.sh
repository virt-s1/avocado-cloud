#!/bin/bash

PATH=~/workspace/bin:/usr/sbin:/usr/local/bin:$PATH

# This script is used to tell the OS type

#grep -i "Red Hat Enterprise Linux" /etc/system-release >/dev/null 2>&1 && echo "redhat" && exit 0
#grep -i "Ubuntu" /etc/issue >/dev/null 2>&1 && echo "ubuntu" && exit 0


if [ -f /etc/system-release ]; then
	echo "redhat"
else
	echo "debian"
fi

exit 0

