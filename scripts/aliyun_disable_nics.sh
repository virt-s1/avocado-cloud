#!/bin/bash
PATH=~/workspace/bin:/usr/sbin:/usr/local/bin:$PATH

systemctl status NetworkManager
if [ $? = 0 ]; then
	echo "NetworkManager Enabled, the NICs should be managed."
	exit 0
fi

primary_nic=$(ifconfig | grep "flags=.*\<UP\>" | cut -d: -f1 |
	grep -e eth -e ens | head -n 1)
device_name=$(echo $primary_nic | tr -d '[:digit:]')
dev_list=$(ifconfig | grep "flags=.*\<UP\>" | cut -d: -f1 |
	grep $device_name | grep -v $primary_nic)

for dev in $dev_list; do
	echo "'ifdown' device $dev..."
	sudo ifdown $dev
	sleep 1s
done

exit 0
