#!/bin/bash

PATH=~/workspace/bin:/usr/sbin:/usr/local/bin:$PATH

# setup
#setup.sh

inst_type=$1
time_stamp=$(date -u +%Y%m%d_%H%M%S)
logpath="$HOME/workspace/log"
mkdir -p $logpath
logfile="$logpath/resource_validation_${inst_type}_${time_stamp}.log"

# log the informaiton
#show_info.sh >> $logfile 2>&1

# perform this test
function run_cmd(){
	# $1: Command

	echo -e "\n$ $1" >> $logfile
	eval $1 >> $logfile 2>&1
}

echo -e "\n\nTest Results:\n===============\n" >> $logfile

run_cmd 'lscpu'
run_cmd 'free -k'

run_cmd 'cat /proc/cpuinfo'
run_cmd 'cat /proc/meminfo'

CPU=$(grep "^CPU(s):" $logfile | awk '{print $2}')
MEM=$(grep "^MemTotal:" $logfile | awk '{print $2}')

# nproc should equal to CPU number
if [ "$(nproc)" != "$CPU" ]; then
	echo "* WARNING: nproc is mismatched with CPU number!!! ($(nproc) != $CPU)" >> $logfile
else
	echo "* PASSED: nproc is matched with CPU number. ($(nproc) = $CPU)" >> $logfile
fi

# Check CPU flags
if [ "$(sed -n 's/^flags.*://p' $logfile | sort -u | wc -l)" != "1" ]; then
	# Processes kept mismatched CPU flags
	echo "* ERROR: Processes kept mismatched CPU flags." >> $logfile
else
	# Get CPU flags, remove blanks from head/tail, get 1-7 chars of MD5 (for further comparison)
	FLAGS=$(sed -n 's/^flags.*://p' $logfile | sort -u | xargs echo | md5sum | cut -c 1-7)
fi

# Write down a summary
echo -e "\nTest Summary: \n----------\n" >> $logfile
printf "** %-12s %-5s %-12s %-12s\n" VMSize "CPU#" "MemSize(kB)" Flags >> $logfile
printf "** %-12s %-5s %-12s %-12s\n" $inst_type $CPU $MEM $FLAGS >> $logfile

# Additional validation
run_cmd 'sudo virt-what'
run_cmd 'lspci'
run_cmd 'lsmod'

# teardown
#teardown.sh

exit 0
