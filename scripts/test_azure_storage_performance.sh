#!/bin/bash
workspace="/root/virt-perf-scripts/block"
vmsize=`curl -H Metadata:true -s "http://169.254.169.254/metadata/instance/compute/vmSize?api-version=2017-08-01&format=text"`
if [[ x"$vmsize" =~ xStandard_M128.* ]];then
    backend="temporarydisk"
    driver="hv_storevsc"
    fs="raw"
    boot_disk=`df|grep boot|awk '{print $1}'|xargs basename`
    if [[ x"${boot_disk}" == x"sda1" ]];then
        filename="/dev/sdb"
    else
        filename="/dev/sda"
    fi
elif [[ x"$vmsize" == x"Standard_L80s_v2" ]];then
    backend="NVMe"
    driver="nvme"
    fs="raw"
    filename="/dev/nvme0n1:/dev/nvme1n1:/dev/nvme2n1:/dev/nvme3n1:/dev/nvme4n1:/dev/nvme5n1:/dev/nvme6n1:/dev/nvme7n1:/dev/nvme8n1:/dev/nvme9n1"
else
    echo "Non-supported VM size!"
    exit 1
fi
filename=$(echo ${filename}|sed 's/\//\\\//g')
/usr/bin/cp $workspace/tests/full.yaml $workspace/virt_perf_scripts.yaml
sed -i "s/filename.*$/filename: ${filename}/g" $workspace/virt_perf_scripts.yaml
sed -i "s/backend.*$/backend: $backend/g" $workspace/virt_perf_scripts.yaml
sed -i "s/driver.*$/driver: $driver/g" $workspace/virt_perf_scripts.yaml
sed -i "s/fs.*$/fs: $fs/g" $workspace/virt_perf_scripts.yaml
sed -i "s/runtime.*$/runtime: 2m/g" $workspace/virt_perf_scripts.yaml
cpu=$(nproc)
cd $workspace
echo "======================================="
cat virt_perf_scripts.yaml
echo "======================================="
echo
if [[ x$1 != x"-y" ]];then
    read -p "Please confirm the configuration:"
fi
if [[ x"$vmsize" =~ xStandard_M128.* ]];then
    blkdiscard $filename
elif [[ x"$vmsize" == x"Standard_L80s_v2" ]];then
#    for i in `seq 0 9`; do echo 0 >/sys/block/nvme${i}n1/queue/rq_affinity; done
    for i in `seq 0 9`; do blkdiscard /dev/nvme${i}n1; done
fi
(./RunFioTest.py --rw_list read,write,rw --numjobs 1 --log_path "${vmsize}_`uname -r`";./RunFioTest.py --rw_list randread,randwrite,randrw --numjobs $cpu --log_path "${vmsize}_`uname -r`";./GenerateTestReport.py --result_path "${vmsize}_`uname -r`" --report_csv "${vmsize}_`uname -r`.csv") > ${vmsize}_`uname -r`.log 2>&1 &
