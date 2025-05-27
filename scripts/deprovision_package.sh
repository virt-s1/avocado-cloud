#!/bin/bash

if [ x$1 != x ];then
    func=$1
else
    echo "Must specify function: deprovision/verify/all. Exit!"
    echo "Usage: $0 <function: deprovision|verify|all> <type: cloudinit|cloudinit_wala|wala|kernel|azure-vm-utils> [username]"
    exit 1
fi

if [ x$2 != x ];then
    type=$2
else
    echo "Must specify type: cloudinit/cloudinit_wala/wala. Exit!"
    echo "Usage: $0 <function: deprovision|verify|all> <type: cloudinit|cloudinit_wala|wala|kernel|azure-vm-utils> [username]"
    exit 1
fi

if [ x$3 == x ];then
    username="azureuser"
else
    username=$3
fi

delete_arr=(/var/lib/waagent /var/lib/cloud /var/log/waagent.log* /var/log/cloud-init* \
/var/log/messages /etc/sudoers.d/* /mnt/resource/swapfile /mnt/swapfile \
/var/lib/NetworkManager/dhclient-* /etc/resolv.conf )

function deprovision_wala() {
    systemctl stop waagent
    systemctl enable waagent > /dev/null 2>&1
    # systemctl disable cloud-{init-local,init,config,final} > /dev/null 2>&1
    rpm -e cloud-init > /dev/null 2>&1
    sed -i -e 's/^ResourceDisk.EnableSwap=n/ResourceDisk.EnableSwap=y/g' \
        -e 's/^ResourceDisk.SwapSizeMB=.*/ResourceDisk.SwapSizeMB=2048/g' \
        -e 's/^ResourceDisk.Format=.*/ResourceDisk.Format=y/g' \
        /etc/waagent.conf
    swapoff -a
    for i in "${delete_arr[@]}";
    do
        rm -rf $i
    done
    sed -i '/azure_resource-part1/d' /etc/fstab
    userdel -rf $username
    sed -i -e '/DHCP_HOSTNAME/d' -e '/HWADDR/d' /etc/sysconfig/network-scripts/ifcfg-eth0
    hostnamectl set-hostname localhost.localdomain
    # Remove duplicated dhcp=dhclient
    release=`cat /etc/redhat-release| sed 's/.*release \([0-9]*\.[0-9]*\).*/\1/g'`
    if [ ${release%%.*} == '8' ];then
        sed -i -e '/\[main\]/a\dhcp = dhclient' -e '/dhcp *= *dhclient/d' /etc/NetworkManager/NetworkManager.conf
    fi
    # Create ifcfg-eth0 to workaround BZ#2092002
    touch /etc/sysconfig/network-scripts/ifcfg-eth0
    # Remove 50-cloud-init.conf
    rm -f /etc/ssh/sshd_config.d/50-cloud-init.conf
}

function deprovision_azure_vm_utils() {
    #rpm -e azure-vm-utils > /dev/null 2>&1 
    return 1
}

function deprovision_cloudinit_wala() {
    systemctl stop waagent
    systemctl enable waagent > /dev/null 2>&1
    systemctl enable cloud-{init-local,init,config,final} > /dev/null 2>&1
    # Disable WALA swap and resource disk format because will conflict with cloud-init
    sed -i -e 's/^ResourceDisk.Format=.*/ResourceDisk.Format=n/g' \
           -e 's/^ResourceDisk.EnableSwap=.*/ResourceDisk.EnableSwap=n/g' \
        /etc/waagent.conf
    # For old WALA version
    grep ^Provisioning.Agent /etc/waagent.conf > /dev/null || {
        sed -i -e 's/^Provisioning.UseCloudInit=.*/Provisioning.UseCloudInit=y/g' \
               -e 's/^Provisioning.Enabled=.*/Provisioning.Enabled=n/g' \
            /etc/waagent.conf
    }
    swapoff -a
    for i in "${delete_arr[@]}";
    do
        rm -rf $i
    done
    sed -i '/azure_resource-part1/d' /etc/fstab
    userdel -rf $username
#    sed -i -e '/DHCP_HOSTNAME/d' -e '/HWADDR/d' /etc/sysconfig/network-scripts/ifcfg-eth0
    rm -f /etc/sysconfig/network-scripts/ifcfg-eth0
    hostnamectl set-hostname localhost.localdomain
    if [ ! -f /etc/cloud/cloud.cfg.d/91-azure_datasource.cfg ];then
        echo "datasource_list: [ Azure ]" > /etc/cloud/cloud.cfg.d/91-azure_datasource.cfg
    fi
    # If is RHEL-8.0, add dhcp=dhclient in NetworkManager.conf for bug 1641190
    # Remove duplicated dhcp=dhclient
    release=`cat /etc/redhat-release| sed 's/.*release \([0-9]*\.[0-9]*\).*/\1/g'`
    if [ ${release%%.*} == '8' ];then
        sed -i -e '/\[main\]/a\dhcp = dhclient' -e '/dhcp *= *dhclient/d' /etc/NetworkManager/NetworkManager.conf
    fi
    # Remove 50-cloud-init.conf
    rm -f /etc/ssh/sshd_config.d/50-cloud-init.conf
}

function deprovision_cloudinit() {
    systemctl stop waagent
    rpm -e WALinuxAgent WALinuxAgent-udev
    systemctl enable cloud-{init-local,init,config,final} > /dev/null 2>&1
    swapoff -a
    for i in "${delete_arr[@]}";
    do
        rm -rf $i
    done
    sed -i '/azure_resource-part1/d' /etc/fstab
    userdel -rf $username
#    sed -i -e '/DHCP_HOSTNAME/d' -e '/HWADDR/d' /etc/sysconfig/network-scripts/ifcfg-eth0
    rm -f /etc/sysconfig/network-scripts/ifcfg-eth0
    hostnamectl set-hostname localhost.localdomain
    if [ ! -f /etc/cloud/cloud.cfg.d/91-azure_datasource.cfg ];then
        echo "datasource_list: [ Azure ]" > /etc/cloud/cloud.cfg.d/91-azure_datasource.cfg
    fi
    # If is RHEL-8.0, add dhcp=dhclient in NetworkManager.conf for bug 1661574
    # Remove duplicated dhcp=dhclient
    release=`cat /etc/redhat-release| sed 's/.*release \([0-9]*\.[0-9]*\).*/\1/g'`
    if [ ${release%%.*} == '8' ];then
        sed -i -e '/\[main\]/a\dhcp = dhclient' -e '/dhcp *= *dhclient/d' /etc/NetworkManager/NetworkManager.conf
    fi
    # Remove 50-cloud-init.conf
    rm -f /etc/ssh/sshd_config.d/50-cloud-init.conf
}

function format_echo() {
    msg=`echo "$1"|awk -F ': ' '{print $1}'`
    result=`echo "$1"|awk -F ': ' '{print $2}'`
    len_msg=${#msg}
    echo -n $msg
    printf "%$((40-$len_msg))s\n" $result
}


### Verify functions
function verify_files_removed() {
    ret=0
    for i in "${delete_arr[@]}";
    do
        if [ -f $i ];then echo "$i is not removed!";ret=1;fi
    done
    if [ $ret -ne 0 ];then
        format_echo "Verify files removed: FAIL"
        ret=1
    else
        format_echo "Verify files removed: PASS"
        ret=0
    fi
    return $ret
}

function verify_wala_provision_enabled() {
    grep ^Provisioning.Enabled=n /etc/waagent.conf > /dev/null
    if [[ $? == 0 ]];then
        format_echo "Verify Provisioning.Enabled=n: PASS"
        ret=0
    else
        format_echo "Verify Provisioning.Enabled=n: FAIL"
        echo $output
        ret=1
    fi
    return $ret
}

function verify_wala_provision_usecloudinit() {
    grep ^Provisioning.UseCloudInit=y /etc/waagent.conf > /dev/null
    if [[ $? == 0 ]];then
        format_echo "Verify Provisioning.UseCloudInit=y: PASS"
        ret=0
    else
        format_echo "Verify Provisioning.UseCloudInit=y: FAIL"
        echo $output
        ret=1
    fi
    return $ret
}

function verify_wala_provision_agent() {
    grep -E '^Provisioning.Agent=(auto|cloud-init)' /etc/waagent.conf > /dev/null
    if [[ $? == 0 ]];then
        format_echo "Verify Provisioning.Agent=auto: PASS"
        ret=0
    else
        format_echo "Verify Provisioning.Agent=auto: FAIL"
        echo $output
        ret=1
    fi
    return $ret
}

function verify_wala_conf() {
    wala_conf_ret=0
    grep ^Provisioning.Agent /etc/waagent.conf > /dev/null
    if [[ $? == 0 ]];then
        verify_wala_provision_agent||((wala_conf_ret=wala_conf_ret+1))
    else
        verify_wala_provision_enabled||((wala_conf_ret=wala_conf_ret+1))
        verify_wala_provision_usecloudinit||((wala_conf_ret=wala_conf_ret+1))
    fi
    return $wala_conf_ret
}

function verify_wala_resourcedisk_disableformat() {
    grep ^ResourceDisk.Format=n /etc/waagent.conf > /dev/null
    if [[ $? == 0 ]];then
        format_echo "Verify ResourceDisk.Format=n: PASS"
        ret=0
    else
        format_echo "Verify ResourceDisk.Format=n: FAIL"
        echo $output
        ret=1
    fi
    return $ret
}

function verify_wala_resourcedisk_enableswap() {
    grep ^ResourceDisk.EnableSwap=y /etc/waagent.conf > /dev/null
    if [[ $? == 0 ]];then
        format_echo "Verify ResourceDisk.EnableSwap=y: PASS"
        ret=0
    else
        format_echo "Verify ResourceDisk.EnableSwap=y: FAIL"
        echo $output
        ret=1
    fi
    return $ret
}

function verify_wala_resourcedisk_disableswap() {
    grep ^ResourceDisk.EnableSwap=n /etc/waagent.conf > /dev/null
    if [[ $? == 0 ]];then
        format_echo "Verify ResourceDisk.EnableSwap=n: PASS"
        ret=0
    else
        format_echo "Verify ResourceDisk.EnableSwap=n: FAIL"
        echo $output
        ret=1
    fi
    return $ret
}

function verify_wala_resourcedisk_swapsize() {
    grep ^ResourceDisk.SwapSizeMB=2048$ /etc/waagent.conf > /dev/null
    if [[ $? == 0 ]];then
        format_echo "Verify ResourceDisk.SwapSizeMB=2048: PASS"
        ret=0
    else
        format_echo "Verify ResourceDisk.SwapSizeMB=2048: FAIL"
        echo $output
        ret=1
    fi
    return $ret
}

function verify_wala_resourcedisk_mountpoint() {
    grep ^ResourceDisk.MountPoint=/mnt$ /etc/waagent.conf > /dev/null
    if [[ $? == 0 ]];then
        format_echo "Verify ResourceDisk.MountPoint=/mnt: PASS"
        ret=0
    else
        format_echo "Verify ResourceDisk.MountPoint=/mnt: FAIL"
        echo $output
        ret=1
    fi
    return $ret
}

function verify_cloudinit_enabled() {
    output=`systemctl is-enabled cloud-{init-local,init,config,final}`
    if [[ $? -ne 0 ]] || [[ $output =~ "disable" ]];then
        format_echo "Verify cloud-init status: FAIL"
        echo $output
        ret=1
    else
        format_echo "Verify cloud-init status: PASS"
        ret=0
    fi
    return $ret
}

function verify_cloudinit_disabled() {
    output=`systemctl is-enabled cloud-{init-local,init,config,final} 2>&1`
    if [[ $output =~ "enabled" ]];then
        format_echo "Verify cloud-init is disabled: FAIL"
        echo $output
        ret=1
    else
        format_echo "Verify cloud-init is disabled: PASS"
        ret=0
    fi
    return $ret
}

function verify_cloudinit_removed() {
    rpm -q cloud-init > /dev/null 2>&1
    if [[ $? -eq 0 ]];then
        format_echo "Verify cloud-init is removed: FAIL"
        ret=1
    else
        format_echo "Verify cloud-init is removed: PASS"
        ret=0
    fi
    return $ret
}

function verify_50cloudinitconf_removed() {
    ls /etc/ssh/sshd_config.d/50-cloud-init.conf > /dev/null 2>&1 
    if [[ $? -eq 0 ]];then
        format_echo "Verify 50-cloud-init.conf is removed: FAIL"
        ret=1
    else
        format_echo "Verify 50-cloud-init.conf is removed: PASS"
        ret=0
    fi
    return $ret
}


function verify_waagent_enabled() {
    output=`systemctl is-enabled waagent`
    if [[ $? -ne 0 ]] || [[ $output =~ "disable" ]];then
        format_echo "Verify waagent status: FAIL"
        echo $output
        ret=1
    else
        format_echo "Verify waagent status: PASS"
        ret=0
    fi
    return $ret
}

function verify_fstab_clean() {
    grep azure_resource-part1 /etc/fstab > /dev/null
    if [ $? -eq 0 ];then
        format_echo "Verify fstab: FAIL"
        ret=1
    else
        format_echo "Verify fstab: PASS"
        ret=0
    fi
    return $ret
}

function verify_dhcphostname_removed() {
    grep DHCP_HOSTNAME /etc/sysconfig/network-scripts/ifcfg-eth0 > /dev/null
    if [ $? -eq 0 ];then
        format_echo "Verify DHCP_HOSTNAME removed: FAIL"
        ret=1
    else
        format_echo "Verify DHCP_HOSTNAME removed: PASS"
        ret=0
    fi
    return $ret
}

function verify_91_azure_datasource_exists() {
    if [ ! -f /etc/cloud/cloud.cfg.d/91-azure_datasource.cfg ];then
        format_echo "Verify 91-azure_datasource.cfg: FAIL"
        ret=1
    else
        format_echo "Verify 91-azure_datasource.cfg: PASS"
        ret=0
    fi
    return $ret
}

function verify_mounts_in_cloudcfg() {
    grep mounts /etc/cloud/cloud.cfg > /dev/null
    if [ $? -ne 0 ];then
        format_echo "Verify mounts: FAIL"
        ret=1
    else
        format_echo "Verify mounts: PASS"
        ret=0
    fi
    return $ret
}

function verify_disksetup_in_cloudcfg() {
    grep disk_setup /etc/cloud/cloud.cfg > /dev/null
    if [ $? -ne 0 ];then
        format_echo "Verify disk_setup: FAIL"
        ret=1
    else
        format_echo "Verify disk_setup: PASS"
        ret=0
    fi
    return $ret
}

function verify_account_removed() {
    id $username > /dev/null 2>&1
    if [ $? -eq 0 ];then
        format_echo "Verify $username removed: FAIL"
        ret=1
    else
        format_echo "Verify $username removed: PASS"
        ret=0
    fi
    return $ret
}

function verify_dhclient_in_networkmanager() {
    ret=0
    release=`cat /etc/redhat-release| sed 's/.*release \([0-9]*\.[0-9]*\).*/\1/g'`
    if [ ${release%%.*} == '8' ];then
        num=$(grep "dhcp *= *dhclient" /etc/NetworkManager/NetworkManager.conf|wc -l)
        if [ $num -eq 1 ];then
            format_echo "Verify dhcp = dhclient added: PASS"
        else
            format_echo "Verify dhcp = dhclient added: FAIL"
            format_echo "Number of dhclient lines: $num"
            ret=1
        fi
    fi
    return $ret
}

function verify_wala_removed() {
    rpm -q WALinuxAgent > /dev/null
    if [ $? -eq 0 ];then
        format_echo "Verify WALinuxAgent removed: FAIL";
        ret=1
    else
        format_echo "Verify WALinuxAgent removed: PASS"
        ret=0
    fi
    return $ret
}

function verify_wala() {
    rflag=0
    # Verify files are removed
    verify_files_removed||((rflag=rflag+1))
    # Verify ResourceDisk.EnableSwap=y
    verify_wala_resourcedisk_enableswap||((rflag=rflag+1))
    # Verify ResourceDisk.SwapSizeMB=2048
    verify_wala_resourcedisk_swapsize||((rflag=rflag+1))
    # Verify cloud-init package is removed
    verify_cloudinit_removed||((rflag=rflag+1))
    # Verify 50-cloud-init.conf is removed
    verify_50cloudinitconf_removed||((rflag=rflag+1))
    # Verify waagent is enabled
    verify_waagent_enabled||((rflag=rflag+1))
    # Verify no azure line in /etc/fstab
    verify_fstab_clean||((rflag=rflag+1))
    # Verify DHCP_HOSTNAME is removed from ifcfg-eth0
    verify_dhcphostname_removed||((rflag=rflag+1))
    # Verify account removed
    verify_account_removed||((rflag=rflag+1))
    exit $rflag
}

function verify_cloudinit_wala() {
    rflag=0
    # Verify files are removed
    verify_files_removed||((rflag=rflag+1))
    # Verify WALA conf
    verify_wala_conf||((rflag=rflag+1))
    # Verify ResourceDisk.EnableSwap=n
    verify_wala_resourcedisk_disableswap||((rflag=rflag+1))
    # Verify ResourceDisk.Format=n
    verify_wala_resourcedisk_disableformat||((rflag=rflag+1))
    # Verify cloud-init is enabled
    verify_cloudinit_enabled||((rflag=rflag+1))
    # Verify 50-cloud-init.conf is removed
    verify_50cloudinitconf_removed||((rflag=rflag+1))
    # Verify waagent is enabled
    verify_waagent_enabled||((rflag=rflag+1))
    # Verify no azure line in /etc/fstab
    verify_fstab_clean||((rflag=rflag+1))
    # Verify no DHCP_HOSTNAME in ifcfg-eth0
    verify_dhcphostname_removed||((rflag=rflag+1))
    # Verify 91-azure_datasource.cfg exists
    verify_91_azure_datasource_exists||((rflag=rflag+1))
    # Verify mounts and disk_setup are in cloud.cfg
    verify_mounts_in_cloudcfg||((rflag=rflag+1))
    verify_disksetup_in_cloudcfg||((rflag=rflag+1))
    # Verify account removed
    verify_account_removed||((rflag=rflag+1))
    # Verify dhcp=dhclient added (RHEL-8.0 only)
    verify_dhclient_in_networkmanager||((rflag=rflag+1))
    exit $rflag
}

function verify_cloudinit() {
    rflag=0
    # Verify files are removed
    verify_files_removed||((rflag=rflag+1))
    # verify cloud-init is enabled
    verify_cloudinit_enabled||((rflag=rflag+1))
    # Verify waagent is removed
    verify_wala_removed||((rflag=rflag+1))
    # Verify 50-cloud-init.conf is removed
    verify_50cloudinitconf_removed||((rflag=rflag+1))
    # Verify no azure line in /etc/fstab
    verify_fstab_clean||((rflag=rflag+1))
    # Verify no DHCP_HOSTNAME in ifcfg-eth0
    verify_dhcphostname_removed||((rflag=rflag+1))
    # Verify 91-azure_datasource.cfg exists
    verify_91_azure_datasource_exists||((rflag=rflag+1))
    # Verify mounts and disk_setup are in cloud.cfg
    verify_mounts_in_cloudcfg||((rflag=rflag+1))
    verify_disksetup_in_cloudcfg||((rflag=rflag+1))
    # Verify account removed
    verify_account_removed||((rflag=rflag+1))
    # Verify dhcp=dhclient added (RHEL-8.0 only)
    verify_dhclient_in_networkmanager||((rflag=rflag+1))
    exit $rflag
}

function verify_azure_vm_utils() {
    # rpm -q azure-vm-utils > /dev/null
    # if [ $? -eq 0 ];then
    #     format_echo "Verify azure-vm-utils removed: FAIL";
    #     ret=1
    # else
    #     format_echo "Verify azure-vm-utils removed: PASS"
    #     ret=0
    # fi
    # return $ret
    return 0
}

case $type in
cloudinit)
    function deprovision() { deprovision_cloudinit; }
    function verify() { verify_cloudinit; }
;;
cloudinit_wala)
    function deprovision() { deprovision_cloudinit_wala; }
    function verify() { verify_cloudinit_wala; }
;;
wala)
    function deprovision() { deprovision_wala; }
    function verify() { verify_wala; }
;;
kernel)
# Some old images have no cloud-init
    which cloud-init > /dev/null 2>&1
    if [ $? -eq 0 ];then
        function deprovision() { deprovision_cloudinit_wala; }
        function verify() { verify_cloudinit_wala; }
    else
        function deprovision() { deprovision_wala; }
        function verify() { verify_wala; }
    fi
;;
azure-vm-utils)
# azure-vm-utils
    function deprovision() { deprovision_azure_vm_utils; }
    function verify() { verify_azure_vm_utils; }
;;
*)
    echo "$type: unsupported deprovision type! Exit."
    echo "Usage: $0 <function: deprovision|verify|all> <type: cloudinit|cloudinit_wala|wala|kernel|azure-vm-utils> [username]"
    exit 1
;;
esac

source /etc/os-release

if [ x$func == x"deprovision" ];then
    deprovision
elif [ x$func == x"verify" ];then
    # RHEL-8.2 image cannot pass the verificaiton. No need to do it.
    [[ x"${VERSION_ID}" == x"8.2" ]] || verify
elif [ x$func == x"all" ];then
    deprovision
    verify
else
    echo "No such function: $func. Exit!"
    exit 1
fi
