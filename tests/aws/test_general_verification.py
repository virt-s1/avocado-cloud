from avocado import Test
from avocado_cloud.app.aws import aws
from avocado_cloud.utils import utils_lib
import re
import time
import math
import decimal


class GeneralVerification(Test):
    '''
    :avocado: tags=generalverify,acceptance,fulltest
    '''
    def _check_boot_time(self, max_boot_time):

        self.session.connect(timeout=self.ssh_wait_timeout)
        utils_lib.run_cmd(self, "sudo which systemd-analyze", expect_ret=0)
        time_start = int(time.time())
        while True:
            output = utils_lib.run_cmd(self, "sudo systemd-analyze ")
            if 'Bootup is not yet finished' not in output:
                break
            time_end = int(time.time())
            utils_lib.run_cmd(self, 'sudo systemctl list-jobs')
            if time_end - time_start > 60:
                self.fail("Bootup is not yet finished after 60s")
            self.log.info("Wait for bootup finish......")
            time.sleep(1)

        cmd = "sudo systemd-analyze blame > /tmp/blame.log"
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        utils_lib.run_cmd(self, "cat /tmp/blame.log", expect_ret=0)
        output = utils_lib.run_cmd(self, "sudo systemd-analyze", expect_ret=0)
        boot_time = re.findall("=.*s", output)[0]
        boot_time = boot_time.strip("=\n")
        boot_time_sec = re.findall('[0-9.]+s', boot_time)[0]
        boot_time_sec = boot_time_sec.strip('= s')
        if 'min' in boot_time:
            boot_time_min = re.findall('[0-9]+min', boot_time)[0]
            boot_time_min = boot_time_min.strip('min')
            boot_time_sec = int(boot_time_min) * 60 + int(boot_time_sec)
        self.log.info(
            "Boot time is %s(s), less than max_boot_time %s in cfg file! " %
            (boot_time_sec, max_boot_time))
        self.assertLessEqual(float(boot_time_sec),
                             max_boot_time,
                             msg='Boot time over %s(s)' % max_boot_time)

    def setUp(self):
        self.session = None
        self.vm = None
        self.ssh_wait_timeout = None
        aws.init_test(self)

    def test_check_gpgkey(self):
        '''
        :avocado: tags=test_check_gpgkey,fast_check
        polarion_id: RHEL7-103849
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        utils_lib.run_cmd(self,
                    r"sudo cat /etc/redhat-release",
                    expect_ret=0,
                    cancel_not_kw="Beta",
                    msg="Only run in GA release version, pre-ga always \
has some pkg not signed")
        check_cmd = r"rpm -qa --qf \
            '%{name}-%{version}-%{release}.%{arch} (%{SIGPGP:pgpsig})\n'\
            |grep -v 'Key ID'|grep -v gpg-pubkey|grep -v ltp"

        self.session.cmd_output('\n')
        utils_lib.run_cmd(self, check_cmd, expect_not_ret=0)

    def test_check_timezone(self):
        '''
        :avocado: tags=test_check_timezone,fast_check
        polarion_id: RHEL7-103856
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        utils_lib.run_cmd(self, 'date', expect_ret=0,
                    expect_kw='UTC',
                    msg='Check timezone is UTC.')

    def test_check_virtwhat(self):
        '''
        :avocado: tags=test_check_virtwhat,fast_check,kernel_tier1
        polarion_id: RHEL7-103857
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        utils_lib.run_cmd(self, r'sudo yum install -y virt-what')
        virt_what_output = utils_lib.run_cmd(self, r"sudo virt-what", expect_ret=0)
        lscpu_output = utils_lib.run_cmd(self, 'lscpu', expect_ret=0)
        if 'Xen' in lscpu_output:
            self.log.info("Found it is a xen system!")
            if 'full' in lscpu_output:
                self.assertIn('xen-hvm', virt_what_output)
            else:
                self.assertIn('xen-domU', virt_what_output)
        elif 'KVM' in lscpu_output:
            self.log.info("Found it is a kvm system!")
            self.assertIn('kvm', virt_what_output)
        else:
            self.log.info("Found it is a bare metal system!")

    def test_xenfs_mount(self):
        '''
        :avocado: tags=test_xenfs_mount,fast_check
        polarion_id:
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)

        utils_lib.run_cmd(self,
                    'sudo lscpu',
                    expect_ret=0,
                    cancel_kw="Xen",
                    msg="Only run in xen instance")

        utils_lib.run_cmd(self, r'sudo mount -t xenfs xenfs /proc/xen/', expect_ret=0)
        utils_lib.run_cmd(self,
                    'sudo ls /proc/xen',
                    expect_ret=0,
                    expect_kw='capabilities  privcmd  xenbus')

    def test_xe_guest_utilities(self):
        '''
        :avocado: tags=test_xe_guest_utilities,fast_check
        polarion_id:
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)

        utils_lib.run_cmd(self,
                    'lscpu',
                    expect_ret=0,
                    cancel_kw="Xen",
                    msg="Only run in xen instance")

        utils_lib.run_cmd(self, 'sudo su', expect_ret=0)
        aws.install_pkgs(self.session, 'wget')
        cmd = 'sudo wget https://kojipkgs.fedoraproject.org//packages/\
xe-guest-utilities/7.12.0/1.fc29/x86_64/xe-guest-utilities-7.12.0-1.fc29.\
x86_64.rpm'

        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = 'yum localinstall -y xe-guest-utilities-7.12.0-1.fc29.x86_64.rpm'
        utils_lib.run_cmd(self, cmd)
        cmd = 'rpm -ivh xe-guest-utilities-7.12.0-1.fc29.x86_64.rpm --force \
--nodeps'

        utils_lib.run_cmd(self, cmd)
        xenstore_read = '/usr/libexec/xe-guest-utilities/xenstore-read'
        utils_lib.run_cmd(self, "%s domid" % xenstore_read, expect_ret=0)
        cmd = "%s name" % xenstore_read
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = "%s memory/target" % xenstore_read
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        if 'vif' in utils_lib.run_cmd(self, 'ethtool -i eth0', expect_ret=0):
            cmd = "%s device/vif/0/mac" % xenstore_read
            utils_lib.run_cmd(self, cmd, expect_ret=0)

        xenstore_list = '/usr/libexec/xe-guest-utilities/xenstore-list'
        utils_lib.run_cmd(self, "%s device" % xenstore_list, expect_ret=0)
        utils_lib.run_cmd(self, "%s control" % xenstore_list, expect_ret=0)

    def test_xenfs_write_inability(self):
        '''
        :avocado: tags=test_xenfs_write_inability,fast_check
        polarion_id:
        BZ# 1663266
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)

        utils_lib.run_cmd(self,
                    'lscpu',
                    expect_ret=0,
                    cancel_kw="Xen",
                    msg="Only run in xen instance")

        utils_lib.run_cmd(self, 'sudo umount /proc/xen')
        cmd = r'sudo mount -t xenfs xenfs /proc/xen/'
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        utils_lib.run_cmd(self, 'sudo su', expect_ret=0)
        script_str = '''
#!/usr/bin/env python

import os
import struct

if __name__ == "__main__":
    fd = os.open("/proc/xen/xenbus", os.O_RDWR)
    # end a fake transaction
    os.write(fd, struct.pack("<IIII", 7, 2, 1234, 0))
        '''
        utils_lib.run_cmd(self, "echo '%s' > t.py" % script_str, expect_ret=0)
        utils_lib.run_cmd(self, 'sudo python3 t.py')
        utils_lib.run_cmd(self, "dmesg", expect_not_kw='Call Trace')

    def test_check_dmesg_error(self):
        '''
        :avocado: tags=test_check_dmesg_error,fast_check
        polarion_id: RHEL7-103851
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        aws.check_dmesg(self, 'error')

    def test_check_dmesg_fail(self):
        '''
        :avocado: tags=test_check_dmesg_fail,fast_check
        polarion_id: RHEL7-103851
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        aws.check_dmesg(self, 'fail')

    def test_check_dmesg_warn(self):
        '''
        :avocado: tags=test_check_dmesg_warn,fast_check
        polarion_id: RHEL7-103851
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        aws.check_dmesg(self, 'warn')

    def test_check_dmesg_calltrace(self):
        '''
        :avocado: tags=test_check_dmesg_calltrace,fast_check,kernel_tier1
        polarion_id: RHEL7-103851
        bz#: 1777179
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        utils_lib.run_cmd(self, 'dmesg', expect_ret=0, expect_not_kw='Call Trace')

    def test_check_dmesg_unknownsymbol(self):
        '''
        :avocado: tags=test_check_dmesg_unknownsymbol,fast_check,kernel_tier1
        polarion_id:
        bz#: 1649215
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        utils_lib.run_cmd(self,
                    'dmesg',
                    expect_ret=0,
                    expect_not_kw='Unknown symbol',
                    msg='Check there is no Unknown symbol')

    def test_check_dmesg_unable(self):
        '''
        :avocado: tags=test_check_dmesg_unable,fast_check
        polarion_id:
        bz#: 1779454
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        utils_lib.run_cmd(self, 'dmesg', expect_ret=0, expect_not_kw='unable')

    def test_check_journalctl_traceback(self):
        '''
        :avocado: tags=test_check_journalctl_traceback,fast_check
        polarion_id:
        bz#: 1801999, 1736818
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        # redirect journalctl output to a file as it is not get return
        # normally in RHEL7
        cmd = 'journalctl > /tmp/journalctl.log'
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = 'cat /tmp/journalctl.log'
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='Traceback,Backtrace')

    def test_check_journalctl_dumpedcore(self):
        '''
        :avocado: tags=test_check_journalctl_dumpedcore,fast_check
        polarion_id:
        bz#: 1797973
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        # redirect journalctl output to a file as it is not get return
        # normally in RHEL7
        cmd = 'journalctl > /tmp/journalctl.log'
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = 'cat /tmp/journalctl.log'
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='dumped core')

    def test_check_journalctl_invalid(self):
        '''
        :avocado: tags=test_check_journalctl_invalid,fast_check
        polarion_id:
        BZ#:1750417
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        # redirect journalctl output to a file as it is not get return
        # normally in RHEL7
        # skip sshd to filter out invalid user message
        cmd = 'journalctl|grep -v sshd|grep -v MTU > /tmp/journalctl.log'
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = 'cat /tmp/journalctl.log'
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='invalid,Invalid')

    def test_check_modload(self):
        '''
        :avocado: tags=test_check_modload,fast_check
        polarion_id:
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        utils_lib.run_cmd(self, 'lsmod', expect_ret=0)

    def test_check_console_log(self):
        '''
        :avocado: tags=test_check_console_log
        this case only confirm whether can get console log normally.
        do not check its content as done in dmesg check, focus on function
        support
        polarion_id: RHEL-117929
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        # as console log may not appear imediately, so wait maximum 600s
        time_start = int(time.time())
        while True:
            time.sleep(20)
            status, output = self.vm.get_console_log()
            if output and status:
                break
            time_end = int(time.time())
            if time_end - time_start > 600:
                self.fail("Console log is emtpy after 600s, exit!")
                break
            self.log.info("Console log is empty, wait for 20s to check again")

        if status:
            if len(output) < 1000:
                self.fail(
                    "Please check console log, too few characters!\n %s" %
                    output)
            else:
                self.log.info(
                    "Can get console log successfully, you may need check \
content manually!\n %s" % output)
        else:
            self.fail(output)

    def test_check_release_name(self):
        '''
        :avocado: tags=test_check_release_name,fast_check
        check /etc/redhat-release have the correct name
        polarion_id: RHEL7-103850
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        check_cmd = r"sudo cat /etc/redhat-release"
        self.log.info("Check release name cmd: %s" % check_cmd)
        output = utils_lib.run_cmd(self,check_cmd, expect_ret=0)
        kernel_ver = utils_lib.run_cmd(self, 'uname -r', msg="Get kernel version")
        if '2.6.32' in kernel_ver:
            self.assertIn(
                'Red Hat Enterprise Linux Server release 6',
                output,
                msg="It should be like: Red Hat Enterprise Linux \
Server release 6.n\n but it is %s" % output)
        elif '3.10.0' in kernel_ver:
            self.assertIn(
                'Red Hat Enterprise Linux Server release 7',
                output,
                msg="It should be like: Red Hat Enterprise Linux \
Server release 7.n\n but it is %s" % output)
        elif 'el8' in kernel_ver:
            self.assertIn(
                'Red Hat Enterprise Linux release 8',
                output,
                msg="It should be like: Red Hat Enterprise Linux \
release 8.n\n but it is %s" % output)
        self.log.info("Check PASS: %s" % output)

    def test_check_vulnerabilities(self):
        '''
        :avocado: tags=test_check_vulnerabilities,fast_check
        polarion_id: N/A
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        # utils_lib.run_cmd(self, 'lscpu', expect_ret=0,cancel_not_kw="aarch64",
        #     msg="Not run in arm instance")

        utils_lib.run_cmd(self, "rpm -qa|grep microcode", msg='Get microcode version')
        check_cmd = r"sudo grep . /sys/devices/system/cpu/vulnerabilities/* | \
sed 's/:/^/' | column -t -s^"

        utils_lib.run_cmd(self, check_cmd, expect_ret=0)
        # utils_lib.run_cmd(self, check_cmd, expect_ret=0,
        #     expect_not_kw='Vulnerable')
        self.log.info('All ec2 instances has "spec_store_bypass Vulnerable", \
so skip it currently')
        output = utils_lib.run_cmd(self, 'uname -r', expect_ret=0)
        if 'metal' in self.vm.instance_type:
            self.log.info(
                "Bare metal instance should not have any vulnerable.")
            cmd = r"sudo grep . /sys/devices/system/cpu/vulnerabilities/* | \
sed 's/:/^/' | column -t -s^"

        elif 'el7' in output:
            self.log.info(
                "Skip spec_store_bypass,Retpoline and mds in RHEL7 vms")
            check_cmd = r"sudo grep . /sys/devices/system/cpu/vulnerabilities\
/* |grep -v spec_store_bypass|grep -v 'tsx_async_abort'|grep -v 'Vulnerable: \
Retpoline'|grep -v mds| sed 's/:/^/' | column -t -s^"

        else:
            self.log.info(
                "Skip spec_store_bypass and mds,itlb_multihit in vms")
            check_cmd = r"sudo grep . /sys/devices/system/cpu/vulnerabilities\
/* |grep -v spec_store_bypass|grep -v 'tsx_async_abort'|grep -v mds|grep -v \
itlb_multihit|sed 's/:/^/' | column -t -s^"

        utils_lib.run_cmd(self, check_cmd, expect_ret=0, expect_not_kw='Vulnerable')

    def test_check_avclog(self):
        '''
        :avocado: tags=test_check_avclog,fast_check,kernel_tier1
        polarion_id: N/A
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        cmd = "sudo ausearch -m AVC -ts today"
        utils_lib.run_cmd(self, cmd, expect_not_ret=0, msg='Checking avc log!')

    def test_check_avclog_nfs(self):
        '''
        :avocado: tags=test_check_avclog_nfs,fast_check
        polarion_id: N/A
        '''
        self.log.info("Check no permission denied at nfs server - bug1655493")

        self.session.connect(timeout=self.ssh_wait_timeout)
        cmd = 'sudo yum install -y nfs-utils'
        utils_lib.run_cmd(self, cmd, msg='Install nfs-utils')
        output = utils_lib.run_cmd(self, 'uname -r', expect_ret=0)

        if 'el7' in output or 'el6' in output:
            cmd = "sudo systemctl start nfs"
        else:
            cmd = 'sudo systemctl start nfs-server.service'

        utils_lib.run_cmd(self, cmd, expect_ret=0)
        utils_lib.run_cmd(self, "sudo mkdir /tmp/testrw")
        cmd = "sudo chmod -R 777 /tmp/testrw"
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = "sudo exportfs -o rw,insecure_locks,all_squash,fsid=1 \
*:/tmp/testrw"

        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = "sudo mount -t nfs 127.0.0.1:/tmp/testrw /mnt"
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        utils_lib.run_cmd(self, "sudo umount /mnt")

        cmd = "sudo ausearch -m AVC -ts today"
        utils_lib.run_cmd(self, cmd, expect_not_ret=0, msg='Checking avc log!')

    def test_check_nouveau(self):
        '''
        :avocado: tags=test_check_nouveau,fast_check
        polarion_id: N/A
        '''
        self.log.info("nouveau is not required in ec2, make sure it is \
in blacklist and not loaded bug1645772")
        self.session.connect(timeout=self.ssh_wait_timeout)
        utils_lib.run_cmd(self,
                    "sudo lsmod",
                    expect_ret=0,
                    expect_not_kw="nouveau",
                    msg="Checking lsmod")
        utils_lib.run_cmd(self,
                    "sudo cat /proc/cmdline",
                    expect_ret=0,
                    expect_kw="rd.blacklist=nouveau",
                    msg="Checking cmdline")

    def test_check_nvme_io_timeout(self):
        '''
        :avocado: tags=test_check_nvme_io_timeout,fast_check
        polarion_id: N/A
        bz#: 1859088
        '''
        self.log.info("nvme_core.io_timeout=4294967295 is recommended in ec2, make sure it is \
in cmdline as bug1859088")
        self.session.connect(timeout=self.ssh_wait_timeout)
        utils_lib.run_cmd(self,
                    "sudo cat /sys/module/nvme_core/parameters/io_timeout",
                    msg="Checking actual value")
        utils_lib.run_cmd(self,
                    "sudo cat /proc/cmdline",
                    expect_ret=0,
                    expect_kw="nvme_core.io_timeout=4294967295",
                    msg="Checking cmdline")

    def test_check_secure_ioerror(self):
        '''
        :avocado: tags=test_check_secure_ioerror,fast_check
        polarion_id: N/A
        bz#: 1103344
        description:
        https://access.redhat.com/solutions/975803
        Check there is no io error in /var/log/secure
        '''
        self.log.info("Check /var/log/secure")
        self.session.connect(timeout=self.ssh_wait_timeout)
        utils_lib.run_cmd(self, "sudo cat /var/log/secure", expect_ret=0)
        utils_lib.run_cmd(self, "sudo cp /var/log/secure /tmp", expect_ret=0)
        utils_lib.run_cmd(self, "sudo cat  /var/log/secure", expect_not_kw="Input/output error")

    def test_check_rngd(self):
        '''
        :avocado: tags=test_check_rngd,fast_check
        polarion_id: N/A
        '''
        self.log.info("check rngd service is enabled in RHEL8, not required \
in RHEL7|6, bug1625874")
        self.session.connect(timeout=self.ssh_wait_timeout)
        output = utils_lib.run_cmd(self, "uname -r", expect_ret=0)
        if 'el8' in output:
            utils_lib.run_cmd(self,
                        'sudo systemctl status rngd',
                        expect_kw='active (running)',
                        msg="Checking rngd service")
        else:
            utils_lib.run_cmd(self,
                        'sudo systemctl status rngd',
                        expect_not_ret=0,
                        msg="Checking rngd service")

    def test_check_service(self):
        '''
        :avocado: tags=test_check_service,fast_check,kernel_tier1
        polarion_id: N/A
        bz#: 1740443
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        utils_lib.run_cmd(self, "sudo systemctl>/tmp/systemctl.log", expect_ret=0)
        cmd = "cat /tmp/systemctl.log|grep -v dnf-makecache"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='failed')

    def test_check_cpupower(self):
        '''
        :avocado: tags=test_check_cpupower,fast_check,kernel_tier1
        No exception when run cpupower command
        polarion_id: N/A
        bz#: 1626505, 1659883
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        cmd = "sudo cpupower info"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='core dumped')
        cmd = "sudo cpupower idle-info"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='core dumped')
        cmd = "sudo cpupower frequency-info"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='core dumped')

    def test_check_pkgs_list(self):
        '''
        :avocado: tags=test_check_pkgs_list,fast_check
        polarion_id: N/A
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        utils_lib.run_cmd(self, "sudo rpm -qa", expect_ret=0)

    def test_check_firstlaunch_time(self):
        '''
        :avocado: tags=test_check_firstlaunch_time,fast_check
        polarion_id:
        bz#: 1862930
        '''
        max_boot_time = self.params.get('max_boot_time')
        self._check_boot_time(max_boot_time)

    def test_check_boot_time(self):
        '''
        :avocado: tags=test_check_boot_time,fast_check
        polarion_id: RHEL7-93100
        bz#: 1776710
        '''
        max_boot_time = self.params.get('max_boot_time')
        self._check_boot_time(max_boot_time)

    def test_check_reboot_time(self):
        '''
        :avocado: tags=test_check_reboot_time,fast_check
        polarion_id: RHEL7-93100
        '''
        self.vm.reboot()
        if 'metal' in self.vm.instance_type:
            self.log.info("Wait %s" % self.ssh_wait_timeout)
            time.sleep(self.ssh_wait_timeout)
        else:
            self.log.info("Wait 30s")
            time.sleep(30)
        max_boot_time = self.params.get('max_reboot_time')
        self._check_boot_time(max_boot_time)

    def test_check_available_clocksource(self):
        '''
        :avocado: tags=test_check_available_clocksource,fast_check,kernel_tier1
        polarion_id:
        bz#: 1726487
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        output = utils_lib.run_cmd(self, 'lscpu', expect_ret=0)
        if 'Xen' in output:
            expect_clocks = 'xen,tsc,hpet,acpi_pm'
        elif 'aarch64' in output:
            expect_clocks = 'arch_sys_counter'
        elif 'AuthenticAMD' in output and 'KVM' in output:
            expect_clocks = 'kvm-clock,tsc,acpi_pm'
        elif 'GenuineIntel' in output and 'KVM' in output:
            expect_clocks = 'kvm-clock,tsc,acpi_pm'
        else:
            expect_clocks = 'tsc,hpet,acpi_pm'

        cmd = 'sudo cat /sys/devices/system/clocksource/clocksource0/\
available_clocksource'
        utils_lib.run_cmd(self,
                    cmd,
                    expect_ret=0,
                    expect_kw=expect_clocks,
                    msg='Checking available clocksource')

    def test_change_clocksource(self):
        '''
        :avocado: tags=test_change_clocksource,fast_check
        polarion_id:
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        output = utils_lib.run_cmd(self, 'lscpu', expect_ret=0)
        cmd = 'sudo cat /sys/devices/system/clocksource/clocksource0/\
current_clocksource'

        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Check current clock source')
        cmd = 'sudo cat /sys/devices/system/clocksource/clocksource0/\
available_clocksource'

        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        utils_lib.run_cmd(self, 'sudo su', expect_ret=0)
        for clocksource in output.split(' '):
            cmd = 'echo %s > /sys/devices/system/clocksource/clocksource0/\
current_clocksource' % clocksource
            utils_lib.run_cmd(self,
                        cmd,
                        expect_ret=0,
                        msg='Change clocksource to %s' % clocksource)
            cmd = 'cat /sys/devices/system/clocksource/clocksource0/\
current_clocksource'

            utils_lib.run_cmd(self,
                        cmd,
                        expect_kw=clocksource,
                        msg='Check current clock source')
        utils_lib.run_cmd(self, 'dmesg|tail -30', expect_ret=0)

    def test_change_tracer(self):
        '''
        :avocado: tags=test_change_tracer,fast_check
        no hang happen
        polarion_id:
        bz#: 1650273
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        cmd = 'sudo mount -t debugfs nodev /sys/kernel/debug'
        utils_lib.run_cmd(self, cmd, msg='mount debugfs')

        cmd = 'sudo cat /sys/kernel/debug/tracing/current_tracer'
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='Check current tracer')
        cmd = 'sudo cat /sys/kernel/debug/tracing/available_tracers'

        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        utils_lib.run_cmd(self, 'sudo su', expect_ret=0)
        for tracer in output.split(' '):
            cmd = 'echo %s > /sys/kernel/debug/tracing/current_tracer' % tracer
            utils_lib.run_cmd(self,
                        cmd,
                        expect_ret=0,
                        msg='Change tracer to %s' % tracer)
            cmd = 'sudo cat /sys/kernel/debug/tracing/current_tracer'

            utils_lib.run_cmd(self,
                        cmd,
                        expect_kw=tracer,
                        msg='Check current tracer')
        utils_lib.run_cmd(self, 'dmesg|tail -30', expect_ret=0)

    def test_check_tsc_deadline_timer(self):
        '''
        :avocado: tags=test_check_tsc_deadline_timer,fast_check
        polarion_id: RHEL7-111006
        des: check TSC deadline timer enabled in dmesg
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        utils_lib.run_cmd(self,
                    'lscpu',
                    expect_ret=0,
                    cancel_not_kw="Xen,aarch64,AuthenticAMD")

        cmd = "grep tsc_deadline_timer /proc/cpuinfo"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='tsc_deadline_timer')
        cmd = "dmesg|grep 'TSC deadline timer enabled'"
        utils_lib.run_cmd(self, cmd, expect_ret=0)

        cmd = "sudo cat /sys/devices/system/clockevents/clockevent0/\
current_device"

        utils_lib.run_cmd(self,
                    cmd,
                    expect_ret=0,
                    expect_kw='lapic-deadline',
                    msg='Check guest timer')

    def test_check_timedrift_reboot(self):
        '''
        :avocado: tags=test_check_timedrift_reboot
        After 3 times reboot, if the average drift time over 1 seconds,
        we are considering it as fail.
        polarion_id: RHEL7-110672
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        utils_lib.run_cmd(self,
                    "sudo cat /etc/redhat-release",
                    expect_ret=0,
                    cancel_kw="release 7,release 6",
                    msg="Only run in RHEL7 and RHEL6")
        utils_lib.run_cmd(self, "sudo systemctl stop ntpd")
        utils_lib.run_cmd(self, "sudo systemctl disable ntpd")
        utils_lib.run_cmd(self, "sudo systemctl stop chronyd")
        utils_lib.run_cmd(self, "sudo systemctl disable chronyd")
        utils_lib.run_cmd(self, "sudo timedatectl set-ntp 0")

        offset1 = aws.get_drift(self)
        self.vm.reboot()
        self.session.connect(timeout=self.ssh_wait_timeout)
        offset2 = aws.get_drift(self)
        self.vm.reboot()
        self.session.connect(timeout=self.ssh_wait_timeout)
        offset3 = aws.get_drift(self)
        self.vm.reboot()
        self.session.connect(timeout=self.ssh_wait_timeout)
        offset4 = aws.get_drift(self)
        x = decimal.Decimal(offset2) - decimal.Decimal(offset1)
        y = decimal.Decimal(offset3) - decimal.Decimal(offset1)
        z = decimal.Decimal(offset4) - decimal.Decimal(offset1)
        drift = math.fabs(x) * 10 + math.fabs(y) * 10 + math.fabs(z) * 10
        self.assertLess(drift, 30, msg="Drift is over 1 seconds")
        self.log.info("Average drift is less than 1 seconds. %d/30" % drift)

    def test_check_timedrift_stress(self):
        '''
        :avocado: tags=test_check_timedrift_stress
        After 120 seconds stress test, if the average drift time over 1
        seconds, we are considering it as fail.
        polarion_id: RHEL7-110673
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        utils_lib.run_cmd(self,
                    r"sudo cat /etc/redhat-release",
                    expect_ret=0,
                    cancel_kw="release 7,release 6",
                    msg="Only run in RHEL7 and RHEL6")

        utils_lib.run_cmd(self, "sudo systemctl stop ntpd")
        utils_lib.run_cmd(self, "sudo systemctl disable ntpd")
        utils_lib.run_cmd(self, "sudo systemctl stop chronyd")
        utils_lib.run_cmd(self, "sudo systemctl disable chronyd")
        utils_lib.run_cmd(self, "sudo timedatectl set-ntp 0")
        offset1 = aws.get_drift(self)
        stress_url = self.params.get('stress_url')
        aws.install_pkgs(self.session, stress_url)
        cpu_count = utils_lib.run_cmd(
            self, 'cat /proc/cpuinfo |grep -i "model name"|wc -l')
        utils_lib.run_cmd(self, "stress -c %s -t 120" % cpu_count, timeout=160)
        offset2 = aws.get_drift(self)

        x = decimal.Decimal(offset2) - decimal.Decimal(offset1)
        drift = math.fabs(x) * 10
        self.assertLess(drift, 10, msg="Drift is over 1 seconds")
        self.log.info("Average drift is less than 1 seconfs. %d/10" % drift)

    def test_check_microcode_load(self):
        '''
        :avocado: tags=test_check_microcode_load,fast_check
        For bug 1607899, RHEL should not update microcode inside VMs.
        This case checks it from dmesg output.
        polarion_id: N/A
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        lscpu_output = utils_lib.run_cmd(self, 'lscpu', expect_ret=0)
        utils_lib.run_cmd(self,
                    'lscpu',
                    expect_ret=0,
                    cancel_not_kw="aarch64,AMD",
                    msg="Only run in intel platform")
        cmd = 'rpm -qa|grep microcode'
        utils_lib.run_cmd(self, cmd)
        cmd = 'dmesg|grep microcode|grep -v "no microcode"'
        if 'Xen' in lscpu_output or 'KVM' in lscpu_output:
            utils_lib.run_cmd(self,
                        cmd,
                        expect_not_ret=0,
                        msg='microcode should not load in VMs')
        else:
            utils_lib.run_cmd(self,
                        cmd,
                        expect_ret=0,
                        msg='microcode should load in bare metals')

    def test_check_cpu_count(self):
        '''
        :avocado: tags=test_check_cpu_count,fast_check,kernel_tier1
        polarion_id: N/A
        '''
        expect_cpus = self.params.get('cpu', '*/instance_types/*')
        utils_lib.run_cmd(self, 'lscpu', expect_ret=0)
        utils_lib.run_cmd(self,
                    'cat /proc/cpuinfo |grep processor|wc -l',
                    expect_ret=0,
                    expect_output=str(expect_cpus),
                    msg='online cpu check')

    def test_check_mem_size(self):
        '''
        :avocado: tags=test_check_mem_size,fast_check
        if memory in guest less than 5% than assigned, fail it.
        polarion_id: N/A
        '''
        expect_mem = self.params.get('memory', '*/instance_types/*')
        allow_ratio = 10
        output = utils_lib.run_cmd(self, 'sudo kdumpctl showmem')
        if output == '':
            reserved = 0
        else:
            try:
                reserved = re.findall('[0-9]+MB', output)[0].rstrip('MB')
                self.log.info('kdump reserved %s' % reserved)
            except Exception as err:
                self.log.info('Unable to get kdump saved mem size!')
                reserved = 0
        utils_lib.run_cmd(self, 'sudo cat /proc/meminfo', expect_ret=0)
        cmd = ' grep MemTotal /proc/meminfo'
        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        mem_in_kb = int(re.findall('[0-9]+', output)[0]) + int(reserved) * 1024
        expect_in_kb = expect_mem * 1024 * 1024

        miss_ratio = (expect_in_kb -
                      int(mem_in_kb)) / float(expect_in_kb) * 100
        self.assertGreaterEqual(allow_ratio,
                                miss_ratio,
                                msg=r'Memory less than 5% in guest')
        self.log.info("Expected: %s, Actual %s, Allow ration: %s" %
                      (expect_in_kb, mem_in_kb, allow_ratio))

    def test_check_memleaks(self):
        '''
        :avocado: tags=test_check_memleaks
        polarion_id: RHEL-117648
        '''
        self.log.info("Check memory leaks")
        self.session.connect(timeout=self.ssh_wait_timeout)
        utils_lib.run_cmd(self,
                    'uname -a',
                    expect_ret=0,
                    cancel_kw="debug",
                    msg="Only run in debug kernel")
        utils_lib.run_cmd(self,
                    'cat /proc/cmdline',
                    expect_ret=0,
                    cancel_kw="kmemleak=on",
                    msg="Only run with kmemleak=on")

        utils_lib.run_cmd(self, 'sudo su', expect_ret=0)
        cmd = 'echo scan > /sys/kernel/debug/kmemleak'
        utils_lib.run_cmd(self, cmd, expect_ret=0, timeout=1800)

        cmd = 'cat /sys/kernel/debug/kmemleak'
        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        if len(output) > 0:
            self.fail('Memory leak found!')

    def test_collect_insights_result(self):
        '''
        :avocado: tags=test_collect_insights_result
        polarion_id:
        bz#:
        '''

        self.session.connect(timeout=self.ssh_wait_timeout)
        utils_lib.run_cmd(self,
                    'sudo insights-client --register',
                    msg="try to register system")
        utils_lib.run_cmd(self,
                    'sudo insights-client --status',
                    cancel_kw="System is registered",
                    msg="Check system register status")
        utils_lib.run_cmd(self,
                    'sudo insights-client --check-result',
                    expect_ret=0,
                    msg="checking system")
        utils_lib.run_cmd(self,
                    'sudo insights-client --show-result',
                    expect_ret=0,
                    msg="show insights result")


    def test_collect_log(self):
        '''
        :avocado: tags=test_collect_log
        polarion_id: N/A
        '''
        self.log.info("This case is only saving log for future check purpose")
        self.session.connect(timeout=self.ssh_wait_timeout)
        aws.check_cmd(self, cmd='wget')
        aws.check_cmd(self, cmd='tar')
        aws.check_cmd(self, cmd='unzip')
        virt_utils_url = "https://github.com/SCHEN2015/virt-utils/archive/\
master.zip"

        self.log.info("Download %s" % virt_utils_url)
        cmd = "wget %s ; unzip master.zip" % virt_utils_url
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = "virt-utils-master/vm_check/vm_check.sh"
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = "tar zcf vmlog.tar.gz workspace/log"
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        remote_path = "vmlog.tar.gz"
        local_path = "%s/%s_vmlog.tar.gz" % (self.job.logdir,
                                             self.vm.instance_type)
        self.log.info("Copy %s from guest to %s, please wait" %
                      (remote_path, local_path))
        self.session.copy_files_from(remote_path, local_path, timeout=600)


    def tearDown(self):
        if self.session.session.is_responsive(
        ) is not None and self.vm.is_started():
            aws.gcov_get(self)
            utils_lib.run_cmd(self, 'uname -r', msg='Get instance kernel version')
            self.session.close()
