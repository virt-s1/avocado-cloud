from avocado import Test
from avocado_cloud.app.aws import aws
from avocado_cloud.app import Setup
from avocado_cloud.utils import utils_lib
import re
import time
import math
import decimal
import json


class GeneralVerification(Test):
    '''
    :avocado: tags=generalverify,acceptance,fulltest,outposts
    '''
                            
    def setUp(self):
        self.session = None
        self.vm = None
        self.ssh_wait_timeout = None
        aws.init_test(self)
        self.session.connect(timeout=self.ssh_wait_timeout)

    def test_check_gpgkey(self):
        '''
        :avocado: tags=test_check_gpgkey,fast_check
        polarion_id: RHEL7-103849
        '''
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
        utils_lib.run_cmd(self, 'date', expect_ret=0,
                    expect_kw='UTC',
                    msg='Check timezone is UTC.')

    def test_check_virtwhat(self):
        '''
        :avocado: tags=test_check_virtwhat,fast_check,kernel_tier1
        polarion_id: RHEL7-103857
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_virtwhat"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_fork_pte(self):
        '''
        :avocado: tags=test_fork_pte,fast_check,kernel_tier1
        polarion_id: RHEL7-103857
        RHBZ: 1908439
        '''
        case_name = "os_tests.tests.test_general_test.TestGeneralTest.test_fork_pte"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_xenfs_mount(self):
        '''
        :avocado: tags=test_xenfs_mount,fast_check
        polarion_id:
        '''
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
        case_name = "os_tests.tests.test_general_test.TestGeneralTest.test_xenfs_write_inability"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_dmesg_error(self):
        '''
        :avocado: tags=test_check_dmesg_error,fast_check
        polarion_id: RHEL7-103851
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_dmesg_error"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_dmesg_fail(self):
        '''
        :avocado: tags=test_check_dmesg_fail,fast_check
        polarion_id: RHEL7-103851
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_dmesg_fail"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_dmesg_warn(self):
        '''
        :avocado: tags=test_check_dmesg_warn,fast_check
        polarion_id: RHEL7-103851
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_dmesg_warn"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_dmesg_calltrace(self):
        '''
        :avocado: tags=test_check_dmesg_calltrace,fast_check,kernel_tier1
        polarion_id: RHEL7-103851
        bz#: 1777179
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_dmesg_calltrace"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_dmesg_unknownsymbol(self):
        '''
        :avocado: tags=test_check_dmesg_unknownsymbol,fast_check,kernel_tier1
        polarion_id:
        bz#: 1649215
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_dmesg_unknownsymbol"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_dmesg_unable(self):
        '''
        :avocado: tags=test_check_dmesg_unable,fast_check
        polarion_id:
        bz#: 1779454
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_dmesg_unable"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_journalctl_traceback(self):
        '''
        :avocado: tags=test_check_journalctl_traceback,fast_check
        polarion_id:
        bz#: 1801999, 1736818
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_journal_calltrace"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_journalctl_dumpedcore(self):
        '''
        :avocado: tags=test_check_journalctl_dumpedcore,fast_check
        polarion_id:
        bz#: 1797973
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_journalctl_dumpedcore"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_journalctl_invalid(self):
        '''
        :avocado: tags=test_check_journalctl_invalid,fast_check
        polarion_id:
        BZ#:1750417
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_journalctl_invalid"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_journalctl_service_unknown_lvalue(self):
        '''
        :avocado: tags=test_check_journalctl_service_unknown_lvalue,fast_check
        polarion_id:
        BZ#:1871139
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_journalctl_service_unknown_lvalue"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_modload(self):
        '''
        :avocado: tags=test_check_modload,fast_check
        polarion_id:
        '''
        utils_lib.run_cmd(self, 'lsmod', expect_ret=0)

    def test_check_console_log(self):
        '''
        :avocado: tags=test_check_console_log
        this case only confirm whether can get console log normally.
        do not check its content as done in dmesg check, focus on function
        support
        polarion_id: RHEL-117929
        '''
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
        BZ#: 1852657
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_release_name"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_vulnerabilities(self):
        '''
        :avocado: tags=test_check_vulnerabilities,fast_check
        polarion_id: N/A
        '''
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
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_avclog"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_avclog_nfs(self):
        '''
        :avocado: tags=test_check_avclog_nfs,fast_check
        polarion_id: N/A
        bz#: 1771856
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_avclog_nfs"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_nouveau(self):
        '''
        :avocado: tags=test_check_nouveau,fast_check
        polarion_id: N/A
        BZ#: 1349927
        '''
        utils_lib.run_cmd(self, 'cat /etc/redhat-release', cancel_not_kw='CentOS', msg='skip this check on centos, rhbz1349927')
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_nouveau"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_nvme_io_timeout(self):
        '''
        :avocado: tags=test_check_nvme_io_timeout,fast_check
        polarion_id: N/A
        bz#: 1859088
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_nvme_io_timeout"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_tuned_adm_active(self):
        '''
        :avocado: tags=test_check_tuned_adm_active,fast_check
        polarion_id: N/A
        bz#: 1893063
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_tuned_adm_active"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_proc_self_status(self):
        '''
        :avocado: tags=test_check_proc_self_status,fast_check
        polarion_id: N/A
        bz#: 1773868
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_proc_self_status"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_sysfs_cpu_list(self):
        '''
        :avocado: tags=test_check_sysfs_cpu_list,fast_check
        polarion_id: N/A
        bz#: 1741462
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_sysfs_cpu_list"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_dracut_f_v(self):
        '''
        :avocado: tags=test_dracut_f_v,fast_check
        polarion_id: N/A
        bz#: 1849082
        '''
        case_name = "os_tests.tests.test_general_test.TestGeneralTest.test_dracut_f_v"
        utils_lib.run_os_tests(self, case_name=case_name)

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
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_service"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_cpupower(self):
        '''
        :avocado: tags=test_check_cpupower,fast_check,kernel_tier1
        No exception when run cpupower command
        polarion_id: N/A
        bz#: 1626505, 1659883
        '''
        case_name = "os_tests.tests.test_general_test.TestGeneralTest.test_cpupower_exception"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_pkgs_list(self):
        '''
        :avocado: tags=test_check_pkgs_list,fast_check
        polarion_id: N/A
        '''
        utils_lib.run_cmd(self, "sudo rpm -qa", expect_ret=0)

    def test_check_firstlaunch_time(self):
        '''
        :avocado: tags=test_check_firstlaunch_time,fast_check
        polarion_id:
        bz#: 1862930
        check the first launch boot time.
        '''
        max_boot_time = self.params.get('max_boot_time')
        boot_time_sec = utils_lib.getboottime(self)
        utils_lib.compare_nums(self, num1=boot_time_sec, num2=max_boot_time, ratio=0, msg="Compare with cfg specified max_boot_time")

    def test_check_firstlaunch_compare(self):
        '''
        :avocado: tags=test_check_firstlaunch_compare
        polarion_id:
        bz#: 1862930
        compare the first launch boot time with Amazon Linux 2 and Ubuntu.
        '''
        self.log.info("3 Nodes (RHEL, AMZ, Ubuntu) needed!")
        max_boot_time = self.params.get('max_boot_time')
        rhel_boot_time_sec = utils_lib.getboottime(self)
        self.rhel_session = self.session
        self.rhel_vm = self.vm
        self.amz_session = None
        self.amz_vm = None
        self.ubuntu_session = None
        self.ubuntu_vm = None
        if utils_lib.is_arm(self):
            cloud = Setup(self.params, self.name, vendor="amzn2_arm")
        else:
            cloud = Setup(self.params, self.name, vendor="amzn2_x86")
        self.amz_vm = cloud.vm
        self.amz_session = cloud.init_vm()
        utils_lib.run_cmd(self, 'uname -a', vm=self.amz_vm, session=self.amz_session, msg="Get Amazon Linux 2 version")
        amz_boot_time_sec = utils_lib.getboottime(self,vm=self.amz_vm, session=self.amz_session)
        self.amz_vm.delete()

        if utils_lib.is_arm(self):
            cloud = Setup(self.params, self.name, vendor="ubuntu_arm")
        else:
            cloud = Setup(self.params, self.name, vendor="ubuntu_x86")
        self.ubuntu_vm = cloud.vm
        self.ubuntu_session = cloud.init_vm()
        utils_lib.run_cmd(self, 'uname -a', vm=self.ubuntu_vm, session=self.ubuntu_session, msg="Get Ubuntu version")
        ubuntu_boot_time_sec = utils_lib.getboottime(self,vm=self.ubuntu_vm, session=self.ubuntu_session)
        self.ubuntu_vm.delete()
        ratio = self.params.get('boottime_max_ratio')
        utils_lib.compare_nums(self, num1=rhel_boot_time_sec, num2=amz_boot_time_sec, ratio=ratio, msg="Compare with Amazon Linux 2 boot time")
        utils_lib.compare_nums(self, num1=rhel_boot_time_sec, num2=ubuntu_boot_time_sec, ratio=ratio, msg="Compare with Ubuntu boot time")

    def test_check_boot_time(self):
        '''
        :avocado: tags=test_check_boot_time,fast_check
        polarion_id: RHEL7-93100
        bz#: 1776710
        check the boot time after stop-start.
        '''
        max_boot_time = self.params.get('max_boot_time')
        self.vm.stop(wait=True, loops=20)
        self.vm.start(wait=True)
        if 'metal' in self.vm.instance_type:
            self.log.info("Wait %s" % self.ssh_wait_timeout)
            time.sleep(self.ssh_wait_timeout)
        else:
            self.log.info("Wait 30s")
            time.sleep(30)
        self.session.connect(timeout=self.ssh_wait_timeout)
        boot_time_sec = utils_lib.getboottime(self)
        utils_lib.compare_nums(self, num1=boot_time_sec, num2=max_boot_time, ratio=0, msg="Compare with cfg specified max_boot_time")

    def test_check_reboot_time(self):
        '''
        :avocado: tags=test_check_reboot_time
        polarion_id: RHEL7-93100
        check the boot time after reboot.
        '''
        self.vm.reboot()
        if 'metal' in self.vm.instance_type:
            self.log.info("Wait %s" % self.ssh_wait_timeout)
            time.sleep(self.ssh_wait_timeout)
        else:
            self.log.info("Wait 30s")
            time.sleep(30)
        max_boot_time = self.params.get('max_reboot_time')
        self.session.connect(timeout=self.ssh_wait_timeout)
        boot_time_sec = utils_lib.getboottime(self)
        utils_lib.compare_nums(self, num1=boot_time_sec, num2=max_boot_time, ratio=0, msg="Compare with cfg specified max_reboot_time")

    def test_check_available_clocksource(self):
        '''
        :avocado: tags=test_check_available_clocksource,fast_check,kernel_tier1
        polarion_id:
        bz#: 1726487
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_available_clocksource"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_change_clocksource(self):
        '''
        :avocado: tags=test_change_clocksource,fast_check
        polarion_id:
        '''
        case_name = "os_tests.tests.test_general_test.TestGeneralTest.test_change_clocksource"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_change_tracer(self):
        '''
        :avocado: tags=test_change_tracer,fast_check
        no hang happen
        polarion_id:
        bz#: 1650273
        '''
        case_name = "os_tests.tests.test_general_test.TestGeneralTest.test_change_tracer"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_tsc_deadline_timer(self):
        '''
        :avocado: tags=test_check_tsc_deadline_timer,fast_check
        polarion_id: RHEL7-111006
        des: check TSC deadline timer enabled in dmesg
        BZ#: 1503160
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_tsc_deadline_timer"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_timedrift_reboot(self):
        '''
        :avocado: tags=test_check_timedrift_reboot
        After 3 times reboot, if the average drift time over 1 seconds,
        we are considering it as fail.
        polarion_id: RHEL7-110672
        '''
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

    def test_check_lshw_mem(self):
        '''
        :avocado: tags=test_check_lshw_mem
        polarion_id:
        BZ#: 1882157
        '''

        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_lshw_mem"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_lspci_nvme(self):
        '''
        :avocado: tags=test_check_lspci_nvme
        polarion_id:
        BZ#: 1656862
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_lspci_nvme"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_meminfo_memfree(self):
        '''
        :avocado: tags=test_check_meminfo_memfree
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_meminfo_memfree"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_rpm_V_efi(self):
        '''
        :avocado: tags=test_check_rpm_V_efi
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_rpm_V_efi"
        utils_lib.run_os_tests(self, case_name=case_name)

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
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_memleaks"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_collect_insights_result(self):
        '''
        :avocado: tags=test_collect_insights_result
        polarion_id:
        bz#: 1889702
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_collect_insights_result"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_collect_log(self):
        '''
        :avocado: tags=test_collect_log
        polarion_id: N/A
        '''
        self.log.info("This case is only saving log for future check purpose")
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
        aws.done_test(self)
        if self.vm.is_created:
            if self.session.session.is_responsive(
            ) is not None and self.vm.is_started():
                aws.gcov_get(self)
                utils_lib.run_cmd(self, 'uname -r', msg='Get instance kernel version')
                self.session.close()
