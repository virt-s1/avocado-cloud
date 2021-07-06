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
        description:
            Verify all packages are signed with GPG key in RHEL on AWS. Linked case RHEL7-103849.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_gpgkey"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance with RHEL AMI uploaded by Red Hat officially on AWS.
            2. Connect instance via ssh, list packages don't have gpg key via command "$ sudo rpm -qa --qf '%{name}-%{version}-%{release}.%{arch} (%{SIGPGP:pgpsig})\n'|grep -v 'Key ID'|grep -v gpg-pubkey".
        pass_criteria: 
            All packages are signed with GPG key.
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
        description:
            Verify all packages are signed with GPG key in RHEL on AWS. Linked case RHEL7-103856.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_timezone"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance with RHEL AMI uploaded by Red Hat officially on AWS.
            2. Connect instance via ssh, check the timezone set by default in RHEL via command "$ date".
        pass_criteria: 
            The default timezone is UTC.
        '''
        utils_lib.run_cmd(self, 'date', expect_ret=0,
                    expect_kw='UTC',
                    msg='Check timezone is UTC.')

    def test_check_virtwhat(self):
        '''
        :avocado: tags=test_check_virtwhat,virt_what,fast_check,kernel
        description:
            os-tests detect the type of virtual machine in RHEL on AWS. Linked case RHEL7-103857.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_virtwhat"
        bugzilla_id: 
            1782435
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect instance via ssh, check the virtual machine type via command "$ sudo virt-what".
        pass_criteria: 
            The output of virt-what should be as following.
            For Xen based instances, xen-hvm, aws.
            For KVM based instances, kvm, aws.
            For Bare metal instance, aws.
            For ARM instances, aws.
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_virtwhat"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_fork_pte(self):
        '''
        :avocado: tags=test_fork_pte,fast_check,kernel
        description:
            [RHEL8.4] os-tests Check dirty bit is preserved across pte_wrprotect in RHEL on AWS.
            The patch supports this feature in arm64 was backported from RHEL8.4 as well as RHEL8.3.z.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_fork_pte"
        bugzilla_id: 
            1908439
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect instance via ssh, run below tests in the instance.
               $ sudo wget https://github.com/redis/redis/files/5717040/redis_8124.c.txt
               $ sudo mv redis_8124.c.txt redis_8124.c
               $ sudo gcc -o reproduce redis_8124.c
               $ sudo systemd-run --scope -p MemoryLimit=550M ./reproduce
        pass_criteria:
            The output should look like "Running scope as unit: run-r1cb2f8dfc1c84acc95d51da36f543903.scope Your kernel looks fine.".
            It would be bug if the output looks like "Running scope as unit: run-r2d61239abf8446f19f75611c8c6008c5.scope Your kernel has a bug.".
        '''
        case_name = "os_tests.tests.test_general_test.TestGeneralTest.test_fork_pte"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_xenfs_mount(self):
        '''
        :avocado: tags=test_xenfs_mount,fast_check
        description:
            Test mount xenfs in RHEL on AWS.
            This case is only for Xen based instances include T2, R4, P2, P3, G3, G3s, M4, C4, D2, H1, X1, X1e, I3, F1.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_xenfs_mount"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect instance via ssh, mount xenfs via command "$ sudo mount -t xenfs xenfs /proc/xen/".
            3. Check the result after mounted "$ sudo ls /proc/xen".
        pass_criteria:
            xenfs is mounted to /proc/xen successfully.
            The output of step 3 is "capabilities privcmd xenbus".
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
        description:
            Test xe-guest-utilities in RHEL on AWS.
            This case is only for Xen based instances include T2, R4, P2, P3, G3, G3s, M4, C4, D2, H1, X1, X1e, I3, F1.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_xe_guest_utilities"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect instance via ssh, run below tests in the instance.
               $ sudo wget https://kojipkgs.fedoraproject.org//packages/xe-guest-utilities/7.12.0/1.fc29/x86_64/xe-guest-utilities-7.12.0-1.fc29.x86_64.rpm
               $ sudo yum localinstall -y xe-guest-utilities-7.12.0-1.fc29.x86_64.rpm
               Or $ sudo rpm -ivh xe-guest-utilities-7.12.0-1.fc29.x86_64.rpm --force --nodeps
               $ sudo /usr/libexec/xe-guest-utilities/xenstore-read domid
               $ sudo /usr/libexec/xe-guest-utilities/xenstore-read name 
               $ sudo /usr/libexec/xe-guest-utilities/xenstore-read memory/target

               Run "$ sudo ethtool -i eth0" to check the nic dirver, if the driver is vif (T2 instances), 
               run this command "$ sudo /usr/libexec/xe-guest-utilities/xenstore-read device/vif/0/mac".

               $ sudo /usr/libexec/xe-guest-utilities/xenstore-list device
               $ sudo /usr/libexec/xe-guest-utilities/xenstore-list control

        pass_criteria:
            All tests pass.
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
        description:
            os-tests Test write to xenfs in RHEL on AWS.
            This case is only for Xen based instances include T2, R4, P2, P3, G3, G3s, M4, C4, D2, H1, X1, X1e, I3, F1.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_xenfs_write_inability"
        bugzilla_id: 
            1663266
        customer_case_id: 
            BZ1663266
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect instance via ssh, run below tests in the instance.
               $ sudo umount /proc/xen
               $ sudo mount -t xenfs xenfs /proc/xen/
               $ echo '
                #!/usr/bin/env python

                import os
                import struct

                if __name__ == "__main__":
                    fd = os.open("/proc/xen/xenbus", os.O_RDWR)
                    # end a fake transaction
                    os.write(fd, struct.pack("<IIII", 7, 2, 1234, 0))
                        ' > t.py
               $ sudo python3 t.py

        pass_criteria:
            No call trace or crash when running the script.
        '''
        case_name = "os_tests.tests.test_general_test.TestGeneralTest.test_xenfs_write_inability"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_dmesg_error(self):
        '''
        :avocado: tags=test_check_dmesg_error,fast_check
        description:
            os-tests Check error message in dmesg for RHEL on AWS. Linked case RHEL7-103851.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_dmesg_error"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect instance via ssh, check dmesg.

        pass_criteria:
            There isn't unexpected error message in dmesg.
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_dmesg_error"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_dmesg_fail(self):
        '''
        :avocado: tags=test_check_dmesg_fail,fast_check
        description:
            os-tests Check fail message in dmesg for RHEL on AWS. Linked case RHEL7-103851.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_dmesg_fail"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect instance via ssh, check dmesg.

        pass_criteria:
            There isn't unexpected fail message in dmesg.
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_dmesg_fail"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_dmesg_warn(self):
        '''
        :avocado: tags=test_check_dmesg_warn,fast_check
        description:
            os-tests Check warn message in dmesg for RHEL on AWS. Linked case RHEL7-103851.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_dmesg_warn"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect instance via ssh, check dmesg.

        pass_criteria:
            There isn't unexpected warn message in dmesg.
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_dmesg_warn"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_dmesg_calltrace(self):
        '''
        :avocado: tags=test_check_dmesg_calltrace,fast_check,kernel
        description:
            os-tests Check call trace in dmesg for RHEL on AWS. Linked case RHEL7-103851.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_dmesg_calltrace"
        bugzilla_id: 
            1777179, 1777260
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect instance via ssh, check dmesg.

        pass_criteria:
            There isn't Call trace/Call Trace in dmesg.
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_dmesg_calltrace"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_dmesg_unknownsymbol(self):
        '''
        :avocado: tags=test_check_dmesg_unknownsymbol,fast_check,kernel
        description:
            os-tests Check unknown symbol in dmesg for RHEL on AWS. Linked case RHEL7-103851.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_dmesg_unknownsymbol"
        bugzilla_id: 
            1649215
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect instance via ssh, check dmesg.

        pass_criteria:
            There isn't Unknown symbol in dmesg.
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_dmesg_unknownsymbol"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_dmesg_unable(self):
        '''
        :avocado: tags=test_check_dmesg_unable,fast_check
        description:
            os-tests Check keyword "unable" in dmesg for RHEL on AWS. Linked case RHEL7-103851.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_dmesg_unable"
        bugzilla_id: 
            1779454
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect instance via ssh, check dmesg.

        pass_criteria:
            There isn't keyword "unable" in dmesg.
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_dmesg_unable"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_journalctl_traceback(self):
        '''
        :avocado: tags=test_check_journalctl_traceback,fast_check
        description:
            os-tests Check call trace in journalctl log for RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_journalctl_traceback"
        bugzilla_id: 
            1801999, 1736818
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect instance via ssh, redirect journalctl output to a file as it is not get return normally in RHEL7.
               $ sudo journalctl > /tmp/journalctl.log
        pass_criteria:
            There isn't keyword "Traceback" or "Backtrace" in journal log.
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_journal_calltrace"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_journalctl_dumpedcore(self):
        '''
        :avocado: tags=test_check_journalctl_dumpedcore,fast_check
        description:
            os-tests Check dumped core in journalctl log for RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_journalctl_dumpedcore"
        bugzilla_id: 
            1797973
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect instance via ssh, redirect journalctl output to a file as it is not get return normally in RHEL7.
               $ sudo journalctl > /tmp/journalctl.log
        pass_criteria:
            There isn't keyword "dumped core" in journal log.
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_journalctl_dumpedcore"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_journalctl_invalid(self):
        '''
        :avocado: tags=test_check_journalctl_invalid,fast_check
        description:
            os-tests Check invalid message in journalctl log for RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_journalctl_invalid"
        bugzilla_id: 
            1750417
        customer_case_id: 
            BZ1750417
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect instance via ssh, redirect journalctl output to a file as it is not get return normally in RHEL7.
               $ sudo journalctl > /tmp/journalctl.log
        pass_criteria:
            There isn't keyword "invalid" (except "Invalid user,invalid user") in journal log.
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_journalctl_invalid"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_journalctl_service_unknown_lvalue(self):
        '''
        :avocado: tags=test_check_journalctl_service_unknown_lvalue,fast_check
        description:
            os-tests Check unknown lvalue in service journalctl log for RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_journalctl_service_unknown_lvalue"
        bugzilla_id: 
            1871139
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect instance via ssh, run below tests in instance.
               Get all systemd unit files
               $ sudo systemctl list-unit-files |grep -v UNIT|grep -v listed|awk -F' ' '{print $1}'
               Check each service status, e.g.,
               $ sudo systemctl status proc-sys-fs-binfmt_misc.automount
               Check journalctl log for this service,
               $ sudo journalctl --unit proc-sys-fs-binfmt_misc.automount
               Check journalctl logs of all services.
        pass_criteria:
            There isn't Unknown lvalue in journal log.
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_journalctl_service_unknown_lvalue"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_modload(self):
        '''
        :avocado: tags=test_check_modload,fast_check
        description:
            Check currently loaded modules for RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_modload"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect instance via ssh, use "$ sudo lsmod" to check currently loaded modules.
        pass_criteria:
            All necessary modules should be loaded by default. 
        '''
        utils_lib.run_cmd(self, 'lsmod', expect_ret=0)

    def test_check_console_log(self):
        '''
        :avocado: tags=test_check_console_log
        description:
            Check can get console output from RHEL instance on AWS. Linked case RHEL-117929.
            This case only confirm whether can get console log normally. Do not check its content as done in dmesg check, focus on function support.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_console_log"
        bugzilla_id: 
            1527545
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Use AWS CLI in client to get instance console output.
               "$ aws ec2 get-console-output --output text --instance-id <instance-id>"
            3. Restart or Stop the instance, wait several minutes and check the console output again.
        pass_criteria:
            The console output displays as normal in step 2.
            Console output and time stamp change as the instance status changing in step 3.
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
        description:
            os-tests Check release name for RHEL on AWS. Linked case RHEL7-103850.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_release_name"
        bugzilla_id: 
            1852657
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and check the release name via command "sudo cat /etc/redhat-release"
            3. Check the current kernel version via command "$ sudo uname -a".
        pass_criteria:
            The version in /etc/redhat-release should the correct compared with the release version in default kernel for a clean system.
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_release_name"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_systemd_analyze_verify_deprecated_unsafe(self):
        '''
        :avocado: tags=test_check_systemd_analyze_verify_deprecated_unsafe,fast_check
        description:
            os-tests check service does not use obsolete options in unit file
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_systemd_analyze_verify_deprecated_unsafe"
        bugzilla_id: 
            1974184
        customer_case_id: 
            
        maintainer: 
            xiliang
        case_priority: 
            2
        case_component: 
            systemd
        key_steps:
            1. Launch an instance on AWS EC2.
            2. # systemd-analyze verify $service name
        pass_criteria: 
            No 'deprecated' or 'unsafe' found in output
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_systemd_analyze_verify_deprecated_unsafe"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_systemd_analyze_verify_obsolete(self):
        '''
        :avocado: tags=test_check_systemd_analyze_verify_obsolete,fast_check
        description:
            os-tests check service does not use obsolete options in unit file
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_systemd_analyze_verify_obsolete"
        bugzilla_id: 
            1974108
        customer_case_id: 
            
        maintainer: 
            xiliang
        case_priority: 
            2
        case_component: 
            systemd
        key_steps:
            1. Launch an instance on AWS EC2.
            2. # systemd-analyze verify $service name
        pass_criteria: 
            No "is obsolete" found in output
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_systemd_analyze_verify_obsolete"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_systemd_analyze_verify_ordering_cycle(self):
        '''
        :avocado: tags=test_check_systemd_analyze_verify_ordering_cycle,fast_check
        description:
            os-tests Make sure there is no ordering cycle which may block boot up.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_systemd_analyze_verify_ordering_cycle"
        bugzilla_id: 
            1932614
        customer_case_id: 
            BZ1932614
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            systemd
        key_steps:
            1. Launch an instance on AWS EC2.
            2. Make sure there is no ordering cycle which may block boot up.
        pass_criteria: 
            No ordering cycle found.

        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_systemd_analyze_verify_ordering_cycle"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_product_id(self):
        '''
        :avocado: tags=test_check_product_id,fast_check
        description:
            os-tests Check if product id matches /etc/redhat-release for RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_product_id"
        bugzilla_id: 
            1938930, RHELPLAN-60817
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and check the release name via command "sudo cat /etc/redhat-release"
            3. Check the current kernel version via command "$ sudo rpm -qa|grep redhat-release".
            4. Check product certificate via command "sudo rct cat-cert /etc/pki/product-default/*.pem".
        pass_criteria:
            The three versions are the same in step 2,3,4.
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_product_id"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_vulnerabilities(self):
        '''
        :avocado: tags=test_check_vulnerabilities,fast_check
        description:
            Check vulnerabilities for RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_vulnerabilities"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and get microcode version via command "sudo rpm -qa|grep microcode".
            3. Check the current vulnerabilities via command "$ sudo grep . /sys/devices/system/cpu/vulnerabilities/* | sed 's/:/^/' | column -t -s^".
        pass_criteria:
            There is no unexpected Vulnerable in system.
            Here are known Vulnerables for ec2 vm instances, "spec_store_bypass", "Retpoline", "tsx_async_abort", "mds".
            There should not be any Vulnerable in Bare Metal instance.

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
        :avocado: tags=test_check_avclog,fast_check,kernel
        description:
            os-tests Check avclog in RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_avclog"
        bugzilla_id: 
            1655493, 1771856
        customer_case_id: 
            BZ1655493
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh, check AVC log via command "$ sudo ausearch -m AVC -ts today".
        pass_criteria:
            The command returns 1 with <no matches>.
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_avclog"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_avclog_nfs(self):
        '''
        :avocado: tags=test_check_avclog_nfs,fast_check
        description:
            os-tests Check nfs mount function and AVC log in RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_avclog_nfs"
        bugzilla_id: 
            1655493, 1771856
        customer_case_id: 
            BZ1655493
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh, run below tests.
               $ sudo yum install -y nfs-utils 
               $ sudo systemctl start nfs-server.service
               $ sudo mkdir /tmp/testrw
               $ sudo chmod -R 777 /tmp/testrw
               $ sudo exportfs -o rw,insecure_locks,all_squash,fsid=1 *:/tmp/testrw
               $ sudo mount -t nfs 127.0.0.1:/tmp/testrw /mnt
               $ sudo ausearch -m AVC -ts today
            3. Check the current kernel version via command "$ sudo uname -a".
        pass_criteria:
            The dir is mounted successfully to the mountpoint via nfs, and ausearch command should return 1 with <no matches>.
            No permission denied in AVC log. 
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_avclog_nfs"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_nouveau(self):
        '''
        :avocado: tags=test_check_nouveau,fast_check
        description:
            os-tests Check nouveau is disabled by default in RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_nouveau"
        bugzilla_id: 
            1349927, 1645772
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and check the loaded moudles via command "sudo lsmod"
            3. Check kernel parameters via command "/proc/cmdline".
        pass_criteria:
            The nouveau module isn't in the loaded modules list.
            There should be "rd.blacklist=nouveau" in kernel command line.
        '''
        utils_lib.run_cmd(self, 'cat /etc/redhat-release', cancel_not_kw='CentOS', msg='skip this check on centos, rhbz1349927')
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_nouveau"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_nvme_io_timeout(self):
        '''
        :avocado: tags=test_check_nvme_io_timeout,fast_check
        description:
            os-tests Check the default setting of nvme_core.io_timeout in RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_nvme_io_timeout"
        bugzilla_id: 
            1859088, 1717041
        customer_case_id: 
            BZ1717041
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and check io_timeout value via command "sudo cat /sys/module/nvme_core/parameters/io_timeout"
            3. Check the kernel commandline via command "$ sudo cat /proc/cmdline".
        pass_criteria:
            The default value nvme_core.io_timeout=4294967295 is recommended in ec2.
            Make sure it is configured in cmdline and the actual value is set in system.
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_nvme_io_timeout"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_tuned_adm_active(self):
        '''
        :avocado: tags=test_check_tuned_adm_active,fast_check
        description:
            os-tests Check tuned-adm loads default "virtual-guest" in vm and does not load virtual-guest in metal instance on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_tuned_adm_active"
        bugzilla_id: 
            1893063
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and enable tuned service via command "sudo systemctl enable --now tuned".
            3. Use command "$ sudo tuned-adm active" to display current active profile.
        pass_criteria:
            The current active profile is virtual-guest in vm instances.
            The current active profile should not be virtual-guest in bare metal instances.
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_tuned_adm_active"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_proc_self_status(self):
        '''
        :avocado: tags=test_check_proc_self_status,fast_check
        description:
            os-tests Check no unknown in /proc/self/status in RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_proc_self_status"
        bugzilla_id: 
            1773868
        customer_case_id: 
            BZ1773868
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and check self status via command "$ /proc/self/status".
        pass_criteria:
            There isn't "unknown" in the output.
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_proc_self_status"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_sysfs_cpu_list(self):
        '''
        :avocado: tags=test_check_sysfs_cpu_list,fast_check
        description:
            os-tests Check no crash when read "cpu_list" in /sys in RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_sysfs_cpu_list"
        bugzilla_id: 
            1741462
        customer_case_id: 
            BZ1741462
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and read cpu_list via command "$ sudo find -H /sys -name cpu_list  -type f -perm -u=r -print -exec cat '{}' 2>&1 \;".
        pass_criteria:
            There isn't crash when read "cpu_list" in /sys.
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_sysfs_cpu_list"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_dracut_f_v(self):
        '''
        :avocado: tags=test_dracut_f_v,fast_check
        description:
            os-tests Check there is no failed item in generating an initramfs/initrd image. for RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_dracut_f_v"
        bugzilla_id: 
            1849082, 1906301
        customer_case_id: 
            BZ1906301
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and generate an initramfs/initrd image via command "$ sudo dracut -f -v"
        pass_criteria:
            There isn't no failed/FAILED item when running "dracut -f -v".
        '''
        case_name = "os_tests.tests.test_general_test.TestGeneralTest.test_dracut_f_v"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_secure_ioerror(self):
        '''
        :avocado: tags=test_check_secure_ioerror,fast_check
        description:
            Check there is no io error in /var/log/secure in RHEL on AWS.
            https://access.redhat.com/solutions/975803
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_secure_ioerror"
        bugzilla_id: 
            1103344
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and check /var/log/secure via command "sudo cat /var/log/secure".
            3. Check the current kernel version via command "$ sudo uname -a".
        pass_criteria:
            There isn't "Input/output error" in secure log.
        '''
        self.log.info("Check /var/log/secure")
        utils_lib.run_cmd(self, "sudo cat /var/log/secure", expect_ret=0)
        utils_lib.run_cmd(self, "sudo cp /var/log/secure /tmp", expect_ret=0)
        utils_lib.run_cmd(self, "sudo cat  /var/log/secure", expect_not_kw="Input/output error")

    def test_check_rngd(self):
        '''
        :avocado: tags=test_check_rngd,fast_check
        description:
            [RHEL8] Check rngd service is enabled by default in RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_rngd"
        bugzilla_id: 
            1625874
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and check the rngd status via command "$ sudo systemctl status rngd".
            3. Check the current kernel version via command "$ sudo uname -a".
        pass_criteria:
            rngd service is in 'active (running)' status.
        '''
        self.log.info("check rngd service is enabled in RHEL8, not required \
in RHEL7|6, bug1625874")
        output = utils_lib.run_cmd(self, "uname -r", expect_ret=0)
        if 'el8' in output:
            utils_lib.run_cmd(self,
                        'sudo systemctl status -l rngd',
                        expect_kw='active (running)',
                        msg="Checking rngd service")
        else:
            utils_lib.run_cmd(self,
                        'sudo systemctl status -l rngd',
                        msg="Checking rngd service")

    def test_check_service(self):
        '''
        :avocado: tags=test_check_service,fast_check,kernel
        description:
            os-tests Check no failed service in start up in RHEL on AWS.
 for RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_service"
        bugzilla_id: 
            1740443
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and check if there is failed service via command "sudo systemctl|grep failed".
        pass_criteria:
            There isn't failed service in start up.
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_service"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_cpupower(self):
        '''
        :avocado: tags=test_check_cpupower,fast_check,kernel
        description:
            os-tests Check no exception when run cpupower command in RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_cpupower"
        bugzilla_id: 
            1626505, 1659883
        customer_case_id: 
            BZ1626505
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and run below tests.
               $ sudo cpupower info
               $ sudo cpupower idle-info
               $ sudo cpupower frequency-info
        pass_criteria:
            There isn't core dumped in outputs of above commands.
        '''
        case_name = "os_tests.tests.test_general_test.TestGeneralTest.test_cpupower_exception"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_pkgs_list(self):
        '''
        :avocado: tags=test_check_pkgs_list,fast_check
        description:
            Check installed packages list in RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_pkgs_list"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and check installed packages via command "sudo rpm -qa".
        pass_criteria:
            Installed packages are as expected.
        '''
        utils_lib.run_cmd(self, "sudo rpm -qa", expect_ret=0)

    def test_check_firstlaunch_time(self):
        '''
        :avocado: tags=test_check_firstlaunch_time,fast_check
        description:
            Check the first launch boot time for RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_firstlaunch_time"
        bugzilla_id: 
            1862930
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh, check boot time and service start time via below commands.
               "$ sudo systemd-analyze"
               "$ sudo systemd-analyze blame"
        pass_criteria:
            No more time used when first launching instance compared with previous RHEL release. 
        '''
        max_boot_time = self.params.get('max_boot_time')
        boot_time_sec = utils_lib.getboottime(self)
        utils_lib.compare_nums(self, num1=boot_time_sec, num2=max_boot_time, ratio=0, msg="Compare with cfg specified max_boot_time")

    def test_check_firstlaunch_compare(self):
        '''
        :avocado: tags=test_check_firstlaunch_compare
        description:
            Compare the first launch RHEL boot time with Amazon Linux 2 and Ubuntu on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_firstlaunch_compare"
        bugzilla_id: 
            1862930
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh, check boot time and service start time via below commands.
               "$ sudo systemd-analyze"
               "$ sudo systemd-analyze blame"
        pass_criteria:
            Compare the first launch boot time with Amazon Linux 2 and Ubuntu.
            No more time used when firsh launching RHEL instance than Amazon Linux 2 and Ubuntu.
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
        description:
            Check the boot time after stop-start for RHEL on AWS. Linked case RHEL7-93100.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_boot_time"
        bugzilla_id: 
            1776710
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Stop the instance and start it again.
            3. Connect the instance via ssh, check boot time and service start time via below commands.
               "$ sudo systemd-analyze"
               "$ sudo systemd-analyze blame"
        pass_criteria:
            No more time used when starting an instance compared with previous RHEL release. 
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
        description:
            Check the boot time after reboot RHEL on AWS. Linked case RHEL7-93100.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_reboot_time"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Reboot the instance.
            3. Connect the instance via ssh, check boot time and service start time via below commands.
               "$ sudo systemd-analyze"
               "$ sudo systemd-analyze blame"
        pass_criteria:
            No more time used when reboot an instance compared with previous RHEL release. 
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
        :avocado: tags=test_check_available_clocksource,fast_check,kernel
        description:
            os-tests Check available clocksource in RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_available_clocksource"
        bugzilla_id: 
            1726487
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and run below tests.
               Check the Architecture,
               $ lscpu
               Checking available clocksource,
               $ sudo cat /sys/devices/system/clocksource/clocksource0/available_clocksource
        pass_criteria:
            The available clocksource outputs are as expected as below.
            For Xen instances, expected clocks are 'xen,tsc,hpet,acpi_pm'.
            For ARM instances, expected clocks are 'arch_sys_counter'.
            For KVM and AMD instances, expected clocks are 'kvm-clock,tsc,acpi_pm'.
            For KVM and Intel instances, expected clocks are 'kvm-clock,tsc,acpi_pm'.
            For Bare Metal instances, expected clocks are 'tsc,hpet,acpi_pm'.
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_available_clocksource"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_change_clocksource(self):
        '''
        :avocado: tags=test_change_clocksource,fast_check
        description:
            os-tests Test change clocksource in RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_change_clocksource"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and run below tests.
               Check the Architecture,
               $ lscpu
               Checking available clocksource,
               $ sudo cat /sys/devices/system/clocksource/clocksource0/available_clocksource
               Checking current clocksource,
               $ sudo cat /sys/devices/system/clocksource/clocksource0/current_clocksource
               Change clocksource items lists in available one by one,
               $ sudo bash -c 'echo "tsc" > /sys/devices/system/clocksource/clocksource0/current_clocksource'
               Check current clocksource again,
               $ sudo cat /sys/devices/system/clocksource/clocksource0/current_clocksource
               $ dmesg
        pass_criteria:
            The clocksource can be changed successfully, and displays in current clocksource after changed.
            No error or exception in dmesg when changing clocksource.
        '''
        case_name = "os_tests.tests.test_general_test.TestGeneralTest.test_change_clocksource"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_change_tracer(self):
        '''
        :avocado: tags=test_change_tracer,fast_check,kernel
        description:
            os-tests Test change tracer in RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_change_tracer"
        bugzilla_id: 
            1650273
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and run tests via below commands.
               $ sudo mount -t debugfs nodev /sys/kernel/debug
               $ sudo cat /sys/kernel/debug/tracing/current_tracer
               $ sudo cat /sys/kernel/debug/tracing/available_tracers
               Add available tracers to current e.g.,
               $ echo function > /sys/kernel/debug/tracing/current_tracer
               $ sudo cat /sys/kernel/debug/tracing/current_tracer
               $ dmesg
        pass_criteria:
            Current tracer can be changed, and no hangs or crash happen.
        '''
        case_name = "os_tests.tests.test_general_test.TestGeneralTest.test_change_tracer"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_tsc_deadline_timer(self):
        '''
        :avocado: tags=test_check_tsc_deadline_timer,fast_check
        description:
            os-tests check TSC deadline timer enabled in dmesg in RHEL on AWS. Linked case RHEL7-111006.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_tsc_deadline_timer"
        bugzilla_id: 
            1503160
        customer_case_id: 
            BZ1503160
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and run tests via below commands.
               Check if cpu flags include tsc,
               $ sudo grep tsc /proc/cpuinfo
               Check system actually using TSC_DEADLINE feature via dmesg,
               $ sudo dmesg|grep -i tsc
               Check system actually using "lapic-deadline" as clock events device,
               $ sudo cat /sys/devices/system/clockevents/clockevent0/current_device
        pass_criteria:
            In dmesg it displays deadline timer was enabled.
            $ grep -i tsc dmesg_738_ec2.log
              [    0.000000] tsc: Fast TSC calibration using PIT
              [    0.000000] tsc: Detected 3000.103 MHz processor
              [    0.163053] TSC deadline timer enabled
              [   23.193957] Switched to clocksource tsc
            The output is "lapic-deadline" for current clock events device.
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_tsc_deadline_timer"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_timedrift_reboot(self):
        '''
        :avocado: tags=test_check_timedrift_reboot
        description:
            [RHEL7] Check the average drift time isn't over 1 second in RHEL on AWS after 3 times reboot. Linked case RHEL7-110672.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_timedrift_reboot"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and run below commands.
               $ sudo systemctl stop ntpd
               $ sudo systemctl disable ntpd
               $ sudo systemctl stop chronyd
               $ sudo systemctl disable chronyd
               $ sudo timedatectl set-ntp 0
               Run 3 times sync with ntp server, check the drift time and reboot,
               $ ntpdate -q de.ntp.org.cn
               $ reboot
               $ ntpdate -q de.ntp.org.cn
        pass_criteria:
            The average drift time should be less than 1s.
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
        description:
            [RHEL7] The average drift time should less than 1 after 120s stress test in RHEL on AWS. Linked case RHEL7-110673
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_timedrift_stress"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and run below commands.
               $ sudo systemctl stop ntpd
               $ sudo systemctl disable ntpd
               $ sudo systemctl stop chronyd
               $ sudo systemctl disable chronyd
               $ sudo timedatectl set-ntp 0
               $ sudo ntpdate -q de.ntp.org.cn
               Download and install stress package from below url,
               https://rpmfind.net/linux/epel/7/x86_64/Packages/s/stress-1.0.4-16.el7.x86_64.rpm
               $ sudo cat /proc/cpuinfo |grep -i "model name"|wc -l
               $ sudo stress -c 72 -t 120
               $ ntpdate  -q de.ntp.org.cn
        pass_criteria:
            The version in /etc/redhat-release should the correct compared with the release version
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
        description:
            Check if microcode is loaded or not as expected in RHEL on AWS.
            This case is only for instances in Intel platform, not suitable for ARM instances and *a instances.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_microcode_load"
        bugzilla_id: 
            1607899
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and check if microcode is loaded via command "sudo dmesg | grep -i microcode".
        pass_criteria:
            For virtualized instances, the output is null since microcode should not be loaded in VM.
            For bare metal instances, microcode is loaded.
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
        :avocado: tags=test_check_cpu_count,fast_check,kernel
        description:
            Check cpu count is the same as in specs for RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_cpu_count"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and check the cpu counts via command "$ sudo cat /proc/cpuinfo |grep processor|wc -l".
        pass_criteria:
            The cpu count is the same as in specs of this instance.
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
        description:
            os-tests Check "lshw -C memory" reported memory size is correct in RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_lshw_mem"
        bugzilla_id: 
            1882157
        customer_case_id: 
            BZ1882157
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and run command "$ sudo lshw -C memory".
        pass_criteria:
            No big gap between lshw reported memory and in specs.
        '''

        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_lshw_mem"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_lspci_nvme(self):
        '''
        :avocado: tags=test_check_lspci_nvme
        description:
            os-tests Check all nvme pci devices are found by "lsblk" in RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_lspci_nvme"
        bugzilla_id: 
            1656862
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and check nvme pci devices via command "$ lspci|grep "Non-Volatile memory"|wc -l".
            3. Check nvme block devices via command "$ sudo lsblk -d|grep nvme|wc -l".
        pass_criteria:
            The numbers in steps 2 and 3 should be the same and as in specs.
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_lspci_nvme"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_meminfo_memfree(self):
        '''
        :avocado: tags=test_check_meminfo_memfree
        description:
            os-tests Check MemFree is less than MemTotal RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_meminfo_memfree"
        bugzilla_id: 
            1880090
        customer_case_id: 
            BZ1880090
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and check memory infomation via command "sudo cat /sys/devices/system/node/node0/meminfo".
        pass_criteria:
            The MemFree should be less than MemTotal.
            Fail output for FYI.
            # cat /sys/devices/system/node/node0/meminfo
              Node 0 MemTotal:       30774804 kB
              Node 0 MemFree:        31505560 kB
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_meminfo_memfree"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_rpm_V_efi(self):
        '''
        :avocado: tags=test_check_rpm_V_efi
        description:
            os-tests Check if product id matches /etc/redhat-release for RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_rpm_V_efi"
        bugzilla_id: 
            1845052
        customer_case_id: 
            BZ1845052
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and check if package efi-filesystem is installed via command "$ sudo rpm -q efi-filesystem".
            3. Check rpm verify status via command "$ sudo rpm -V efi-filesystem".
        pass_criteria:
            There isn't fail in step3.
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_rpm_V_efi"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_mem_size(self):
        '''
        :avocado: tags=test_check_mem_size,fast_check
        description:
            Check actual memory is not less than 5% than assigned in RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_mem_size"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and check kdump reserved memory via command "$ sudo kdumpctl showmem".
            3. Check memory via command "$ sudo cat /proc/meminfo".
        pass_criteria:
            Compare the actual memory calculated by kdump reserved memory + MemTotal with the memory in instance spec.
            Ther actual memory should not be less than 5% than assigned.
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
        description:
            os-tests Check there isn't memory leak in RHEL on AWS. Linked case RHEL-117648.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_memleaks"
        bugzilla_id: 
            1349927
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh, check if debug kernel is installed.
            3. Install debug kernel packages if debug kernel isn't installed in system.
            4. Configure grubby to set debug kernel as the defualt boot kernel.
            5. Enable kmemleak with command "$ sudo grubby --update-kernel=ALL --args="kmemleak=on"".
            6. Reboot system.
            7. Scan memory leak with command "$ sudo echo scan > /sys/kernel/debug/kmemleak".
            8. Check memory leak with command " $ sudo cat /sys/kernel/debug/kmemleak".
        pass_criteria:
            There should not be memory leak found.
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_memleaks"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_collect_insights_result(self):
        '''
        :avocado: tags=test_collect_insights_result
        description:
            os-tests Check if insights-client hits rules in RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_collect_insights_result"
        bugzilla_id: 
            1889702
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and run below commands,
               $ sudo insights-client --register
               $ sudo insights-client --check-result
               $ sudo insights-client --show-results
        pass_criteria:
            Check the hit rules, make sure all suggested rules are hit.
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_collect_insights_result"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_collect_log(self):
        '''
        :avocado: tags=test_collect_log
        description:
            Collect system logs for RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_collect_log"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and save system logs.
               $ sudo wget https://github.com/SCHEN2015/virt-utils/archive/master.zip
               $ sudo unzip master.zip
               $ virt-utils-master/vm_check/vm_check.sh

        pass_criteria:
            Just collect and save various system logs.
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

    def test_subscription_manager_auto(self):
        '''
        :avocado: tags=test_subscription_manager_auto
        description:
            [RHEL8.4] os-tests Check if auto subscription registered works in RHEL on AWS.
            This case is for instances created from Golden Images but not on-demand images.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_subscription_manager_auto"
        bugzilla_id: 
            1932802, 1905398
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and check subscription-manager config via command "$ sudo subscription-manager config".
            3. Check if rhsmcertd enabled via command "$ sudo systemctl is-enabled rhsmcertd".
            4. Change rhsmcertd.auto_registration_interval from 60min to 1min, "$ sudo subscription-manager config --rhsmcertd.auto_registration_interval=1".
            5. Rester rhsmcertd "$ sudo systemctl restart rhsmcertd".
            6. Check rhsmcertd.log "$ sudo cat /var/log/rhsm/rhsmcertd.log".
            7. Check rhsm.log "$ sudo cat /var/log/rhsm/rhsm.log".
            8. Check subscription identity "$ sudo subscription-manager identity".
            9. List currently installed on the system "$ sudo subscription-manager list --installed".
            10. Check subscription status "$ sudo subscription-manager status".
            11. Check if insights-client can register successfully, "$ sudo insights-client --register".
        pass_criteria:
            There are "auto_registration = 1" and "manage_repos = 0" in subscription-manager config in step2.
            Auto subscription registered completed.
            Product Name is "Red Hat Enterprise Linux" and Content Access Mode is "Simple Content Access" from outputs of step 9,10.
            Output of step 11, "This host has already been registered. Automatic scheduling for Insights has been enabled."
        '''
        case_name = "os_tests.tests.test_general_test.TestGeneralTest.test_subscription_manager_auto"
        utils_lib.run_os_tests(self, case_name=case_name, timeout=1800)

    def test_subscription_manager_config(self):
        '''
        :avocado: tags=test_subscription_manager_config
        description:
            os-tests Check "subscription-manager config" return the same response as "subscription-manager config --list" for RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_subscription_manager_config"
        bugzilla_id: 
            1862431
        customer_case_id: 
            BZ1862431
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and run commands
               $ sudo subscription-manager config
               $ subscription-manager config --list
            3. Compare the outputs of above 2 commands.
        pass_criteria:
            The same output with the 2 commands in step2.
        '''
        case_name = "os_tests.tests.test_general_test.TestGeneralTest.test_subscription_manager_config"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_dmidecode_outofspec(self):
        '''
        :avocado: tags=test_check_dmidecode_outofspec
        description:
            os-tests Check there is no "OUT OF SPEC" in dmidecode output in RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_check_dmidecode_outofspec"
        bugzilla_id: 
            1858350
        customer_case_id: 
            BZ1858350
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and check the dmidecode via command "$ sudo dmidecode".
        pass_criteria:
            There isn't "OUT OF SPEC" in dmidecode output.
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_dmidecode_outofspec"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_podman_rm_stopped(self):
        '''
        :avocado: tags=test_podman_rm_stopped
        description:
            os-tests test use podman to remove a stopped container in RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_podman_rm_stopped"
        bugzilla_id: 
            1913295
        customer_case_id: 
            BZ1913295
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            GeneralVerification
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh and run below tests.
               List all containers before testing,
               $ podman ps 
               Clean all containers before testing,
               $ podman rm -a -f
               $ podman run --name myctr1 -td quay.io/libpod/alpine
               $ podman run --name myctr2 -td quay.io/libpod/alpine
               $ timeout 5 podman exec myctr1 sleep 10
               $ podman kill myctr1
               $ podman inspect myctr1
               $ podman rm myctr1
               $ timeout 5 podman exec myctr2 sleep 10
               $ podman stop myctr2
               $ podman inspect myctr2
               $ podman rm myctr2
               List all containers again after testing,
               $ podman ps
        pass_criteria:
            myctr1 and myctr2 are both removed without any error.
        '''
        case_name = "os_tests.tests.test_general_test.TestGeneralTest.test_podman_rm_stopped"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_podman_build_image(self):
        '''
        :avocado: tags=test_podman_build_image,fulltest,acceptance
        case_name:
            test_podman_build_image
        case_priority:
            2
        component:
            podman
        bugzilla_id:
            1903412
        customer_case_id:

        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_podman_build_image"

        maintainer:
            xiliang@redhat.com

        description:
            podman can build an image using '--network container' in rootless or root mode

        key_steps:
            1. $ cat Dockerfile
               FROM registry.access.redhat.com/ubi8/ubi
               RUN touch /tmp/test.txt
            2. # podman build --network container -t build_test .

        expected_result:
            Build successfully.
        '''
        case_name = "os_tests.tests.test_general_test.TestGeneralTest.test_podman_build_image"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_podman_leaks_exit(self):
        '''
        :avocado: tags=test_podman_leaks_exit,fulltest,acceptance
        case_name:
            test_podman_leaks_exit

        case_priority:
            2

        component:
            podman

        bugzilla_id:
            1730281

        customer_case_id:
            02390622

        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_podman_leaks_exit"

        maintainer:
            xiliang@redhat.com

        description:
            podman leaks kernel memory due to return code stored in tmpfs

        key_steps:
            1. $ podman run --name test -d ubi
            2. $ ls /run/libpod/exits/

        expected_result:
            Step2 return nothing.
        '''
        case_name = "os_tests.tests.test_general_test.TestGeneralTest.test_podman_leaks_exit"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_podman_dev_null_permission(self):
        '''
        :avocado: tags=test_podman_dev_null_permission,fulltest,acceptance
        case_name:
            test_podman_dev_null_permission

        case_priority:
            2

        component:
            podman

        bugzilla_id:
            1952698

        customer_case_id:
            02920986

        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_podman_dev_null_permission"

        maintainer:
            xiliang@redhat.com

        description:
            Make sure permission on /dev/null are not changing from 666 to 777 after running podman as root

        key_steps:
            1. # sudo podman run -d -p 80:80 httpd
            2. # ls -l /dev/null

        expected_result:
            /dev/null permission keeps 666
        '''
        case_name = "os_tests.tests.test_general_test.TestGeneralTest.test_podman_dev_null_permission"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_dmidecode_dump_segfault(self):
        '''
        :avocado: tags=test_check_dmidecode_dump_segfault,fulltest,acceptance
        case_name:
            test_check_dmidecode_dump_segfault

        case_priority:
            2

        component:
            dmidecode

        bugzilla_id:
            1885823

        customer_case_id:
            02939365

        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_podman_dev_null_permission"

        maintainer:
            xiliang@redhat.com

        description:
            check there is no segmentation fault while run 'dmidecode --dump'

        key_steps:
            # dmidecode --dump |grep -i Segmentation 

        expected_result:
            No segmentation fault found.
        '''
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_check_dmidecode_dump_segfault"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_fips_selftest(self):
        '''
        :avocado: tags=test_fips_selftest,fulltest,acceptance
        case_name:
            test_fips_selftest

        case_priority:
            2

        component:
            openssl

        bugzilla_id:
            1940085

        customer_case_id:
            02874840

        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]GeneralVerification.test_fips_selftest"

        maintainer:
            xiliang@redhat.com

        description:
            FIPS_selftest() pass

        key_steps:
            1. # gcc fipstest.c -o fipstest -lcrypto
            2. # # ./fipstest

        expected_result:
            No fips selftest failed.
        '''
        case_name = "os_tests.tests.test_general_test.TestGeneralTest.test_fips_selftest"
        utils_lib.run_os_tests(self, case_name=case_name)

    def tearDown(self):
        aws.done_test(self)
        if self.vm.is_created:
            if self.session.session.is_responsive(
            ) is not None and self.vm.is_started():
                aws.gcov_get(self)
                utils_lib.run_cmd(self, 'uname -r', msg='Get instance kernel version')
                self.session.close()
