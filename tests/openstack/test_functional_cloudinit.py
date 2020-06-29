from avocado import Test
from avocado_cloud.app import Setup
from avocado_cloud.utils import utils_misc
from avocado_cloud.utils import utils_lib
from avocado.utils import process
import re
import os
import time


class CloudinitTest(Test):
    def setUp(self):
        self.cloud = Setup(self.params, self.name, create_timeout=300)
        self.vm = self.cloud.vm
        self.ssh_wait_timeout = 600
        pre_delete = False
        pre_stop = False
        if self.name.name.endswith("test_cloudinit_create_vm_login_repeatedly"):
            return
        if self.name.name.endswith("test_cloudinit_login_with_publickey"):
            pre_delete = True
        self.session = self.cloud.init_vm(pre_delete=pre_delete,
                                          pre_stop=pre_stop)


    def test_cloudinit_login_with_publickey(self):
        """
        :avocado: tags=tier1,cloudinit
        RHEL7-103831 - CLOUDINIT-TC: VM can successfully login
        after provisioning(with public key authentication)
        1. Create a VM with only public key authentication
        2. Login with publickey, should have sudo privilege
        """
        output = self.session.cmd_output('whoami')
        self.assertEqual(
            self.vm.vm_username, output,
            "Login VM with publickey error: output of cmd `whoami` unexpected -> %s"
            % output)

    def test_cloudinit_check_hostname(self):
        """
        :avocado: tags=tier1,cloudinit
        RHEL7-103833 - CLOUDINIT-TC: Successfully set VM hostname
        """
        output = self.session.cmd_output("hostname").split('.')[0]
        self.assertEqual(output, self.vm.vm_name.replace('_', '-'),
                         "The hostname is wrong")

    def test_cloudinit_check_services_status(self):
        '''
        :avocado: tags=tier1,cloudinit
        RHEL-188130 - CLOUDINIT-TC: Check cloud-init services status
        check if four cloud-init services are active
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        utils_lib.run_cmd(self, 'cloud-init -v', msg='Get cloud-init version', is_get_console=False)
        cmd = "sudo systemctl is-active cloud-init-local.service"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='active', is_get_console=False)
        cmd = "sudo systemctl is-active cloud-init.service"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='active', is_get_console=False)
        cmd = "sudo systemctl is-active cloud-config.service"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='active', is_get_console=False)
        cmd = "sudo systemctl is-active cloud-final.service"
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_kw='active', is_get_console=False)


    def test_cloudinit_check_log_no_traceback(self):
        '''
        :avocado: tags=tier2,cloudinit
        RHEL-188134 - CLOUDINIT-TC: Check no "Traceback" keyword in /var/log/cloud-init.log
        check no traceback log in cloudinit logs
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        cmd = 'sudo cat /var/log/cloud-init.log'
        utils_lib.run_cmd(self,
                          cmd,
                          expect_ret=0,
                          expect_not_kw='Traceback',
                          msg='check /var/log/cloud-init.log',
                          is_get_console=False)
        if 'release 7' not in utils_lib.run_cmd(self,
                                                'sudo cat /etc/redhat-release',
                                                is_get_console=False):
            cmd = 'sudo cat /var/log/cloud-init-output.log'
            utils_lib.run_cmd(self,
                              cmd,
                              expect_ret=0,
                              expect_not_kw='Traceback',
                              msg='check /var/log/cloud-init-output.log',
                              is_get_console=False)


    def test_cloudinit_check_log_no_unexpected(self):
        '''
        :avocado: tags=tier2,cloudinit
        RHEL-188135 - CLOUDINIT-TC: Check no "unexpected" keyword in /var/log/cloud-init.log
        bz#: 1827207
        check no unexpected error log in cloudinit logs
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        cmd = 'sudo cat /var/log/cloud-init.log'
        utils_lib.run_cmd(self,
                          cmd,
                          expect_ret=0,
                          expect_not_kw='unexpected',
                          msg='check /var/log/cloud-init.log',
                          is_get_console=False)
        if 'release 7' not in utils_lib.run_cmd(self,
                                                'sudo cat /etc/redhat-release',
                                                is_get_console=False):
            cmd = 'sudo cat /var/log/cloud-init-output.log'
            utils_lib.run_cmd(self,
                              cmd,
                              expect_ret=0,
                              expect_not_kw='unexpected',
                              msg='check /var/log/cloud-init-output.log',
                              is_get_console=False)

    def test_cloudinit_check_log_no_critical(self):
        '''
        :avocado: tags=tier1,cloudinit
        RHEL-188131 - CLOUDINIT-TC: Check no "CRITICAL" level message in /var/log/cloud-init.log
        bz#: 1827207
        check no critical log in cloudinit logs
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        cmd = 'sudo cat /var/log/cloud-init.log'
        utils_lib.run_cmd(self,
                          cmd,
                          expect_ret=0,
                          expect_not_kw='CRITICAL',
                          msg='check /var/log/cloud-init.log',
                          is_get_console=False)
        if 'release 7' not in utils_lib.run_cmd(self,
                                                'sudo cat /etc/redhat-release',
                                                is_get_console=False):
            cmd = 'sudo cat /var/log/cloud-init-output.log'
            utils_lib.run_cmd(self,
                              cmd,
                              expect_ret=0,
                              expect_not_kw='CRITICAL',
                              msg='check /var/log/cloud-init-output.log',
                              is_get_console=False)

    def test_cloudinit_check_log_no_warn(self):
        '''
        :avocado: tags=tier2,cloudinit
        RHEL-188133 - CLOUDINIT-TC: Check no "WARNING" level message in /var/log/cloud-init.log
        bz#: 1821999
        check no warning log in cloudinit logs
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        cmd = 'sudo cat /var/log/cloud-init.log'
        utils_lib.run_cmd(self,
                          cmd,
                          expect_ret=0,
                          expect_not_kw='WARNING',
                          msg='check /var/log/cloud-init.log',
                          is_get_console=False)
        if 'release 7' not in utils_lib.run_cmd(self,
                                                'sudo cat /etc/redhat-release',
                                                is_get_console=False):
            cmd = 'sudo cat /var/log/cloud-init-output.log'
            utils_lib.run_cmd(self,
                              cmd,
                              expect_ret=0,
                              expect_not_kw='WARNING',
                              msg='check /var/log/cloud-init-output.log',
                              is_get_console=False)

    def test_cloudinit_check_log_no_error(self):
        '''
        :avocado: tags=tier2,cloudinit
        RHEL-188132 - CLOUDINIT-TC: Check no "ERROR" level message in /var/log/cloud-init.log
        bz#: 1821999
        check no error log in cloudinit logs
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        cmd = 'sudo cat /var/log/cloud-init.log'
        utils_lib.run_cmd(self,
                          cmd,
                          expect_ret=0,
                          expect_not_kw='ERROR',
                          msg='check /var/log/cloud-init.log',
                          is_get_console=False)
        if 'release 7' not in utils_lib.run_cmd(self,
                                                'sudo cat /etc/redhat-release',
                                                is_get_console=False):
            cmd = 'sudo cat /var/log/cloud-init-output.log'
            utils_lib.run_cmd(self,
                              cmd,
                              expect_ret=0,
                              expect_not_kw='ERROR',
                              msg='check /var/log/cloud-init-output.log',
                              is_get_console=False)

    def test_cloudinit_create_vm_login_repeatedly(self):
        """
        :avocado: tags=tier3,cloudinit,test_cloudinit_create_vm_login_repeatedly
        RHEL-188320 - CLOUDINIT-TC:create vm and login repeately
        bz#: 1803928
        create vm and login with ssh-key, run 50 times, because of race condition bug
        """
        pre_delete = True
        for x in range(50):
            self.log.info(str(x)+" run: create VM and login")
            self.session = self.cloud.init_vm(pre_delete=pre_delete,
                                          pre_stop=False)
            output = self.session.cmd_output('whoami')
            self.assertEqual(
                self.vm.vm_username, output,
                str(x)+" run: Login VM with publickey error: output of cmd `whoami` unexpected -> %s"
                % output)
            time.sleep(30)

    def test_cloudutils_growpart_resize_partition_first_boot(self):
        """
        :avocado: tags=tier1,cloud_utils_growpart
        RHEL-188669: CLOUDINIT-TC:[cloud-utils-growpart]resize partition during VM first boot
        """
        self.log.info("RHEL-188669: CLOUDINIT-TC:[cloud-utils-growpart]resize partition \
during VM first boot")
        self.session.cmd_output("sudo su -")
        device = "/dev/vda"
        # Partition Table: gpt, partition number is 3
        # Partition Table: msdos, partition number is 1
        part_type = self.session.cmd_output("parted -s %s print|grep 'Partition Table'|awk '{print $3}'" %device)
        part_number = "3" if part_type == "gpt" else "1"
        # VM flavor m1.medium, size 40G
        self.assertEqual(
            "42.9GB",
            self.session.cmd_output(
                "parted -s %s print|grep ' %s '|awk '{print $3}'" %(device, part_number)),
            "Fail to resize partition during first boot")
        

    def _growpart_auto_resize_partition(self, label):
        """
        :param label: msdos/gpt
        """
        self.session.cmd_output("sudo su -")
        self.assertEqual(
            self.session.cmd_status_output("which growpart")[0], 0,
            "No growpart command.")

        device = "/tmp/testdisk"
        if os.path.exists(device):
            self.session.cmd_output("rm -f {}".format(device))
        self.session.cmd_output("truncate -s 2G {}".format(device))
        self.session.cmd_output(
            "parted -s {} mklabel {}".format(device, label))
        part_type = "primary" if label == "msdos" else ""
        part_name = "xfs" if label == "gpt" else ""
        # 1 partition
        self.session.cmd_output(
            "parted -s {} mkpart {} {} 0 1000".format(device, part_type, part_name))
        self.session.cmd_output("parted -s {} print".format(device))
        self.assertEqual(
            self.session.cmd_status_output("growpart {} 1".format(device))[0],
            0, "Fail to run growpart")
        self.assertEqual(
            "2147MB",
            self.session.cmd_output(
                "parted -s %s print|grep ' 1 '|awk '{print $3}'" % device),
            "Fail to resize partition")
        # 2 partitions
        self.session.cmd_output("parted -s {} rm 1".format(device))
        self.session.cmd_output(
            "parted -s {} mkpart {} {} 0 1000".format(device, part_type, part_name))
        self.session.cmd_output(
            "parted -s {} mkpart {} {} 1800 1900".format(device, part_type, part_name))
        self.session.cmd_output("parted -s {} print".format(device))
        exit_status, output = self.session.cmd_status_output(
            "growpart {} 1".format(device))
        self.assertEqual(exit_status, 0,
                         "Run growpart failed: {}".format(output))
        self.assertEqual(
            "1800MB",
            self.session.cmd_output(
                "parted -s %s print|grep ' 1 '|awk '{print $3}'" % device),
            "Fail to resize partition")

    def test_cloudutils_growpart_auto_resize_partition_in_gpt(self):
        """
        :avocado: tags=tier1,cloud_utils_growpart
        RHEL-171053: CLOUDINIT-TC: [cloud-utils-growpart] Auto resize\
                     partition in gpt
        BZ#1695091
        """
        self.log.info("RHEL-171053: CLOUDINIT-TC: [cloud-utils-growpart] \
Auto resize partition in gpt")
        self._growpart_auto_resize_partition("gpt")


    def test_cloudutils_growpart_auto_resize_partition_in_mbr(self):
        """
        :avocado: tags=tier1,cloud_utils_growpart
        RHEL-188633: CLOUDINIT-TC: [cloud-utils-growpart] Auto resize\
                     partition in MBR
        """
        self.log.info("")
        self._growpart_auto_resize_partition("msdos")


    def tearDown(self):
        self.session.close()