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

    def tearDown(self):
        self.session.close()