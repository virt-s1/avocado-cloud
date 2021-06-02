import os
import re
import time
from avocado import Test
from avocado import main
from avocado_cloud.app import Setup
from avocado_cloud.app.ibmcloud import IbmcloudAccount
from avocado_cloud.app.ibmcloud import Service
from avocado_cloud.app.ibmcloud import BootImage
from distutils.version import LooseVersion
from avocado_cloud.utils import utils_misc
from avocado_cloud.utils import utils_lib
from avocado_cloud.utils.utils_ibmcloud import acommand as command


BASEPATH = os.path.abspath(__file__ + "/../../../")


class CloudinitTest(Test):
    def setUp(self):
        self.account = IbmcloudAccount(self.params)
        self.account.login()
        self.service = Service(self.params)
        self.service.target()
        self.project = self.params.get("rhel_ver", "*/VM/*")
        self.case_short_name = re.findall(r"Test.(.*)", self.name.name)[0]
        self.pwd = os.path.abspath(os.path.dirname(__file__))

        self.cloud = Setup(self.params, self.name, create_timeout=300)
        self.vm = self.cloud.vm
        self.ssh_wait_timeout = 600
        pre_delete = False
        pre_stop = False
 #       if self.name.name.endswith("test_cloudinit_login_with_publickey"):
  #          pre_delete = True

        self.session = self.cloud.init_vm(pre_delete=pre_delete,
                                         pre_stop=pre_stop)    
       
    @property
    def _postfix(self):
        from datetime import datetime
        return datetime.strftime(datetime.now(), "%Y%m%d%H%M%S")

    def test_cloudinit_login_with_publickey(self):
        """
        :avocado: tags=tier1,cloudinit
        RHEL7-103831 - CLOUDINIT-TC: VM can successfully login
        after provisioning(with public key authentication)
        1. Create a VM with only public key authentication
        2. Login with publickey, should have sudo privilege
        """
        self.log.info(
            "RHEL7-103831 - CLOUDINIT-TC: VM can successfully login after provisioning(with public key authentication)")
        self.session.connect(authentication="publickey")
        self.assertEqual(self.vm.vm_username,
                         self.session.cmd_output("whoami"),
                         "Fail to login with publickey")
        self.assertIn(
            "%s ALL=(ALL) NOPASSWD:ALL" % self.vm.vm_username,
            self.session.cmd_output(
                "sudo cat /etc/sudoers.d/90-cloud-init-users"),
            "No sudo privilege")
        # Collect /var/log/cloud-init.log and /var/log/messages
        try:
            self.session.cmd_output("mkdir -p /tmp/logs")
            self.session.cmd_output(
                "sudo cp /var/log/cloud-init.log /tmp/logs/")
            self.session.cmd_output("sudo cp /var/log/messages /tmp/logs/")
            self.session.cmd_output("sudo chmod 644 /tmp/logs/*")
            host_logpath = os.path.dirname(self.job.logfile) + "/logs"
            command("mkdir -p {}".format(host_logpath))
            self.session.copy_files_from("/tmp/logs/*", host_logpath)
        except:
            pass

    #def test_cloudinit_sdk_function(self):
        #self.vm.exists()

    def test_cloudinit_check_hostname(self):
        """
        :avocado: tags=tier1,cloudinit
        RHEL7-103833 - CLOUDINIT-TC: Successfully set VM hostname
        """
        output = self.session.cmd_output("hostname").split('.')[0]
        self.assertEqual(output, self.vm.vm_name.replace('_', '-'),
                         "The hostname is wrong")

    def test_cloudinit_check_service_status(self):
        """
        :avocado: tags=tier1,cloudinit
        RHEL-188130: WALA-TC: [Cloudinit] Check cloud-init service status
        The 4 cloud-init services status should be "active"
        """
        self.log.info(
            "RHEL-188130: WALA-TC: [Cloudinit] Check cloud-init service status")
        service_list = ['cloud-init-local',
                        'cloud-init',
                        'cloud-config',
                        'cloud-final']
        for service in service_list:
            output = self.session.cmd_output(
                "sudo systemctl is-active {}".format(service))
            self.assertEqual(output, 'active',
                             "{} status is not correct: {}".format(service, output))

    def _check_cloudinit_log(self, not_expect_msg):
        self.session.connect(timeout=self.ssh_wait_timeout)
        cmd = 'sudo cat /var/log/cloud-init.log'
        utils_lib.run_cmd(self,
                          cmd,
                          expect_ret=0,
                          expect_not_kw=not_expect_msg,
                          msg='check /var/log/cloud-init.log',
                          is_get_console=False)
        if 'release 7' not in utils_lib.run_cmd(self,
                                                'sudo cat /etc/redhat-release',
                                                is_get_console=False):
            cmd = 'sudo cat /var/log/cloud-init-output.log'
            utils_lib.run_cmd(self,
                              cmd,
                              expect_ret=0,
                              expect_not_kw=not_expect_msg,
                              msg='check /var/log/cloud-init-output.log',
                              is_get_console=False)

    def test_cloudinit_check_log_no_traceback(self):
        '''
        :avocado: tags=tier2,cloudinit
        RHEL-188134 - CLOUDINIT-TC: Check no "Traceback" keyword in /var/log/cloud-init.log
        check no traceback log in cloudinit logs
        '''
        self._check_cloudinit_log("Traceback")

    def test_cloudinit_check_log_no_unexpected(self):
        '''
        :avocado: tags=tier2,cloudinit
        RHEL-188135 - CLOUDINIT-TC: Check no "unexpected" keyword in /var/log/cloud-init.log
        bz#: 1827207
        check no unexpected error log in cloudinit logs
        '''
        self._check_cloudinit_log("unexpected")

    def test_cloudinit_check_log_no_critical(self):
        '''
        :avocado: tags=tier1,cloudinit
        RHEL-188131 - CLOUDINIT-TC: Check no "CRITICAL" level message in /var/log/cloud-init.log
        bz#: 1827207
        check no critical log in cloudinit logs
        '''
        self._check_cloudinit_log("CRITICAL")

    def test_cloudinit_check_log_no_warn(self):
        '''
        :avocado: tags=tier2,cloudinit
        RHEL-188133 - CLOUDINIT-TC: Check no "WARNING" level message in /var/log/cloud-init.log
        bz#: 1821999
        check no warning log in cloudinit logs
        '''
        self._check_cloudinit_log("WARNING")

    def test_cloudinit_check_log_no_error(self):
        '''
        :avocado: tags=tier2,cloudinit
        RHEL-188132 - CLOUDINIT-TC: Check no "ERROR" level message in /var/log/cloud-init.log
        bz#: 1821999
        check no error log in cloudinit logs
        '''
        self._check_cloudinit_log("ERROR")

    def tearDown(self):
        self.account.logout()

if __name__ == "__main__":
    main()
