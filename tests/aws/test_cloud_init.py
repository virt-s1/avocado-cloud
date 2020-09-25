from avocado import Test
from avocado_cloud.app.aws import aws
from avocado_cloud.utils import utils_lib
import time


class CloudInit(Test):
    '''
    :avocado: tags=cloudinit,acceptance,fulltest
    '''
    def setUp(self):
        self.session = None
        self.vm = None
        self.ssh_wait_timeout = None
        aws.init_test(self)

    def test_check_username(self):
        '''
        :avocado: tags=test_check_username,fast_check,kernel_tier1
        polarion_id: RHEL7-103986
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        self.log.info("In fact timeout is %s" % self.ssh_wait_timeout)
        user_name = self.params.get('ssh_user')
        utils_lib.run_cmd(self, 'whoami', expect_ret=0, expect_kw=user_name)
        utils_lib.run_cmd(self, 'uname -r', msg='Get instance kernel version')

    def test_check_userdata(self):
        '''
        :avocado: tags=test_check_userdata,fast_check,kernel_tier1
        polarion_id: RHEL7-87120
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        user_name = self.params.get('ssh_user')
        user_dir = "/home/%s/instance_create_%s" % (user_name,
                                                    self.vm.instance_type)
        check_cmd = "ls -l %s" % user_dir
        utils_lib.run_cmd(self, check_cmd, expect_ret=0)
        check_cmd = "rm -rf %s" % user_dir
        utils_lib.run_cmd(self, check_cmd, expect_ret=0)

        utils_lib.run_cmd(self, 'uname -r', msg='Get instance kernel version')

    def test_check_config_ipv6(self):
        '''
        :avocado: tags=test_check_config_ipv6,fast_check
        polarion_id: RHEL-131239
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        if not self.params.get('ipv6'):
            self.cancel("Instance not support ipv6, skip check")
        cmd = 'ifconfig eth0'
        utils_lib.run_cmd(self, cmd, expect_kw='inet6 2600')
        cmd = 'cat /etc/sysconfig/network-scripts/ifcfg-eth0'
        utils_lib.run_cmd(self, cmd, expect_kw='IPV6INIT=yes')
        utils_lib.run_cmd(self, 'uname -r', msg='Get instance kernel version')

    def test_check_output_isexist(self):
        '''
        :avocado: tags=test_check_output_isexist,fast_check
        polarion_id:
        bz#: 1626117
        check whether /var/log/cloud-init-output.log exists
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        case_name = "os_tests.tests.test_cloud_init.TestCloudInit.test_check_output_isexist"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_metadata(self):
        '''
        :avocado: tags=test_check_metadata,fast_check,kernel_tier1,fast_check
        polarion_id:
        https://cloudinit.readthedocs.io/en/latest/topics/datasources/ec2.html
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        case_name = "os_tests.tests.test_cloud_init.TestCloudInit.test_check_metadata"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_cloudinit_log_traceback(self):
        '''
        :avocado: tags=test_check_cloudinit_log_traceback,fast_check
        polarion_id:
        check no traceback log in cloudinit logs
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        utils_lib.run_cmd(self,
                    'sudo cat /var/log/cloud-init.log',
                    expect_ret=0,
                    expect_not_kw='Traceback',
                    msg='check /var/log/cloud-init.log')
        if 'release 7' not in utils_lib.run_cmd(self,
                                          'sudo cat /etc/redhat-release'):
            utils_lib.run_cmd(self,
                        'sudo cat /var/log/cloud-init-output.log',
                        expect_ret=0,
                        expect_not_kw='Traceback',
                        msg='check /var/log/cloud-init-output.log')

    def test_check_cloudinit_log_unexpected(self):
        '''
        :avocado: tags=test_check_cloudinit_log_unexpected,fast_check
        polarion_id:
        bz#: 1827207
        check no unexpected error log in cloudinit logs
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        case_name = "os_tests.tests.test_cloud_init.TestCloudInit.test_check_cloudinit_log_unexpected"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_cloudinit_log_critical(self):
        '''
        :avocado: tags=test_check_cloudinit_log_critical,fast_check
        polarion_id:
        bz#: 1827207
        check no critical log in cloudinit logs
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        case_name = "os_tests.tests.test_cloud_init.TestCloudInit.test_check_cloudinit_log_critical"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_cloudinit_log_warn(self):
        '''
        :avocado: tags=test_check_cloudinit_log_warn,fast_check
        polarion_id:
        bz#: 1821999
        check no warning log in cloudinit logs
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        case_name = "os_tests.tests.test_cloud_init.TestCloudInit.test_check_cloudinit_log_warn"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_cloudinit_log_error(self):
        '''
        :avocado: tags=test_check_cloudinit_log_error,fast_check
        polarion_id:
        bz#: 1821999
        check no error log in cloudinit logs
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        case_name = "os_tests.tests.test_cloud_init.TestCloudInit.test_check_cloudinit_log_error"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_cloudinit_service_status(self):
        '''
        :avocado: tags=test_check_cloudinit_service_status,fast_check
        polarion_id:
        bz#: 1829713
        The 4 cloud-init services status should be "active"
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        case_name = "os_tests.tests.test_cloud_init.TestCloudInit.test_check_cloudinit_service_status"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_cloudinit_log_imdsv2(self):
        '''
        :avocado: tags=test_check_cloudinit_log_imdsv2,fast_check
        polarion_id:
        bz#: 1810704
        check cloud-init use imdsv2 in aws
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        case_name = "os_tests.tests.test_cloud_init.TestCloudInit.test_check_cloudinit_log_imdsv2"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_cloudinit_ds_identify_found(self):
        '''
        :avocado: tags=test_check_cloudinit_ds_identify_found,fast_check
        polarion_id:
        bz#: 1746627
        check ds-identify run and ret found
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        case_name = "os_tests.tests.test_cloud_init.TestCloudInit.test_check_cloudinit_ds_identify_found"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_lineoverwrite(self):
        '''
        :avocado: tags=test_check_lineoverwrite
        polarion_id: RHEL-152730
        bug: Bug 1653131 - cloud-init remove 'NOZEROCONF=yes' from
        /etc/sysconfig/network cloud-init removed user configuration in
        /etc/sysconfig/network and rewrite the default configuration in
        every prevision before cloud-init-18.2-4.el7, after this version,
        certain lines in network configuration isn't removed after
        re-provision.
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        utils_lib.run_cmd(self,
                    'uname -r',
                     msg='Get instance kernel version')
        cmd = 'ifconfig eth0'
        utils_lib.run_cmd(self, cmd, msg="Previous ifconfig status")
        cmd = 'cat /etc/sysconfig/network'
        output = utils_lib.run_cmd(self, cmd, msg="Previous network configuration.")
        if "NOZEROCONF=yes" not in output:
            cmd = r"sudo sed -i '1s/^/NOZEROCONF=yes\n/' \
/etc/sysconfig/network"

            utils_lib.run_cmd(self,
                        cmd,
                        msg='add NOZEROCONF=yes to top of network config')
        if "NETWORKING_IPV6=no" not in output:
            cmd = r"sudo sed -i '1s/^/NETWORKING_IPV6=no\n/' \
/etc/sysconfig/network"

            utils_lib.run_cmd(self,
                        cmd,
                        msg='add NETWORKING_IPV6=no top of network config')
        cmd = 'cat /etc/sysconfig/network'
        output = utils_lib.run_cmd(self, cmd, msg="Updated network configuration.")
        cmd = 'sudo rm /run/cloud-init/ /var/lib/cloud/* -rf'
        utils_lib.run_cmd(self, cmd, msg='clean cloud-init and redo it')
        self.vm.reboot()
        if 'metal' in self.vm.instance_type:
            self.log.info("Wait %s" % self.ssh_wait_timeout)
            time.sleep(self.ssh_wait_timeout)
        else:
            self.log.info("Wait 30s")
            time.sleep(30)
        self.session.connect(timeout=self.ssh_wait_timeout)
        cmd = 'cat /etc/sysconfig/network'
        output = utils_lib.run_cmd(self, cmd, msg="New network configuration.")
        if "NETWORKING_IPV6=no" in output:
            self.fail("NETWORKING_IPV6=no is not expected")
        if "NOZEROCONF=yes" not in output:
            self.fail("NOZEROCONF=yes is expected")

    def tearDown(self):
        if self.session.session.is_responsive(
        ) is not None and self.vm.is_started():
            utils_lib.run_cmd(self,
                        'rpm -q cloud-init',
                        msg='Get cloud-init version.')
            aws.gcov_get(self)
            aws.get_memleaks(self)
            self.session.close()
