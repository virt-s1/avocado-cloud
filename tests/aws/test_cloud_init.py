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
        check_cmd = r"whoami"
        user_name = self.params.get('ssh_user')
        utils_lib.run_cmd(self, check_cmd, expect_ret=0, expect_kw=user_name)
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
        aws.run_cmd(self, check_cmd, expect_ret=0)
        check_cmd = "rm -rf %s" % user_dir
        aws.run_cmd(self, check_cmd, expect_ret=0)

        aws.run_cmd(self, 'uname -r', msg='Get instance kernel version')

    def test_check_config_ipv6(self):
        '''
        :avocado: tags=test_check_config_ipv6
        polarion_id: RHEL-131239
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        if not self.params.get('ipv6'):
            self.cancel("Instance not support ipv6, skip check")
        cmd = 'ifconfig eth0'
        aws.run_cmd(self, cmd, expect_kw='inet6 2600')
        cmd = 'cat /etc/sysconfig/network-scripts/ifcfg-eth0'
        aws.run_cmd(self, cmd, expect_kw='IPV6INIT=yes')
        aws.run_cmd(self, 'uname -r', msg='Get instance kernel version')

    def test_check_output_isexist(self):
        '''
        :avocado: tags=test_check_output_isexist
        polarion_id:
        bz#: 1626117
        check whether /var/log/cloud-init-output.log exists
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        aws.run_cmd(self,
                    'uname -r',
                    cancel_not_kw='el7,el6',
                    msg='cancel it in RHEL7')
        cmd = 'sudo cat /var/log/cloud-init-output.log'
        aws.run_cmd(self,
                    cmd,
                    expect_kw='Datasource DataSourceEc2Local',
                    msg='check /var/log/cloud-init-output.log exists status')

    def test_check_metadata(self):
        '''
        :avocado: tags=test_check_metadata(,fast_check,kernel_tier1
        polarion_id:
        https://cloudinit.readthedocs.io/en/latest/topics/datasources/ec2.html
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        self.log.info("In fact timeout is %s" % self.ssh_wait_timeout)
        cmd = r"curl http://169.254.169.254/latest/dynamic/instance-identity/\
document"

        aws.run_cmd(self, cmd, expect_ret=0, expect_kw=self.vm.res_id)

    def test_check_cloudinit_log_traceback(self):
        '''
        :avocado: tags=test_check_cloudinit_log_traceback,fast_check
        polarion_id:
        check no traceback log in cloudinit logs
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        cmd = 'sudo cat /var/log/cloud-init.log'
        aws.run_cmd(self,
                    cmd,
                    expect_ret=0,
                    expect_not_kw='Traceback',
                    msg='check /var/log/cloud-init.log')
        if 'release 7' not in aws.run_cmd(self,
                                          'sudo cat /etc/redhat-release'):
            cmd = 'sudo cat /var/log/cloud-init-output.log'
            aws.run_cmd(self,
                        cmd,
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
        cmd = 'sudo cat /var/log/cloud-init.log'
        aws.run_cmd(self,
                    cmd,
                    expect_ret=0,
                    expect_not_kw='unexpected',
                    msg='check /var/log/cloud-init.log')
        if 'release 7' not in aws.run_cmd(self,
                                          'sudo cat /etc/redhat-release'):
            cmd = 'sudo cat /var/log/cloud-init-output.log'
            aws.run_cmd(self,
                        cmd,
                        expect_ret=0,
                        expect_not_kw='unexpected',
                        msg='check /var/log/cloud-init-output.log')

    def test_check_cloudinit_log_critical(self):
        '''
        :avocado: tags=test_check_cloudinit_log_critical,fast_check
        polarion_id:
        bz#: 1827207
        check no critical log in cloudinit logs
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        cmd = 'sudo cat /var/log/cloud-init.log'
        aws.run_cmd(self,
                    cmd,
                    expect_ret=0,
                    expect_not_kw='CRITICAL',
                    msg='check /var/log/cloud-init.log')
        if 'release 7' not in aws.run_cmd(self,
                                          'sudo cat /etc/redhat-release'):
            cmd = 'sudo cat /var/log/cloud-init-output.log'
            aws.run_cmd(self,
                        cmd,
                        expect_ret=0,
                        expect_not_kw='CRITICAL',
                        msg='check /var/log/cloud-init-output.log')

    def test_check_cloudinit_log_warn(self):
        '''
        :avocado: tags=test_check_cloudinit_log_warn,fast_check
        polarion_id:
        bz#: 1821999
        check no warning log in cloudinit logs
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        cmd = 'sudo cat /var/log/cloud-init.log'
        aws.run_cmd(self,
                    cmd,
                    expect_ret=0,
                    expect_not_kw='WARNING',
                    msg='check /var/log/cloud-init.log')
        if 'release 7' not in aws.run_cmd(self,
                                          'sudo cat /etc/redhat-release'):
            cmd = 'sudo cat /var/log/cloud-init-output.log'
            aws.run_cmd(self,
                        cmd,
                        expect_ret=0,
                        expect_not_kw='WARNING',
                        msg='check /var/log/cloud-init-output.log')

    def test_check_cloudinit_log_error(self):
        '''
        :avocado: tags=test_check_cloudinit_log_error,fast_check
        polarion_id:
        bz#: 1821999
        check no error log in cloudinit logs
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        cmd = 'sudo cat /var/log/cloud-init.log'
        aws.run_cmd(self,
                    cmd,
                    expect_ret=0,
                    expect_not_kw='ERROR',
                    msg='check /var/log/cloud-init.log')
        if 'release 7' not in aws.run_cmd(self,
                                          'sudo cat /etc/redhat-release'):
            cmd = 'sudo cat /var/log/cloud-init-output.log'
            aws.run_cmd(self,
                        cmd,
                        expect_ret=0,
                        expect_not_kw='ERROR',
                        msg='check /var/log/cloud-init-output.log')

    def test_check_cloudinit_service_status(self):
        '''
        :avocado: tags=test_check_cloudinit_service_status,fast_check
        polarion_id:
        bz#: 1829713
        The 4 cloud-init services status should be "active"
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        service_list = ['cloud-init-local',
                        'cloud-init',
                        'cloud-config',
                        'cloud-final']
        for service in service_list:
            cmd = "sudo systemctl is-active %s" % service
            utils_lib.run_cmd(self, cmd, expect_kw='active', msg = "check %s status" % service)

    def test_check_cloudinit_log_imdsv2(self):
        '''
        :avocado: tags=test_check_cloudinit_log_imdsv2,fast_check
        polarion_id:
        bz#: 1810704
        check cloud-init use imdsv2 in aws
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        cmd = "sudo rpm -ql cloud-init|grep -w DataSourceEc2.py"
        output = aws.run_cmd(self, cmd, expect_ret=0, msg='Get DataSourceEc2.py')
        cmd = "sudo cat " + output + "|grep IMDSv2"
        aws.run_cmd(self, cmd,
                    cancel_kw="Fetching Ec2 IMDSv2 API Token",
                    msg='Check IMDSv2 support')
        #output = aws.run_cmd(self, 'rpm -q cloud-init',
        #    cancel_not_kw='cloud-init-18,cloud-init-17,cloud-init-16')
        cmd = 'sudo cat /var/log/cloud-init.log'
        aws.run_cmd(self,
                    cmd,
                    expect_ret=0,
                    expect_kw='Fetching Ec2 IMDSv2 API Token,X-aws-ec2-metadata-token',
                    msg='check /var/log/cloud-init.log')

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
        output = aws.run_cmd(self,
                             'uname -r',
                             msg='Get instance kernel version')
        # if 'el8' in output:
        #    self.cancel('Cancel as 1691685 not fix in RHEL8')
        cmd = 'ifconfig eth0'
        aws.run_cmd(self, cmd, msg="Previous ifconfig status")
        cmd = 'cat /etc/sysconfig/network'
        output = aws.run_cmd(self, cmd, msg="Previous network configuration.")
        if "NOZEROCONF=yes" not in output:
            cmd = r"sudo sed -i '1s/^/NOZEROCONF=yes\n/' \
/etc/sysconfig/network"

            aws.run_cmd(self,
                        cmd,
                        msg='add NOZEROCONF=yes to top of network config')
        if "NETWORKING_IPV6=no" not in output:
            cmd = r"sudo sed -i '1s/^/NETWORKING_IPV6=no\n/' \
/etc/sysconfig/network"

            aws.run_cmd(self,
                        cmd,
                        msg='add NETWORKING_IPV6=no top of network config')
        cmd = 'cat /etc/sysconfig/network'
        output = aws.run_cmd(self, cmd, msg="Updated network configuration.")
        cmd = 'sudo rm /run/cloud-init/ /var/lib/cloud/* -rf'
        aws.run_cmd(self, cmd, msg='clean cloud-init and redo it')
        self.vm.reboot()
        if 'metal' in self.vm.instance_type:
            self.log.info("Wait %s" % self.ssh_wait_timeout)
            time.sleep(self.ssh_wait_timeout)
        else:
            self.log.info("Wait 30s")
            time.sleep(30)
        self.session.connect(timeout=self.ssh_wait_timeout)
        cmd = 'cat /etc/sysconfig/network'
        output = aws.run_cmd(self, cmd, msg="New network configuration.")
        if "NETWORKING_IPV6=no" in output:
            self.fail("NETWORKING_IPV6=no is not expected")
        if "NOZEROCONF=yes" not in output:
            self.fail("NOZEROCONF=yes is expected")

    def tearDown(self):
        if self.session.session.is_responsive(
        ) is not None and self.vm.is_started():
            aws.run_cmd(self,
                        'rpm -q cloud-init',
                        msg='Get cloud-init version.')
            aws.gcov_get(self)
            aws.get_memleaks(self)
            self.session.close()
