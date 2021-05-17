from avocado import Test
from avocado_cloud.app.aws import aws
from avocado_cloud.utils import utils_lib
import time


class CloudInit(Test):
    '''
    :avocado: tags=cloudinit,cloud_init,acceptance,fulltest,outposts
    '''
    def setUp(self):
        self.session = None
        self.vm = None
        self.ssh_wait_timeout = None
        aws.init_test(self)

    def test_check_username(self):
        '''
        :avocado: tags=test_check_username,fast_check,kernel_tier1
        description:
            Check the username for guests on AWS. Linked case RHEL7-103986
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]CloudInit.test_check_username"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            cloud-init
        key_steps:
            1. Launch an instance on AWS EC2.
            2. Connect the instance via ssh with user:ec2-user.
        pass_criteria: 
            ec2-user exists and can access instance using it.
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        self.log.info("In fact timeout is %s" % self.ssh_wait_timeout)
        user_name = self.params.get('ssh_user')
        utils_lib.run_cmd(self, 'whoami', expect_ret=0, expect_kw=user_name)
        utils_lib.run_cmd(self, 'uname -r', msg='Get instance kernel version')

    def test_check_userdata(self):
        '''
        :avocado: tags=test_check_userdata,fast_check,kernel_tier1
        description:
            Check the userdata can be passed when creating instance. Linked case RHEL7-87120
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]CloudInit.test_check_userdata"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            cloud-init
        key_steps:
            1. Launch an instance on AWS EC2 with passing userdata, e.g., passing an script like this:
                #!/bin/bash
                 date > /home/ec2-user/time.log
            2. Connect the instance and check time.log appears after system boot up.
        pass_criteria: 
            The passed userdata (time.log) should exist and can be edit and remove.
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
        description:
            Check the IPv6 is configured by default for guests on AWS. Linked case RHEL-131239
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]CloudInit.test_check_config_ipv6"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            cloud-init
        key_steps:
            1. Launch an instance which support IPv6 on AWS EC2 in subnet with IPv6 auto assigned.
            2. Check the IPv6 is configured and auto assigned for NIC and can be connected via IPv6 address after system boot up.
        pass_criteria: 
            The IPv6 address shows in NIC and can be connected.
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        if not self.params.get('ipv6'):
            self.cancel("Instance not support ipv6, skip check")
        cmd = 'ip addr show eth0'
        utils_lib.run_cmd(self, cmd, expect_kw='inet6 2600')
        cmd = 'cat /etc/sysconfig/network-scripts/ifcfg-eth0'
        utils_lib.run_cmd(self, cmd, expect_kw='IPV6INIT=yes')
        utils_lib.run_cmd(self, 'uname -r', msg='Get instance kernel version')

    def test_check_output_isexist(self):
        '''
        :avocado: tags=test_check_output_isexist,fast_check
        description:
            os-tests Check the cloud-init log /var/log/cloud-init-output.log exists.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]CloudInit.test_check_output_isexist"
        bugzilla_id: 
            1626117
        customer_case_id: 
            BZ1626117
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            cloud-init
        key_steps:
            1. Launch an instance on AWS EC2.
            2. Check cloud-init log in /var/log/cloud-init-output.log after system boot up.
        pass_criteria: 
            The cloud-init log /var/log/cloud-init-output.log exists, and its stdout and stderr is redirected to this log.
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        case_name = "os_tests.tests.test_cloud_init.TestCloudInit.test_check_output_isexist"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_cloudinit_cfg_no_wheel(self):
        '''
        :avocado: tags=test_check_cloudinit_cfg_no_wheel,fast_check
        description:
            os-tests Check there is no wheel in default_user's group in "/etc/cloud/cloud.cfg"
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]CloudInit.test_check_cloudinit_cfg_no_wheel"
        bugzilla_id: 
            1549638
        customer_case_id: 
            BZ1549638
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            cloud-init
        key_steps:
            1. Launch an instance on AWS EC2.
            2. Check there is no wheel in default_user's group in "/etc/cloud/cloud.cfg"
        pass_criteria: 
            No 'wheel' in "/etc/cloud/cloud.cfg"

        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        case_name = "os_tests.tests.test_cloud_init.TestCloudInit.test_check_cloudinit_cfg_no_wheel"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_cloudinit_fingerprints(self):
        '''
        :avocado: tags=test_check_cloudinit_fingerprints,fast_check
        description:
            os-tests check fingerprints is saved in /var/log/messages.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]CloudInit.test_check_cloudinit_fingerprints"
        bugzilla_id: 
            1957532
        customer_case_id: 
            BZ1957532
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            cloud-init
        key_steps:
            1. Launch an instance on AWS EC2.
            2. check fingerprints is saved in /var/log/messages.
        pass_criteria: 
            Fingerprints is saved in /var/log/messages.

        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        case_name = "os_tests.tests.test_cloud_init.TestCloudInit.test_check_cloudinit_fingerprints"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_metadata(self):
        '''
        :avocado: tags=test_check_metadata,fast_check,kernel_tier1,fast_check
        description:
            os-tests Check the cloud-init metadata.
            https://cloudinit.readthedocs.io/en/latest/topics/datasources/ec2.html
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]CloudInit.test_check_metadata"
        bugzilla_id:
            n/a
        customer_case_id:
            n/a
        maintainer:
            xiliang
        case_priority:
            0
        case_component:
            cloud-init
        key_steps:
            1. Launch an instance on AWS EC2.
            2. Run command "curl http://169.254.169.254/latest/meta-data/instance-type" to check the instance can make calls to get instance metadata.
        pass_criteria:
            Correct instance type is returned.
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        case_name = "os_tests.tests.test_cloud_init.TestCloudInit.test_check_metadata"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_cloudinit_log_traceback(self):
        '''
        :avocado: tags=test_check_cloudinit_log_traceback,fast_check
        description:
            Check no traceback log in cloudinit logs.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]CloudInit.test_check_cloudinit_log_traceback"
        bugzilla_id:
            n/a
        customer_case_id:
            n/a
        maintainer:
            xiliang
        case_priority:
            0
        case_component:
            cloud-init
        key_steps:
            1. Launch an instance on AWS EC2.
            2. Check the cloud-init logs: /var/log/cloud-init.log or /var/log/cloud-init-output.log.
        pass_criteria:
            There isn't traceback log in cloudinit logs.
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
        description:
            os-tests Check no unexpected error log in cloudinit logs.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]CloudInit.test_check_cloudinit_log_unexpected"
        bugzilla_id:
            1827207
        customer_case_id:
            BZ1827207
        maintainer:
            xiliang
        case_priority:
            0
        case_component:
            cloud-init
        key_steps:
            1. Launch an instance on AWS EC2.
            2. Check the cloud-init logs: /var/log/cloud-init.log or /var/log/cloud-init-output.log.
        pass_criteria:
            There isn't unexpected error in cloudinit logs.
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        case_name = "os_tests.tests.test_cloud_init.TestCloudInit.test_check_cloudinit_log_unexpected"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_cloudinit_log_critical(self):
        '''
        :avocado: tags=test_check_cloudinit_log_critical,fast_check
        description:
            os-tests check no critical log in cloudinit logs.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]CloudInit.test_check_cloudinit_log_critical"
        bugzilla_id:
            1827207
        customer_case_id:
            BZ1827207
        maintainer:
            xiliang
        case_priority:
            0
        case_component:
            cloud-init
        key_steps:
            1. Launch an instance on AWS EC2.
            2. Check the cloud-init logs: /var/log/cloud-init.log or /var/log/cloud-init-output.log.
        pass_criteria:
            There isn't CRITICAL error in cloudinit logs.
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        case_name = "os_tests.tests.test_cloud_init.TestCloudInit.test_check_cloudinit_log_critical"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_cloudinit_log_warn(self):
        '''
        :avocado: tags=test_check_cloudinit_log_warn,fast_check
        description:
            os-tests check no warning log in cloudinit logs.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]CloudInit.test_check_cloudinit_log_warn"
        bugzilla_id:
            1821999
        customer_case_id:
            n/a
        maintainer:
            xiliang
        case_priority:
            0
        case_component:
            cloud-init
        key_steps:
            1. Launch an instance on AWS EC2.
            2. Check the cloud-init logs: /var/log/cloud-init.log or /var/log/cloud-init-output.log.
        pass_criteria:
            There isn't WARNING in cloudinit logs.
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        case_name = "os_tests.tests.test_cloud_init.TestCloudInit.test_check_cloudinit_log_warn"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_cloudinit_log_error(self):
        '''
        :avocado: tags=test_check_cloudinit_log_error,fast_check
        description:
            os-tests check no error log in cloudinit logs.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]CloudInit.test_check_cloudinit_log_error"
        bugzilla_id:
            1821999
        customer_case_id:
            n/a
        maintainer:
            xiliang
        case_priority:
            0
        case_component:
            cloud-init
        key_steps:
            1. Launch an instance on AWS EC2.
            2. Check the cloud-init logs: /var/log/cloud-init.log or /var/log/cloud-init-output.log.
        pass_criteria:  
            There isn't error log in cloudinit logs.
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        case_name = "os_tests.tests.test_cloud_init.TestCloudInit.test_check_cloudinit_log_error"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_cloudinit_service_status(self):
        '''
        :avocado: tags=test_check_cloudinit_service_status,fast_check
        description:
            os-tests Check if the 4 cloud-init services status are "active".
            BZ1829713 is duplicated to BZ1748015 with customer cases linked.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]CloudInit.test_check_cloudinit_service_status"
        bugzilla_id:
            1829713
        customer_case_id:
            BZ1748015
        maintainer:
            xiliang
        case_priority:
            0
        case_component:
            cloud-init
        key_steps:
            1. Launch an instance on AWS EC2.
            2. Use these commands to check the cloud-init services status: "sudo systemctl status cloud-init-local", "sudo systemctl status cloud-init", "sudo systemctl status cloud-config", "sudo systemctl status cloud-final".
        pass_criteria:
            The 4 cloud-init services status should be "active".
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        case_name = "os_tests.tests.test_cloud_init.TestCloudInit.test_check_cloudinit_service_status"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_cloudinit_log_imdsv2(self):
        '''
        :avocado: tags=test_check_cloudinit_log_imdsv2,fast_check
        description:
            os-tests Check cloud-init use imdsv2 in aws.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]CloudInit.test_check_cloudinit_log_imdsv2"
        bugzilla_id:
            1793652
        customer_case_id:
            BZ1793652
        maintainer:
            xiliang
        case_priority:
            0
        case_component:
            cloud-init
        key_steps:
            1. Launch an instance on AWS EC2.
            2. Check the cloud-init fetched Ec2 IMDSv2 API Token and got metadata using the token by commands:
                "sudo rpm -ql cloud-init"
                "sudo cat /var/log/cloud-init.log"
        pass_criteria:
            There are outputs link these: "DataSourceEc2.py[DEBUG]: Fetching Ec2 IMDSv2 API Token", "X-aws-ec2-metadata-token", and no error or unexpected message.
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        case_name = "os_tests.tests.test_cloud_init.TestCloudInit.test_check_cloudinit_log_imdsv2"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_cloudinit_ds_identify_found(self):
        '''
        :avocado: tags=test_check_cloudinit_ds_identify_found,fast_check
        description:
            os-tests Check heck ds-identify run and ret found.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]CloudInit.test_check_cloudinit_ds_identify_found"
        bugzilla_id:
            1746627
        customer_case_id:
            n/a
        maintainer:
            xiliang
        case_priority:
            0
        case_component:
            cloud-init
        key_steps:
            1. Launch an instance on AWS EC2.
            2. Check the cloud-init log /run/cloud-init/cloud-init-generator.log.
        pass_criteria:
            There are keywords like these: "ds-identify _RET=found".
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        case_name = "os_tests.tests.test_cloud_init.TestCloudInit.test_check_cloudinit_ds_identify_found"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_check_lineoverwrite(self):
        '''
        :avocado: tags=test_check_lineoverwrite
        description:
            Bug 1653131 - cloud-init remove 'NOZEROCONF=yes' from /etc/sysconfig/network.
            This is a specific case of openstack, because the cloud guest images need to have "NOZEROCONF=yes" in /etc/sysconfig/network so that it works well as an openstack guest. (Bug 983611 - Cloud guest images needs to have "NOZEROCONF=yes" in /etc/sysconfig/network)
            cloud-init removed user configuration in /etc/sysconfig/network and rewrite the default configuration in every prevision before cloud-init-18.2-4.el7, after this version, certain lines in network configuration isn't removed after re-provision. linked case RHEL-152730
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]CloudInit.test_check_lineoverwrite"
        bugzilla_id:
            1653131
        customer_case_id:
            BZ1653131
        maintainer:
            xiliang
        case_priority:
            0
        case_component:
            cloud-init
        key_steps:
            1. Launch an instance on AWS EC2.
            2. Add "NOZEROCONF=yes" to top of network config /etc/sysconfig/network.
            3. Add "NETWORKING_IPV6=no" to top of network config /etc/sysconfig/network.
            4. Clean cloud-init with command: "rm /run/cloud-init/ /var/lib/cloud/* -rf" and reboot instance.
            5. Check the new network configuration /etc/sysconfig/network after boot.
        pass_criteria:
            "NETWORKING_IPV6=no" and "NOZEROCONF=yes" should be in the network configuration.
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
        aws.done_test(self)
        if self.vm.is_created:
            if self.session.session.is_responsive(
            ) is not None and self.vm.is_started():
                utils_lib.run_cmd(self,
                            'rpm -q cloud-init',
                            msg='Get cloud-init version.')
                aws.gcov_get(self)
                aws.get_memleaks(self)
                self.session.close()
