from avocado import Test
from avocado_cloud.app import Setup
from avocado_cloud.utils import utils_misc
from avocado_cloud.utils import utils_lib
from avocado.utils import process
import re
import os
import time
import base64 


class CloudinitTest(Test):
    def setUp(self):
        self.cloud = Setup(self.params, self.name, create_timeout=300)
        self.vm = self.cloud.vm
        self.ssh_wait_timeout = 600
        self.case_short_name = re.findall(r"Test.(.*)", self.name.name)[0]
        pre_delete = False
        pre_stop = False
       # if self.name.name.endswith("test_cloudinit_create_vm_login_repeatedly"):
        if self.case_short_name in [
                "test_cloudinit_create_vm_login_repeatedly",
                "test_cloudinit_create_vm_config_drive",
                "test_cloudinit_create_vm_two_nics",
                "test_cloudinit_create_vm_stateless_ipv6",
                "test_cloudinit_create_vm_stateful_ipv6",
        ]:
            return
        if self.name.name.endswith("test_cloudinit_login_with_password"):
            if self.vm.exists():
                self.vm.delete(wait=True)
            self.session = self.cloud.init_session()
            return
        if self.name.name.endswith("test_cloudinit_login_with_publickey"):
            pre_delete = True
        user_data = """\
#cloud-config

user: {0}
password: {1}
chpasswd: {{ expire: False }}
ssh_pwauth: 1
""".format(self.vm.vm_username, 'R')# test random password
        self.vm.user_data = base64.b64encode(
        user_data.encode('utf-8')).decode('utf-8')
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
        self.assertIn(
            "%s ALL=(ALL) NOPASSWD:ALL" % self.vm.vm_username,
            self.session.cmd_output(
                "sudo cat /etc/sudoers.d/90-cloud-init-users"),
            "No sudo privilege")

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

    def test_cloudinit_check_instance_data_json(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-182312 - CLOUDINIT-TC:cloud-init can successfully write data to instance-data.json
        bz#: 1744526
        """     
        self.session.connect(timeout=self.ssh_wait_timeout)
        cmd = 'ls -l /run/cloud-init/instance-data.json'
        utils_lib.run_cmd(self,
                          cmd,
                          expect_ret=0,
                          expect_not_kw='No such file or directory',
                          msg='check /run/cloud-init/instance-data.json',
                          is_get_console=False)

    def test_cloudinit_check_config_ipv6(self):
        '''
        :avocado: tags=tier2,cloudinit
        RHEL-189023 - CLOUDINIT-TC: check ipv6 configuration
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        # change command to ip addr because of no net-tool by default in rhel8.4
        cmd = 'ip addr show eth0'
        utils_lib.run_cmd(self, cmd, expect_kw='inet6 2620')
        cmd = 'cat /etc/sysconfig/network-scripts/ifcfg-eth0'
        utils_lib.run_cmd(self, cmd, expect_kw='IPV6INIT=yes')
        utils_lib.run_cmd(self, 'uname -r', msg='Get instance kernel version')
    
    def test_cloudinit_check_random_password_len(self):
        '''
        :avocado: tags=tier2,cloudinit
        RHEL-189226 - CLOUDINIT-TC: checking random password and its length
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        cmd = 'sudo cat /var/log/messages'
        utils_lib.run_cmd(self, cmd, expect_kw='cloud-user:')
        output = self.session.cmd_output('sudo cat /var/log/messages|grep "cloud-user:"').split("cloud-user:",1)[1]
        self.assertEqual(len(output), 20)

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
            # checking /etc/sysconfig/network NOZEROCONF=yes
            output = self.session.cmd_output('sudo cat /etc/sysconfig/network')
            self.log.info("run: cat /etc/sysconfig/network  " + output)
            # checking if there is 'Traceback' in log
            cmd = 'sudo cat /var/log/cloud-init.log'
            utils_lib.run_cmd(self,
                          cmd,
                          expect_ret=0,
                          expect_not_kw='Traceback',
                          msg=str(x)+' run: check Traceback in /var/log/cloud-init.log',
                          is_get_console=False)

            time.sleep(30)

    def test_cloudutils_growpart_resize_partition_first_boot(self):
        """
        :avocado: tags=tier1,cloud_utils_growpart
        RHEL-188669 - CLOUDINIT-TC:[cloud-utils-growpart]resize partition during VM first boot
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
        RHEL-171053 - CLOUDINIT-TC: [cloud-utils-growpart] Auto resize\
                     partition in gpt
        BZ#1695091
        """
        self.log.info("RHEL-171053: CLOUDINIT-TC: [cloud-utils-growpart] \
Auto resize partition in gpt")
        self._growpart_auto_resize_partition("gpt")


    def test_cloudutils_growpart_auto_resize_partition_in_mbr(self):
        """
        :avocado: tags=tier1,cloud_utils_growpart
        RHEL-188633 - CLOUDINIT-TC: [cloud-utils-growpart] Auto resize\
                     partition in MBR
        """
        self.log.info("RHEL-188633: CLOUDINIT-TC: [cloud-utils-growpart] Auto resize\
                     partition in MBR")
        self._growpart_auto_resize_partition("msdos")


    def test_cloudinit_login_with_password(self):
        """
        :avocado: tags=tier1,cloudinit
        RHEL7-103830 - CLOUDINIT-TC: VM can successfully login
        after provisioning(with password authentication)
        1. Create a VM with only password authentication
        2. Login with password, should have sudo privilege
        """
        import base64     
        self.log.info(
            "RHEL7-103830 - CLOUDINIT-TC: VM can successfully login "
            "after provisioning(with password authentication)")
        
        user_data = """\
#cloud-config

user: {0}
password: {1}
chpasswd: {{ expire: False }}
ssh_pwauth: 1
""".format(self.vm.vm_username, self.vm.vm_password)
        self.vm.user_data = base64.b64encode(
                user_data.encode('utf-8')).decode('utf-8')
        self.vm.keypair = None
        self.vm.create(wait=True)
        self.session.connect(authentication="password")
        self.assertEqual(self.vm.vm_username,
                         self.session.cmd_output("whoami"),
                         "Fail to login with password")
        self.assertIn(
            "%s ALL=(ALL) NOPASSWD:ALL" % self.vm.vm_username,
            self.session.cmd_output(
                "sudo cat /etc/sudoers.d/90-cloud-init-users"),
            "No sudo privilege")    

    def test_cloudinit_create_vm_config_drive(self):
        """
        :avocado: tags=tier1,cloudinit
        RHEL-189225 - CLOUDINIT-TC: launch vm with config drive
        basic case of config drive
        1. Create a VM with datasource 'Config Drive'
        2. Login and check user sudo privilege
        3. check data source in /run/cloud-init/cloud.cfg
        """
        self.log.info(
            "RHEL-189225 - CLOUDINIT-TC: launch vm with config drive")
        self.vm.config_drive = True    
        self.session = self.cloud.init_vm(pre_delete=True,
                                          pre_stop=False)
        output = self.session.cmd_output('whoami')
        self.assertEqual(
            self.vm.vm_username, output,
            "Login VM with publickey error: output of cmd `whoami` unexpected -> %s"
            % output)
        self.assertIn(
            "%s ALL=(ALL) NOPASSWD:ALL" % self.vm.vm_username,
            self.session.cmd_output(
                "sudo cat /etc/sudoers.d/90-cloud-init-users"),
            "No sudo privilege")  

        cmd = 'sudo cat /run/cloud-init/cloud.cfg'
        utils_lib.run_cmd(self,
                          cmd,
                          expect_ret=0,
                          expect_kw='ConfigDrive',
                          msg='check if ConfigDrive in /run/cloud-init/cloud.cfg',
                          is_get_console=False)


    def test_cloudinit_create_vm_two_nics(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-186186 - CLOUDINIT-TC: launch an instance with 2 interfaces
        basic case of two nics, the second nic is default ipv6 mode slaac
        1. Create a VM with two nics
        2. Login and check user
        3. check ifcfg-eth1 file
        """
        self.log.info(
            "RHEL-186186 - CLOUDINIT-TC: launch an instance with 2 interfaces")
        # the second nic using hard code? (the second network only contains ipv6, network name provider_net_ipv6_only, ipv6 slaac)
        # if the second nic has ipv4, the ssh login may select it but it could not be connected
        # this solution ensure ssh using eth0 ipv4
        self.vm.second_nic_id = "10e45d6d-5924-48ee-9f5a-9713f5facc36"
        self.session = self.cloud.init_vm(pre_delete=True,
                                          pre_stop=False)
        output = self.session.cmd_output('whoami')
        self.assertEqual(
            self.vm.vm_username, output,
            "Login VM with publickey error: output of cmd `whoami` unexpected -> %s"
            % output)
        cmd = 'ip addr show eth1'
        utils_lib.run_cmd(self, cmd, expect_kw=',UP,')
        cmd = 'cat /etc/sysconfig/network-scripts/ifcfg-eth1'
        utils_lib.run_cmd(self, cmd, expect_kw='DEVICE=eth1')


    def test_cloudinit_create_vm_stateless_ipv6(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-186180 - CLOUDINIT-TC: correct config for dhcp-stateless openstack subnets
        1. Create a VM with two nics, the second nic is stateless ipv6 mode
        2. Login and check user
        3. check ifcfg-eth1 file
        """
        self.log.info(
            "RHEL-186180 - CLOUDINIT-TC: correct config for dhcp-stateless openstack subnets")
        # the second nic using hard code?  (net-ipv6-stateless, only subnet ipv6, dhcp-stateless)
        self.vm.second_nic_id = "e66c7343-98d6-4f07-9d64-2b8bb31d7df8"
        self.session = self.cloud.init_vm(pre_delete=True,
                                          pre_stop=False)
        output = self.session.cmd_output('whoami')
        self.assertEqual(
            self.vm.vm_username, output,
            "Login VM with publickey error: output of cmd `whoami` unexpected -> %s"
            % output)
        # change command to ip addr because of no net-tool by default in rhel8.4
        cmd = 'ip addr show eth1'
        utils_lib.run_cmd(self, cmd, expect_kw=',UP,')
        cmd = 'cat /etc/sysconfig/network-scripts/ifcfg-eth1'
        utils_lib.run_cmd(self, cmd, expect_kw='DHCPV6C_OPTIONS=-S,IPV6_AUTOCONF=yes')


    def test_cloudinit_create_vm_stateful_ipv6(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-186181 - CLOUDINIT-TC: correct config for dhcp-stateful openstack subnets
        1. Create a VM with two nics, the second nic is dhcp-stateful ipv6 mode
        2. Login and check user
        3. check ifcfg-eth1 file
        """
        self.log.info(
            "RHEL-186181 - CLOUDINIT-TC: correct config for dhcp-stateful openstack subnets")
        # the second nic using hard code? (net-ipv6-stateful, only subnet ipv6, dhcp-stateful)
        self.vm.second_nic_id = "9b57a458-5c76-4e4e-b6bf-f1e01388a3b4"
        self.session = self.cloud.init_vm(pre_delete=True,
                                          pre_stop=False)
        output = self.session.cmd_output('whoami')
        self.assertEqual(
            self.vm.vm_username, output,
            "Login VM with publickey error: output of cmd `whoami` unexpected -> %s"
            % output)
        cmd = 'ip addr show eth1'
        utils_lib.run_cmd(self, cmd, expect_kw=',UP,')
        cmd = 'cat /etc/sysconfig/network-scripts/ifcfg-eth1'
        utils_lib.run_cmd(self, cmd, expect_kw='IPV6_FORCE_ACCEPT_RA=yes')

    
    def test_cloudinit_check_ifcfg_no_startmode(self):
        '''
        :avocado: tags=tier2,cloudinit
        RHEL-199308 - CLOUDINIT-TC: Check the network config file ifcfg-xxx	
        bz#: 1931835,1930507
        check no STARTMODE in ifcfg-eth0, the case is for rhel > 8.2
        '''
        self.log.info(
            "RHEL-199308 - CLOUDINIT-TC: Check the network config file ifcfg-xxx")
        self.session.connect(timeout=self.ssh_wait_timeout)
        rhel_ver = self.session.cmd_output("sudo cat /etc/redhat-release")
        rhel_ver = float(re.search('release\s+(\d+.\d+)\s+', rhel_ver).group(1))
        if rhel_ver > 8.2:            
            nic_interface = self.session.cmd_output("ip link show up | grep 'BROADCAST,MULTICAST' | head -1")
            nic_interface = re.search('\d+:\s+([a-zA-Z0-9]+):', nic_interface).group(1)
            cmd = 'sudo cat /etc/sysconfig/network-scripts/ifcfg-{}'.format(nic_interface)
            utils_lib.run_cmd(self,
                              cmd,
                              expect_ret=0,
                              expect_not_kw='STARTMODE',
                              msg='check /etc/sysconfig/network-scripts/ifcfg-{}'.format(nic_interface),
                              is_get_console=False)
        else:
            self.cancel("RHEL is < 8.3. Skip this case.")
        

    def test_cloudinit_no_duplicate_swap(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-205128 - CLOUDINIT-TC: Can deal with the conflict of having swap configured on /etc/fstab 
        *and* having cloud-init duplicating this configuration automatically
        1. Deploy a VM, attach an additional volume(or dd a file) to mkswap. 
        Add it to /etc/fstab, swapon, then check the free -m
        2. Configure cloud-init, /etc/cloud/cloud.cfg.d/cc_mount.cfg
        3. Use this VM as a template and create a new VM_new based on this VM
        4. Login VM_new and check /etc/fstab, no duplicate swap entry
        """
        self.log.info(
            "RHEL-205128 - CLOUDINIT-TC: Can deal with the conflict of having swap configured on /etc/fstab")
        self.session.connect(timeout=self.ssh_wait_timeout)
        self.session.cmd_output("sudo su")
        self.session.cmd_output("dd if=/dev/zero of=/root/swapfile01 bs=1M count=1024")
        self.session.cmd_output("chmod 600 /root/swapfile01")
        self.session.cmd_output("mkswap -L swap01 /root/swapfile01")
        self.session.cmd_output("echo '/root/swapfile01    swap    swap    defaults    0 0' >> /etc/fstab")
        old_fstab = self.session.cmd_output("cat /etc/fstab")
        self.session.cmd_output("swapon -a")
        old_swap = self.session.cmd_output("free -m|grep Swap|awk '{print $2}'")
        cloudinit_config = """\
mounts:
  - ["/root/swapfile01"]
"""
        self.session.cmd_output("echo '''{}''' > /etc/cloud/cloud.cfg.d/cc_mount.cfg".format(cloudinit_config))
        self.session.cmd_output("rm -rf /var/lib/cloud/instance/sem")
        self.session.cmd_output("cloud-init single --name cc_mounts")
        self.session.cmd_output("swapoff -a")
        self.session.cmd_output("swapon -a")
        new_swap = self.session.cmd_output("free -m|grep Swap|awk '{print $2}'")
        new_fstab = self.session.cmd_output("cat /etc/fstab")
        # clean the swap config
        self.session.cmd_output("swapoff -a")
        self.session.cmd_output("rm -rf /etc/cloud/cloud.cfg.d/cc_mount.cfg")
        self.session.cmd_output("sed -i '/swapfile01/d' /etc/fstab")
        self.session.cmd_output("rm -rf /root/swapfile01")
        self.session.cmd_output("exit")
        self.assertNotEqual(old_swap, '0',
            "Swap size is 0 before cloud-init config")
        self.assertEqual(old_swap, new_swap,
            "Swap size is not same before and after cloud-init config")
        self.assertEqual(old_fstab, new_fstab,
            "The /etc/fstab is not same before and after cloud-init config")


    def tearDown(self):
        if self.name.name.endswith("test_cloudinit_login_with_password"):
            self.vm.delete(wait=True)
        self.session.close()
