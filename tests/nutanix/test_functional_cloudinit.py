import os
import re
import time
import yaml
from avocado import Test
from avocado import main
from avocado_cloud.app import Setup
from avocado_cloud.app.nutanix.nutanix import PrismApi
#from avocado_cloud.app.azure import AzureNIC
#from avocado_cloud.app.azure import AzurePublicIP
#from avocado_cloud.app.azure import AzureNicIpConfig
#from avocado_cloud.app.azure import AzureImage
from distutils.version import LooseVersion
from avocado_cloud.utils import utils_nutanix
import logging

BASEPATH = os.path.abspath(__file__ + "/../../../")


class D(dict):
    # Don't raise exception if cannot get key value
    def __missing__(self, key):
        self[key] = D()
        return self[key]


class CloudinitTest(Test):
    def setUp(self):
        self.cloud = Setup(self.params, self.name)
        self.vm = self.cloud.vm
        self.prism = PrismApi(self.params)
        pre_delete = False
        pre_stop = False
        self.case_short_name = re.findall(r"Test.(.*)", self.name.name)[0]
        self.pwd = os.path.abspath(os.path.dirname(__file__))
        self.project = self.params.get("rhel_ver", "*/VM/*")
        self.package = self.params.get("packages", "*/Other/*")
	# For below cases, we create a new VM instance.
        if self.case_short_name in [
            "test_cloudinit_login_with_password",
            "test_cloudinit_login_with_publickey",
            "test_cloudinit_save_and_handle_customdata_script",
            "test_cloudinit_save_and_handle_customdata_runcmd",
            "test_cloudinit_save_and_handle_customdata_cloudinit_config",
            "test_cloudinit_provision_vm_with_multiple_nics",
            "test_cloudinit_remove_cache_and_reboot_password"
        ]:
            if self.vm.exists():
                self.vm.delete(wait=True)
            self.session = self.cloud.init_session()
            return
        self.session = self.cloud.init_vm(pre_delete=pre_delete,
                                          pre_stop=pre_stop)
        # For below cases, we add subscription account.
        if self.case_short_name in [
            "test_cloudinit_auto_register_with_subscription_manager",
            "test_cloudinit_auto_install_package_with_subscription_manager",
            "test_cloudinit_verify_rh_subscription_enablerepo_disablerepo",
            "test_cloudinit_auto_extend_root_partition_and_filesystem",
            "test_cloudinit_no_networkmanager"
        ]:
            self.subscription_username = self.params.get("username", "*/Subscription/*")
            self.subscription_password = self.params.get("password", "*/Subscription/*")
            self.session.cmd_output("sudo su -")
            #self.session.cmd_output("rpm -e rhui-azure-rhel{}".format(self.project.split('.')[0]))
                                          
    def _postfix(self):
        from datetime import datetime
        return datetime.strftime(datetime.now(), "%Y%m%d%H%M%S")

    def test_cloudinit_login_with_password(self):
        """
        :avocado: tags=tier1,cloudinit
        RHEL7-87233: WALA-TC: [Cloudinit] VM can successfully login
        after provisioning(with password authentication)
        1. Create a VM with only password authentication
        2. Login with password, should have sudo privilege
        """
        self.log.info(
            "RHEL7-87233: WALA-TC: [Cloudinit] VM can successfully login "
            "after provisioning(with password authentication)")
        self.vm.ssh_pubkey = None
        self.vm.create(wait=True)
        self.vm.start(wait=True)
        self.session.connect(authentication="password")
        self.assertEqual(self.vm.vm_username,
                         self.session.cmd_output("whoami"),
                         "Fail to login with password")
        self.assertIn(
            "%s ALL=(ALL) NOPASSWD:ALL" % self.vm.vm_username,
            self.session.cmd_output(
                "sudo cat /etc/sudoers.d/90-cloud-init-users"),
            "No sudo privilege")

    def test_cloudinit_login_with_publickey(self):
        """
        :avocado: tags=tier1,cloudinit,cloud_utils_growpart,dependencies
        RHEL7-87453: WALA-TC: [Cloudinit] VM can successfully login
        after provisioning(with publickey authentication)
        1. Create a VM with only public key authentication
        2. Login with publickey, should have sudo privilege
        """
        self.log.info(
            "RHEL7-87453: WALA-TC: [Cloudinit] VM can successfully login "
            "after provisioning(with publickey authentication)")
        self.vm.create(wait=True)
        self.vm.start(wait=True)
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
            utils_nutanix.command("mkdir -p {}".format(host_logpath))
            self.session.copy_files_from("/tmp/logs/*", host_logpath)
        except:
            pass

    def test_cloudinit_verify_hostname(self):
        """
        :avocado: tags=tier1,cloudinit
        RHEL7-87350: WALA-TC: [Cloudinit] Successfully set VM hostname
        1. Verify VM hostname
        """
        self.log.info(
            "RHEL7-87350: WALA-TC: [Cloudinit] Successfully set VM hostname")
        cmd_list = [
            'hostname', 'nmcli general hostname', 'hostnamectl|grep Static'
        ]
        for cmd in cmd_list:
            self.assertIn(self.vm.vm_name, self.session.cmd_output(cmd),
                          "'%s': Hostname is not correct" % cmd)

    def test_cloudinit_check_startup_time(self):
        '''
        :avocado: tags=tier2,cloudinit
        RHEL-189580 - CLOUDINIT-TC: Check VM first launch time and cloud-init startup time
        Verify cloud-init related services startup time <15s per service, and <40s in total
        '''
        self.log.info("RHEL-189580	CLOUDINIT-TC: Check VM first launch time and cloud-init startup time")
        limit = 15
        total_limit = 40
        total = 0
        for retry in range(1, 11):
            if "Bootup is not yet finished" not in self.session.cmd_output("systemd-analyze"):
                break
            self.log.info("Bootup is not yet finished. Wating for 10s and retry...({}/10)".format(retry))
            time.sleep(10)
        else:
            self.error("Bootup is not finished in 100s. Exit.")
        for line in self.session.cmd_output("systemd-analyze blame|grep -E '(cloud-init-local|cloud-init|cloud-final|cloud-config)'|sed 's/^ *//g'").split('\n'):
            real_time, service = line.split(' ')
            if 'ms' in real_time:
                real_time = float(real_time.rstrip('ms')) / 1000
            else:
                real_time = float(real_time.rstrip('s'))
            total += real_time
            self.assertTrue(real_time < limit, "{} service startup time is {}s >= {}s".format(service, real_time, limit))
        self.assertTrue(total < total_limit, "All the services startup time is {}s >= {}s".format(total, total_limit))

    def test_cloudinit_check_critical_log(self):
        """
        :avocado: tags=tier1,cloudinit
        RHEL-188029: WALA-TC: [Cloudinit] Check CRITICAL cloud-init log
        Check cloud-init log. There shouldn't be CRITICAL logs.
        """
        self.log.info(
            "RHEL-188029: WALA-TC: [Cloudinit] Check CRITICAL cloud-init log")
        output = self.session.cmd_output(
            "sudo grep -i 'critical' /var/log/cloud-init.log")
        self.assertEqual(
            "", output, "There're CRITICAL logs: {0}".format(output))

    def _check_cloudinit_log(self, additional_ignore_msg=None):
        with open("{}/data/azure/ignore_cloudinit_messages".format(BASEPATH),
                  'r') as f:
            ignore_message_list = f.read().split('\n')
        if additional_ignore_msg and isinstance(additional_ignore_msg, list):
            ignore_message_list += additional_ignore_msg
        output = self.session.cmd_output(
            "sudo grep -iE -w 'err.*|fail.*|warn.*|unexpected.*|traceback.*' /var/log/cloud-init.log|grep -vE '{0}'"
            .format('|'.join(ignore_message_list)))
        self.assertEqual("", output, "There're error logs: {0}".format(output))

    def test_cloudinit_check_cloudinit_log(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-151376: WALA-TC: [Cloudinit] Check cloud-init log
        Check cloud-init log. There shouldn't be unexpected error logs.
        """
        self.log.info("RHEL-151376: WALA-TC: [Cloudinit] Check cloud-init log")
        self._check_cloudinit_log()

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


    def _verify_rh_subscription(self, config):
        # self.session.copy_files_to(
        #     local_path="/tmp/config_rh_subscription",
        #     remote_path="/tmp/config_rh_subscription"
        # )
        self.session.cmd_output("sudo su -")
        self.session.cmd_output("subscription-manager unregister")
        self.session.cmd_output(
            "rm -f /var/lib/cloud/instance/sem/config_rh_subscription /var/log/cloud-init*.log")
        if "packages" in config:
            self.session.cmd_output(
                "rm -f /var/lib/cloud/instance/sem/config_package_update_upgrade_install")
        self.session.cmd_output("echo '''{}''' > /etc/cloud/cloud.cfg.d/test_rh_subscription.cfg".format(config))
        if "packages" in config:
            self.session.cmd_output("cloud-init modules --mode config", timeout=600)
        else:
            self.session.cmd_output("cloud-init single -n rh_subscription", timeout=600)
        self.assertEqual(self.session.cmd_status_output(
            "grep 'Registered successfully' /var/log/cloud-init.log")[0], 0,
            "No 'Registered successfully log in cloud-init.log")
        self.assertEqual(self.session.cmd_status_output("subscription-manager identity")[0], 0,
            "Fail to register with subscription-manager")
        self._check_cloudinit_log(additional_ignore_msg=["WARNING"])

    def test_cloudinit_auto_register_with_subscription_manager(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-181761 CLOUDINIT-TC: auto register by cloud-init
        1. Add content to /etc/cloud/cloud.cfg.d/test_rh_subscription.cfg
'       rh_subscription:
          username: ******
          password: ******
        2. Run rh_subscription module
        3. Verify can register with subscription-manager
        4. Verify can auto-attach manually
        """
        self.log.info("RHEL-181761 CLOUDINIT-TC: auto register by cloud-init")
        CONFIG='''\
rh_subscription:
  username: {}
  password: {}'''.format(self.subscription_username, self.subscription_password)
        self._verify_rh_subscription(CONFIG)

   # def test_cloudinit_file_injection(self):
   # file can be injected at creation of a VM.

    def test_cloudinit_save_and_handle_customdata_runcmd(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL7-103837 - CLOUDINIT-TC: Save and handle customdata(runcmd)
        1. Create VM with custom data
        2. Check if custom data command is executed
        """
        self.log.info("RHEL7-103837 - CLOUDINIT-TC: Save and handle customdata(script)")
        # Below command will be part of cloud-config.txt.
        self.vm.vm_user_data = "\nruncmd:\n  - echo 'teststring' >> /var/log/test.log"
        self.vm.create(wait=True)
        self.vm.start(wait=True)
        self.session.connect()
        # Check if custom data command is executed.
        for retry in range(1, 11):
            if utils_nutanix.file_exists("/var/log/test.log", self.session):
                break
            self.log.info("/var/log/test.log doesn't exist. Wait for 10s and retry...({}/10)".format(retry))
            time.sleep(10)
        self.assertEqual("teststring",
                         self.session.cmd_output("cat /var/log/test.log"),
                         "The custom data script is not executed correctly.")

    def test_cloudinit_save_and_handle_customdata_script(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL7-103837 - CLOUDINIT-TC: Save and handle customdata(script)
        1. Create VM with custom data
        2. Check if custom data command is executed
        """
        self.log.info("RHEL7-103837 - CLOUDINIT-TC: Save and handle customdata(script)")
        # Prepare custom script
        # This script must be SFTP'ed to storage container first!
        self.vm.vm_custom_file = "customdata.sh"
        self.vm.create(wait=True)
        self.vm.start(wait=True)
        self.session.connect()
        # Check if custom data command is executed.
        self.session.cmd_output("sudo su -;")
        self.session.cmd_output("chmod 777 /tmp/%s" % self.vm.vm_custom_file)
        self.session.cmd_output("/tmp/%s" % self.vm.vm_custom_file)
        self.assertEqual("teststring",
                         self.session.cmd_output("cat /var/log/test1.log"),
                         "The custom data script is not executed correctly.")

    def test_cloudinit_save_and_handle_customdata_cloudinit_config(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL7-103838 - CLOUDINIT-TC: Save and handle customdata(cloud-init configuration)
        1. Create VM with custom data
        2. Get CustomData from ovf-env.xml, decode it and compare with
           original custom data file
        3. Check if the new cloud-init configuration is handled correctly
        """
        self.log.info(
            "RHEL7-103838 - CLOUDINIT-TC: Save and handle customdata(cloud-init configuration)")
        # Prepare custom data
        self.vm.vm_user_data = "\ncloud_config_modules:\n - mounts\n - locale\n - set-passwords\n - yum-add-repo\n - disable-ec2-metadata\n - runcmd"
        self.vm.create(wait=True)
        self.vm.start(wait=True)
        self.session.connect()
        # 3. Check if the new cloud-init configuration is handled correctly
        # (There should be 6 modules ran in cloud-init.log)
        output = self.session.cmd_output(
            "sudo grep 'running modules for config' "
            "/var/log/cloud-init.log -B 10")
        self.assertIn("Ran 6 modules", output,
                      "The custom data is not handled correctly")

    def _get_boot_temp_devices(self):
        boot_dev = self.session.cmd_output("mount|grep 'boot'|head -1|cut -c1-8")
        temp_dev = '/dev/sda' if boot_dev == '/dev/sdb' else '/dev/sdb'
        return(boot_dev, temp_dev)

    def test_cloudinit_auto_extend_root_partition_and_filesystem(self):
        """
        :avocado: tags=tier1,cloudinit,cloud_utils_growpart
        RHEL7-103839 - CLOUDINIT-TC: Auto extend root partition and filesystem
        1. Install cloud-utils-growpart gdisk if not installed(bug 1447177)
        2. Check os disk and fs capacity
        3. Stop VM. Enlarge os disk
        4. Start VM and login. Check os disk and fs capacity
        """
        self.log.info("RHEL7-103839 - CLOUDINIT-TC: Auto extend root partition and filesystem")
        # 1. Install cloud-utils-growpart gdisk
        if self.session.cmd_status_output(
                "rpm -q cloud-utils-growpart gdisk")[0] != 0:
            self.session.cmd_output("sudo subscription-manager register --username {}\
                                      --password {}".format(self.subscription_username, \
                                      self.subscription_password), timeout=600)
            self.session.cmd_output("sudo yum install -y cloud-utils-growpart gdisk", timeout=600)
            if self.session.cmd_status_output("rpm -q cloud-utils-growpart gdisk")[0] != 0:
                self.fail("Cannot install cloud-utils-growpart gdisk packages")
        # 2. Check os disk and fs capacity
        boot_dev = self._get_boot_temp_devices()[0].split('/')[-1]
        partition = self.session.cmd_output(
            "find /dev/ -name {}[0-9]|sort|tail -n 1".format(boot_dev))
        dev_size = self.session.cmd_output(
            "lsblk /dev/{0} --output NAME,SIZE -r"
            "|grep -o -P '(?<={0} ).*(?=G)'".format(boot_dev))
        fs_size = self.session.cmd_output(
            "df {} --output=size -h|grep -o '[0-9.]\+'".format(partition))
        os_disk_size = int(self.vm.show()['vm_disk_info'][0]['size'])/(1024*1024*1024)
        self.assertAlmostEqual(
            first=float(dev_size),
            second=float(os_disk_size),
            delta=1,
            msg="Device size is incorrect. Raw disk: %s, real: %s" %
            (dev_size, os_disk_size))
        # 3. Enlarge os disk size
        logging.debug("================print vm_disk_info to debug============================")
        logging.debug(self.vm.show()['vm_disk_info'])
        logging.debug("===================================================================")
        os_disk_uuid = self.vm.show()['vm_disk_info'][0]['disk_address']['vmdisk_uuid']
        self.prism.expand_disk(disk_uuid=os_disk_uuid, disk_size=os_disk_size+2)
        self.vm.reboot(wait=True)
        self.session.connect()
        boot_dev = self._get_boot_temp_devices()[0].split('/')[-1]
        partition = self.session.cmd_output(
            "find /dev/ -name {}[0-9]|sort|tail -n 1".format(boot_dev))
        new_dev_size = self.session.cmd_output(
            "lsblk /dev/{0} --output NAME,SIZE -r"
            "|grep -o -P '(?<={0} ).*(?=G)'".format(boot_dev))
        new_fs_size = self.session.cmd_output(
            "df {} --output=size -h|grep -o '[0-9]\+'".format(partition))
        new_os_disk_size=os_disk_size+2
        self.assertEqual(
            int(new_dev_size), int(new_os_disk_size),
            "New device size is incorrect. "
            "Device: %s, real: %s" % (new_dev_size, new_os_disk_size))
        self.assertAlmostEqual(first=float(new_fs_size),
                               second=float(new_os_disk_size),
                               delta=1.5,
                               msg="New filesystem size is incorrect. "
                               "FS: %s, real: %s" %
                               (new_fs_size, new_os_disk_size))

    def test_cloudinit_regenerate_sshd_keypairs(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL7-103836 - CLOUDINIT-TC: Default configuration can regenerate sshd keypairs
        1. Verify cloud.cfg: ssh_deletekeys:   1
        2. Deprovision image. Create a new VM base on this image
        3. Login and compare the md5 of the new and old sshd_host* files.
           Should regenerate them.
        """
        self.log.info(
            "RHEL7-103836 - CLOUDINIT-TC: Default configuration can regenerate sshd keypairs")
        # Login with root
        self.session.cmd_output("sudo /usr/bin/cp -a /home/{0}/.ssh /root/;"
                                "sudo chown -R root:root /root/.ssh".format(
                                    self.vm.vm_username))
        self.session.close()
        origin_username = self.vm.vm_username
        self.vm.vm_username = "root"
        self.session.connect(authentication="publickey")
        # Verify cloud.cfg ssh_deletekeys:   0
        self.assertEqual(
            self.session.cmd_status_output(
                "grep -E '(ssh_deletekeys: *1)' /etc/cloud/cloud.cfg")[0], 0,
            "ssh_deletekeys: 1 is not in cloud.cfg")
        old_md5 = self.session.cmd_output("md5sum /etc/ssh/ssh_host_rsa_key "
                                          "/etc/ssh/ssh_host_ecdsa_key "
                                          "/etc/ssh/ssh_host_ed25519_key")
        # Deprovision image
        mode = "cloudinit"
        script = "deprovision_package.sh"
        self.session.copy_files_to(local_path="{}/../../scripts/{}".format(
            self.pwd, script),
            remote_path="/tmp/{}".format(script))
        ret, output = self.session.cmd_status_output(
            "/bin/bash /tmp/{} all {} {}".format(script, mode, origin_username))
        self.assertEqual(ret, 0, "Deprovision VM failed.\n{0}".format(output))
        self.session.close()
        # Delete VM
        self.vm.delete(wait=True)
        self.vm.vm_username = origin_username
        self.vm.create(wait=True)
        self.vm.start(wait=True)
        self.session.connect()
        new_md5 = self.session.cmd_output(
            "sudo md5sum /etc/ssh/ssh_host_rsa_key "
            "/etc/ssh/ssh_host_ecdsa_key "
            "/etc/ssh/ssh_host_ed25519_key")
        self.assertNotEqual(old_md5, new_md5,
                            "The ssh host keys are not regenerated.")

    def _cloudinit_auto_resize_partition(self, label):
        """
        :param label: msdos/gpt
        """
        self.session.cmd_output("sudo su -")
        self.assertEqual(
            self.session.cmd_status_output("which growpart")[0], 0,
            "No growpart command.")
        device = "/tmp/testdisk"
        if "/dev" not in device:
            self.session.cmd_output("rm -f {}".format(device))
        self.session.cmd_output("truncate -s 2G {}".format(device))
        self.session.cmd_output(
            "parted -s {} mklabel {}".format(device, label))
        part_type = "primary" if label == "msdos" else ""
        # 1 partition
        self.session.cmd_output(
            "parted -s {} mkpart {} xfs 0 1000".format(device, part_type))
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
            "parted -s {} mkpart {} xfs 0 1000".format(device, part_type))
        self.session.cmd_output(
            "parted -s {} mkpart {} xfs 1800 1900".format(device, part_type))
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

    def test_cloudinit_auto_resize_partition_in_gpt(self):
        """
        :avocado: tags=tier1,cloud_utils_growpart
        RHEL-171053: CLOUDINIT-TC: [cloud-utils-growpart] Auto resize\
                     partition in gpt
        BZ#1695091
        """
        self.log.info("RHEL-171053: CLOUDINIT-TC: [cloud-utils-growpart] \
Auto resize partition in gpt")
        self._cloudinit_auto_resize_partition("gpt")

    def test_cloudinit_auto_resize_partition_in_mbr(self):
        """
        :avocado: tags=tier1,cloud_utils_growpart
        RHEL-188633: CLOUDINIT-TC: [cloud-utils-growpart] Auto resize\
                     partition in MBR
        """
        self.log.info("RHEL-188633: CLOUDINIT-TC: [cloud-utils-growpart] \
Auto resize partition in gpt")
        self._cloudinit_auto_resize_partition("msdos")

    def test_cloudinit_start_sector_equal_to_partition_size(self):
        """
        :avocado: tags=tier1,cloud_utils_growpart
        RHEL-171175: CLOUDINIT-TC: [cloud-utils-growpart] Start sector equal
                     to partition size
        BZ#1593451
        """
        self.log.info("RHEL-171175: CLOUDINIT-TC: [cloud-utils-growpart] \
Start sector equal to partition size")
        self.session.cmd_output("sudo su -")
        self.assertEqual(
            self.session.cmd_status_output("which growpart")[0], 0,
            "No growpart command.")
        device = "/tmp/testdisk"
        if "/dev" not in device:
            self.session.cmd_output("rm -f {}".format(device))
        self.session.cmd_output("truncate -s 2G {}".format(device))
        size = "1026048"
        self.session.cmd_output("""
cat > partitions.txt <<EOF
# partition table of {0}
unit: sectors

{0}1 : start= 2048, size= 1024000, Id=83
{0}2 : start= {1}, size= {1}, Id=83
EOF""".format(device, size))
        self.session.cmd_output("sfdisk {} < partitions.txt".format(device))
        self.session.cmd_output("growpart {} 2".format(device))
        start = self.session.cmd_output(
            "parted -s %s unit s print|grep ' 2 '|awk '{print $2}'" % device)
        end = self.session.cmd_output(
            "parted -s %s unit s print|grep ' 2 '|awk '{print $3}'" % device)
        self.assertEqual(start, size + 's', "Start size is not correct")
        self.assertEqual(end, '4194270s', "End size is not correct")

    def test_cloudinit_provision_vm_with_multiple_nics(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-176196	WALA-TC: [Cloudinit] Provision VM with multiple NICs
        1. Create a VM with 2 NICs
        2. Check if can provision and connect to the VM successfully
        """
        self.log.info(
            "RHEL-171393	WALA-TC: [Network] Provision VM with multiple NICs")
        self.prism.create_network()
        self.vm.create(wait=True)
        self.vm.start(wait=True)
        self.session.connect(timeout=60)
        ip_list_vm = self.session.cmd_output(
            "ip addr|grep -Po 'inet \\K.*(?=/)'|grep -v '127.0.0.1'").split(
                '\n').sort()
        ip_list_host = []
        for nic in self.vm.show()["vm_nics"]:
            ip_list_host.append(nic["ip_address"])
        self.assertEqual(
            ip_list_vm, ip_list_host.sort(), "The private IP addresses are wrong.\n"
            "Expect: {}\nReal: {}".format(ip_list_host, ip_list_vm))
        self.vm.delete(wait=True)
        self.prism.delete_networks()
        logging.debug('procedure test_cloudinit_provision_vm_with_multiple_nics finished')

    def _verify_authorizedkeysfile(self, keyfiles):
        self.session.cmd_output("sudo su")
        # 1. Modify /etc/ssh/sshd_config
        self.session.cmd_output(
            "sed -i 's/^AuthorizedKeysFile.*$/AuthorizedKeysFile {}/g' /etc/ssh/sshd_config".format(keyfiles.replace('/', '\/')))
        self.assertEqual(self.session.cmd_status_output("grep '{}' /etc/ssh/sshd_config".format(keyfiles))[0], 0,
                         "Fail to change /etc/ssh/sshd_config AuthorizedKeysFile value.")
        # self.session.cmd_output("systemctl restart sshd")
        # 2. Remove cc_ssh flag and authorized_keys
        self.session.cmd_output(
            "rm -f /var/lib/cloud/instance/sem/config_ssh /home/{}/.ssh/authorized_keys".format(self.vm.vm_username))
        self.session.cmd_output("rm -rf {}".format(keyfiles))
        # 3. Run module ssh
        self.session.cmd_output("cloud-init single -n ssh")
        self.session.cmd_output("systemctl restart sshd")
        # 4. Verify can login and no unexpected files in ~/.ssh
        self.assertTrue(self.session.connect(timeout=10),
                        "Fail to login after run ssh module")
        find_result = self.session.cmd_output("{{ ls /{} 2> /dev/null; ls /home/{}/{} 2> /dev/null|grep -vE id_rsa; }} | cat".format(keyfiles.split()[0].replace("/%u","",1), self.vm.vm_username, keyfiles.split()[0]))
        if keyfiles.split()[0] in find_result and self.vm.vm_username not in find_result:
            self.fail("Cannot find expected key file {}.".format(keyfiles.split()[0]))
        elif ("root" in find_result and len(find_result.split('\n')) > 2) or (".ssh" in find_result and len(find_result.split('\n')) > 1):
            # Found more than <user> and root under /etc/ssh/userkeys/; or more than id_rsa and authorized_keys under .ssh/.
            self.fail("Unexpected files found {}.".format(find_result))

    def test_cloudinit_verify_multiple_files_in_authorizedkeysfile(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-189026	CLOUDINIT-TC: Verify multiple files in AuthorizedKeysFile
        1. Launch VM/instance with cloud-init. Modify /etc/ssh/sshd_config:
        AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/userkeys/%u
        2. Remove cc_ssh module flag and authorized_keys
        3. Run module ssh
        # cloud-init single -n ssh
        4. Verify can login and no unexpected files in ~/.ssh/
        5. Set customized keyfile a the front:
        AuthorizedKeysFile /etc/ssh/userkeys/%u.ssh/authorized_keys
        Restart sshd service and rerun step2-4
        """
        self.log.info(
            "RHEL-189026 CLOUDINIT-TC: Verify multiple files in AuthorizedKeysFile")
        # Backup sshd_config
        self.session.cmd_output("/usr/bin/cp /etc/ssh/sshd_config /root/")
        # AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/userkeys/%u
        self._verify_authorizedkeysfile(
            ".ssh/authorized_keys /etc/ssh/userkeys/%u")
        # AuthorizedKeysFile /etc/ssh/userkeys/%u .ssh/authorized_keys
        self._verify_authorizedkeysfile(
            "/etc/ssh/userkeys/%u .ssh/authorized_keys")
        self.session.cmd_output(
                "mv /root/sshd_config /etc/ssh/sshd_config")

    def test_cloudinit_verify_customized_file_in_authorizedkeysfile(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-189027	CLOUDINIT-TC: Verify customized file in AuthorizedKeysFile
        1. Launch VM/instance with cloud-init. Modify /etc/ssh/sshd_config:
        AuthorizedKeysFile .ssh/authorized_keys2
        2. Remove cc_ssh module flag and authorized_keys
        3. Run module ssh
        # cloud-init single -n ssh
        4. Verify can login successfully
        """
        #
        self.log.info(
            "RHEL-189027 CLOUDINIT-TC: Verify customized file in AuthorizedKeysFile")
        self._verify_authorizedkeysfile(".ssh/authorized_keys2")

    def test_cloudinit_remove_cache_and_reboot_password(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-189049	CLOUDINIT-TC: Reboot with no instance cache - password authentication
        1. Create a VM on Azure with password authentication
        2. Remove the instance cache folder and reboot
        3. Verify can login successfully
        """
        self.log.info(
            "RHEL-189049 CLOUDINIT-TC: Reboot with no instance cache - password authentication")
        self.vm.ssh_pubkey = None
        self.vm.authentication_type = "password"
        self.vm.create(wait=True)
        self.vm.start(wait=True)
        self.session.connect(authentication="password")
        self.session.cmd_output("sudo rm -rf /var/lib/cloud/instances/*")
        self.vm.reboot(wait=True)
        self.assertTrue(self.session.connect(timeout=100, authentication="password"),
                        "Fail to login after restart")

    def _verify_rh_subscription(self, config):
        # self.session.copy_files_to(
        #     local_path="/tmp/config_rh_subscription",
        #     remote_path="/tmp/config_rh_subscription"
        # )
        self.session.cmd_output("sudo su -")
        self.session.cmd_output("subscription-manager unregister")
        self.session.cmd_output(
            "rm -f /var/lib/cloud/instance/sem/config_rh_subscription /var/log/cloud-init*.log")
        if "packages" in config:
            self.session.cmd_output(
                "rm -f /var/lib/cloud/instance/sem/config_package_update_upgrade_install")
        self.session.cmd_output("echo '''{}''' > /etc/cloud/cloud.cfg.d/test_rh_subscription.cfg".format(config))
        if "packages" in config:
            self.session.cmd_output("cloud-init modules --mode config", timeout=600)
        else:
            self.session.cmd_output("cloud-init single -n rh_subscription", timeout=600)
        self.assertEqual(self.session.cmd_status_output(
            "grep 'Registered successfully' /var/log/cloud-init.log")[0], 0,
            "No 'Registered successfully log in cloud-init.log")
        self.assertEqual(self.session.cmd_status_output("subscription-manager identity")[0], 0,
            "Fail to register with subscription-manager")
        self._check_cloudinit_log(additional_ignore_msg=["WARNING"])
        self.session.cmd_output("sudo subscription-manager unregister")

    def test_cloudinit_swapon_with_xfs_filesystem(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-182307 CLOUDINIT-TC: Swapon successful when created on a xfs filesystem by cloud-init	
        1. Add additional data disk and format to xfs, mount to /datatest and add to /etc/fstab
        2. Configure cloud-config and run mounts module
        # cat /etc/cloud/cloud.cfg.d/test_swap.cfg 
        swap:
          filename: /datatest/swap.img
          size: "auto" # or size in bytes
          maxsize: 2G 
        3. Check the swap, verify /datadisk/swap.img exists, verify no error logs in cloud-init.log
        """
        self.log.info("RHEL-182307 CLOUDINIT-TC: Swapon successful when created on a xfs filesystem by cloud-init")
        self.session.cmd_output("sudo su -")
        # Clear old swap by cloud-init. (Is this still valid???)
        self.session.cmd_output("swapoff /datatest/swap.img")
        self.session.cmd_output("umount /datatest")
        self.session.cmd_output("rm -rf /datatest")
        self.session.cmd_output("sed -i '/.*\/datatest.*/d' /etc/fstab")
        # Get previous swap size
        old_swap = self.session.cmd_output("free -m|grep Swap|awk '{print $2}'")
        # Attach data disk
        self.vm.attach_disk(size=5, wait=True)
        time.sleep(10) #Add 10 seconds casue sometimes following command could not get exit status
        self.assertEqual(self.session.cmd_status_output("ls /dev/sdb")[0], 0,
            "No /dev/sdb device after attach data disk")
        self.session.cmd_output("parted /dev/sdb rm 1 -s")
        self.session.cmd_output("parted /dev/sdb mklabel msdos -s")
        self.session.cmd_output("parted /dev/sdb mkpart primary xfs 1048k 4000M -s")
        self.session.cmd_output("mkfs.xfs /dev/sdb1 -f")
        self.session.cmd_output("mkdir -p /datatest")
        self.session.cmd_output("mount /dev/sdb1 /datatest")
        self.assertEqual(self.session.cmd_status_output("mount|grep /datatest")[0], 0,
            "Fail to mount datadisk")
        # Test begin
        CONFIG='''\
swap:
  filename: /datatest/swap.img
  size: "auto" # or size in bytes
  maxsize: 2G'''
        self.session.cmd_output("echo '''{}''' > /etc/cloud/cloud.cfg.d/test_swap.cfg".format(CONFIG))
        self.session.cmd_output("rm -f /var/lib/cloud/instance/sem/config_mounts /var/log/cloud-init*.log")
        self.session.cmd_output("cloud-init single --name mounts")
        new_swap = self.session.cmd_output("free -m|grep Swap|awk '{print $2}'")
        self.assertAlmostEqual(first=int(old_swap)+2047, second=int(new_swap), delta=1,
            msg="The enabled swap size does not correct.")
        self.assertEqual(self.session.cmd_status_output("ls /datatest/swap.img")[0], 0,
            "/datatest/swap.img doesn't exist.")
        self.assertEqual(self.session.cmd_status_output("grep swap.img /etc/fstab")[0], 0,
            "Fail to add swap to /etc/fstab")
        self._check_cloudinit_log()
        self.assertNotEqual(self.session.cmd_status_output(
            "grep 'Permission denied' /var/log/cloud-init-output.log")[0], 0,
            "There are Permission denied logs in /var/log/cloud-init-output.log")

    def test_cloudinit_runcmd_module_execute_command(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-186183 CLOUDINIT-TC:runcmd module:execute commands
        1. Set cloud-init config as:
        runcmd:
          - [ sh, -xc, "echo $(uname -r) ': hello!'" ]
          - [ sh, -c, echo "=========hello world=========" ]
        2. Verify can show command output in output
        """
        self.log.info("RHEL-186183 CLOUDINIT-TC:runcmd module:execute commands")
        self.session.cmd_output("sudo su -")
        CONFIG='''\
runcmd:
  - [ sh, -xc, "echo $(uname -r) ': hello!'" ]
  - [ sh, -c, echo "=========hello world=========" ]'''
        self.session.cmd_output("echo '''{}''' > /etc/cloud/cloud.cfg.d/test_runcmd.cfg".format(CONFIG))
        self.session.cmd_output("rm -f /var/lib/cloud/instance/sem/config_runcmd "
                                "/var/lib/cloud/instance/sem/config_scripts_user "
                                "/var/log/cloud-init*.log")
        self.session.cmd_output("cloud-init single --name runcmd")
        output = self.session.cmd_output("cloud-init single --name scripts_user")
        ret1 = "{} : hello!".format(self.session.cmd_output("uname -r"))
        ret2 = "=========hello world========="
        self.assertIn(ret1, output, "Fail to show cmd1 result. Real:{} Expect:{}".format(output, ret1))
        self.assertIn(ret2, output, "Fail to show cmd2 result. Real:{} Expect:{}".format(output, ret2))
        self._check_cloudinit_log()

    def test_cloudinit_check_ds_identity_path(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-188251 CLOUDINIT-TC: check ds-identify path
        1. Verify /usr/libexec/cloud-init/ds-identify (>=cloud-init-19.4) or 
        /usr/lib/cloud-init/ds-identify (<cloud-init-19.4) exists
        2. Verify "ds-identify _RET=found" in /usr/libexec/cloud-init/ds-identify
        """
        self.log.info("RHEL-188251 CLOUDINIT-TC: check ds-identify path")
        self.session.cmd_output("sudo su -")
        version = self.session.cmd_output("cloud-init -v|awk '{print $2}'")
        if int(self.project.split('.')[0]) >= 8:
            if LooseVersion(version) < LooseVersion("19.4"):
                ds_identify = "/usr/lib/cloud-init/ds-identify"
            else:
                ds_identify = "/usr/libexec/cloud-init/ds-identify"
        else:
            ds_identify = "/usr/lib/cloud-init/ds-identify"
        self.assertEqual(self.session.cmd_status_output("[ -f {} ]".format(ds_identify))[0], 0,
            "{} doesn't exist!".format(ds_identify))
        self.assertEqual(self.session.cmd_status_output(
            "grep 'ds-identify _RET=found' /run/cloud-init/cloud-init-generator.log")[0], 0,
            "Cannot find 'ds-identify _RET=found' in /run/cloud-init/cloud-init-generator.log")

    def test_cloudinit_man_page(self):
        '''
        :avocado: tags=tier2,cloudinit
        RHEL-189322 - CLOUDINIT-TC: Man page for cloud-init
        1. man cloud-init, should have man page
        2. download man-page-day.sh and check with this script
        '''
        self.log.info("RHEL-189322 - CLOUDINIT-TC: Man page for cloud-init")
        self.assertEqual(self.session.cmd_status_output("man cloud-init > /dev/null")[0], 0,
            "Fail to man cloud-init")
        self.session.copy_scripts_to_guest("man-page-day.sh")
        self.assertIn("13x OK", self.session.cmd_output("sudo bash /tmp/man-page-day.sh cloud-init"),
            "man-page-day.sh check failed")

    def test_cloudinit_show_full_version(self):
        '''
        :avocado: tags=tier2,cloudinit
        RHEL-196547	- CLOUDINIT-TC: cloud-init version should show full specific version
        cloud-init --version should show version and release
        '''
        self.log.info("RHEL-196547 - CLOUDINIT-TC: cloud-init version should show full specific version")
        output = self.session.cmd_output("cloud-init --version")
        # Workaround for cloud-init-21.1-8.el9.noarch.rpm. There are '\n's in output like "/usr/bin/cl\noud-init\n21.1-8.el9"
        if '\n' in output:
            output = output.replace('\n', '', 1).replace('\n', ' ', 1)
        package = self.session.cmd_output("rpm -q cloud-init")
        cloudinit_path = self.session.cmd_output("which cloud-init")
        expect = package.rsplit(".", 1)[0].replace("cloud-init-", cloudinit_path+' ')
        self.assertEqual(output, expect, 
            "cloud-init --version doesn't show full version. Real: {}, Expect: {}".format(output, expect))

    def test_cloudinit_check_default_config(self):
        '''
        :avocado: tags=tier2,cloudinit
        RHEL-196560 - CLOUDINIT-TC: Check the cloud-init default config file /etc/cloud/cloud.cfg
        Verify default values in cloud.cfg
        '''
        self.log.info("RHEL-196560 - CLOUDINIT-TC: Check the cloud-init default config file /etc/cloud/cloud.cfg")
        # For now, Nutanix has same config as Azure.
        self.session.copy_data_to_guest('azure', 'default_cloud.cfg')
        diff = self.session.cmd_output("diff /tmp/default_cloud.cfg /etc/cloud/cloud.cfg")
        self.assertEqual(diff, '', 
            "Default cloud.cfg is changed:\n"+diff)

    def test_cloudinit_lang_is_not_en_us_utf8(self):
        '''
        :avocado: tags=tier2,cloud-utils-growpart
        RHEL-189273 CLOUDINIT-TC: [cloud-utils-growpart] growpart works when LANG is not en_US.UTF-8
        Verify cloud-utils-growpart works well when LANG is not en_US.UTF-8
        '''
        self.log.info("RHEL-189273 CLOUDINIT-TC: [cloud-utils-growpart] growpart works when LANG is not en_US.UTF-8")
        self.assertNotIn("unexpected output", self.session.cmd_output("LANG=cs_CZ.UTF-8 growpart /dev/sdb 1 -v -N"),
            "BZ#1885992 growpart doesn't work when LANG=cs_CZ.UTF-8")

    def test_cloudinit_mount_with_noexec_option(self):
        '''
        :avocado: tags=tier2,cloudinit
        RHEL-196483	CLOUDINIT-TC: cloud-init runs well when VM mounts /var/tmp with noexec option
        Bug 1857309 - [Azure][RHEL 8] cloud-init Permission denied with the use of mount option noexec
        '''
        self.log.info("Bug 1857309 - [Azure][RHEL 8] cloud-init Permission denied with the use of mount option noexec")
        self.session.cmd_output("sudo su -")
        # Mount /tmp /var/tmp with noexec option
        self.session.cmd_output("dd if=/dev/zero of=/var/tmp.partition bs=1024 count=1024000")
        self.session.cmd_output("/sbin/mke2fs /var/tmp.partition ")
        self.session.cmd_output("mount -o loop,noexec,nosuid,rw /var/tmp.partition /tmp")
        self.session.cmd_output("chmod 1777 /tmp")
        self.session.cmd_output("mount -o rw,noexec,nosuid,nodev,bind /tmp /var/tmp")
        self.session.cmd_output("echo '/var/tmp.partition /tmp ext2 loop,noexec,nosuid,rw 0 0' >> /etc/fstab")
        self.session.cmd_output("echo '/tmp /var/tmp none rw,noexec,nosuid,nodev,bind 0 0' >> /etc/fstab")
        self.session.cmd_output("rm -rf /var/lib/cloud/instance /var/lib/cloud/instances/* /var/log/cloud-init.log")
        # Restart VM
        self.session.close()
        self.vm.reboot(wait=True)
        self.session.connect()
        # Verify cloud-init.log
        ret, output = self.session.cmd_status_output("sudo grep 'Permission denied' /var/log/cloud-init.log")
        self.assertNotEqual(ret, 0,
            "BZ#1857309. Should not have 'Permission denied' error message:\n"+output)

    def test_cloudinit_no_networkmanager(self):
        '''
        :avocado: tags=tier2,cloudinit
        RHEL-196477	CLOUDINIT-TC: cloud-init works well if NetworkManager not installed
        Bug 1898943 - [rhel-8]cloud-final.service fails if NetworkManager not installed.
        '''
        self.log.info("RHEL-196477 - CLOUDINIT-TC: cloud-init works well if NetworkManager not installed")
        self.session.cmd_output("sudo su -")
        if self.session.cmd_status_output("rpm -q network-scripts")[0] != 0:
            self.session.cmd_output("sudo subscription-manager register --username {}\
                                      --password {}".format(self.subscription_username, \
                                      self.subscription_password), timeout=600)
            self.session.cmd_output("yum install -y network-scripts", timeout=300)
            self.session.cmd_output("/usr/lib/systemd/systemd-sysv-install enable network")
            # Remove ifcfg files other than eth0 and lo
            self.session.cmd_output("rm -f $(find /etc/sysconfig/network-scripts/ifcfg-*|grep -vE '(eth0|lo)')")
            self.assertEqual(self.session.cmd_status_output("systemctl start network")[0], 0,
                "Fail to start network.service")
        self.session.cmd_output("systemctl status network")
        self.session.cmd_output("yum remove -y NetworkManager", timeout=300)
        self.assertNotEqual(self.session.cmd_status_output("rpm -q NetworkManager"), 0,
            "Fail to remove NetworkManager")
        self.session.cmd_output("rm -rf /var/lib/cloud/instance /var/lib/cloud/instances/* /var/log/cloud-init.log")
        # Restart VM and verify connection
        self.session.close()
        self.vm.reboot(wait=True)
        self.assertTrue(self.session.connect(timeout=120), "Fail to connect to VM after remove NetworkManager and restart VM")
        self.assertIn("active (exited)", self.session.cmd_output("sudo systemctl status cloud-final"),
            "cloud-final.service status is not active (exited)")
        self.session.cmd_output("sudo subscription-manager unregister")

    def _generate_password(self, password, hash, salt=''):
        import crypt
        if hash == 'md5':
            crypt_type = '$1$'
        elif hash == 'sha-256':
            crypt_type = '$5$'
        elif hash == 'sha-512':
            crypt_type = '$6$'
        else:
            assert False, 'Unhandled hash option: {}'.format(hash)
        # Generate a random salt
        if salt == '':
            with open('/dev/urandom', 'rb') as urandom:
                while True:
                    byte = urandom.read(1)
                    byte = byte.decode("gbk","ignore")
                    if byte in ('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
                                './0123456789'):
                        salt += byte
                        if len(salt) == 16:
                            break
        salt = crypt_type + salt
        hashed = crypt.crypt(password, salt)
        return hashed

    def test_cloudinit_chpasswd_with_hashed_passwords(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-172679	CLOUDINIT-TC: chpasswd in cloud-init should support hashed passwords
        1. Add 6 users in the VM
        2. Add different passwords to /etc/cloud/cloud.conf.d/test_hash_passwords.cfg
        chpasswd:
          list:
            - test1:(md5 hashed)
            - test2:(sha256 hashed)
            - test3:(sha-512 hashed)
            - test4:RedHat@2019
            - test5:R (random)
            - test6:RANDOM (random)
        3. Verify if cloud-init can handle these passwords
        """
        self.log.info("RHEL-172679 CLOUDINIT-TC: chpasswd in cloud-init should support hashed passwords")
        self.session.cmd_output("sudo su -")
        # Enable boot diagnostic
        #utils_azure.command("az vm boot-diagnostics enable -n {} -g {} --storage https://{}.blob.core.windows.net/"\
        #    .format(self.vm.vm_name, self.vm.resource_group, self.vm.storage_account), timeout=120)
        # Add test1..test6 users in the VM
        for i in range(1, 7):
            user = "test{}".format(str(i))
            self.session.cmd_output("userdel -r {}".format(user))
            self.session.cmd_output("useradd {}".format(user))
            self.assertEqual(self.session.cmd_status_output("id {}".format(user))[0], 0,
                "Fail to create user {}".format(user))
        # Run set_passwords module
        base_pw = "RedHat@2019"
        pw_config_dict = {
            "test1": self._generate_password(base_pw, "md5"),
            "test2": self._generate_password(base_pw, "sha-256"),
            "test3": self._generate_password(base_pw, "sha-512"),
            "test4": base_pw,
            "test5": "R",
            "test6": "RANDOM"
        }
        CONFIG='''\
chpasswd:
  list:
    - test1:{test1}
    - test2:{test2}
    - test3:{test3}
    - test4:{test4}
    - test5:{test5}
    - test6:{test6}'''.format(**pw_config_dict)
        self.session.cmd_output("echo '''{}''' > /etc/cloud/cloud.cfg.d/test_hash_passwords.cfg".format(CONFIG))
        self.session.cmd_output("rm -f /var/lib/cloud/instance/sem/config_set_passwords /var/log/cloud-init*.log")
        output = self.session.cmd_output("cloud-init single --name set_passwords")
        
        #####################Comment this section cause NUTANIXVM has no method to get console log, may be related to BZ2034588(root cause: put log to console error)#####################
        # Verify serial output. Sleep 20s to wait for the serial console log refresh
        #time.sleep(30)
        #serial_output = utils_azure.command("az vm boot-diagnostics get-boot-log -n {} -g {}".format(self.vm.vm_name, self.vm.resource_group), timeout=10, ignore_status=True).stdout
        #for line in serial_output.split('\r\n'):
        #    if "test5" in line:
        #        test5_pw = line.split(':')[1]
        #    elif "test6" in line:
        #        test6_pw = line.split(':')[1]
        #if "test5_pw" not in vars() or "test6_pw" not in vars():
        #    self.fail("Not show random passwords in the serial console")
         #####################Comment this section cause NUTANIXVM has no method to get console log, may be related to BZ2034588(root cause: put log to console error)#####################
        test4_salt = self.session.cmd_output("getent shadow test4").split('$')[2]
        test5_salt = self.session.cmd_output("getent shadow test5").split('$')[2]
        test6_salt = self.session.cmd_output("getent shadow test6").split('$')[2]
        shadow_dict = {
            "test1": pw_config_dict['test1'],
            "test2": pw_config_dict['test2'],
            "test3": pw_config_dict['test3'],
            "test4": "test4:{}:".format(self._generate_password(base_pw, "sha-512", test4_salt)),
            #"test5": "test5:{}:".format(self._generate_password(test5_pw, "sha-512", test5_salt)), #Comment this cause NUTANIXVM has no method to get console log
            #"test6": "test6:{}:".format(self._generate_password(test6_pw, "sha-512", test6_salt)),#Comment this cause NUTANIXVM has no method to get console log
        }
        for user in shadow_dict:
            real = self.session.cmd_output("getent shadow {}".format(user))
            expect = shadow_dict.get(user)
            self.assertIn(expect, real,
                "The {} password in /etc/shadow doesn't meet the expectation. Real:{} Expect:{}".format(user, real, expect))
        #Move this step after checking test4 pwd
        for line in output.split('\n'):
            if "test5" in line:
                test5_pw = line.split(':')[1]
            elif "test6" in line:
                test6_pw = line.split(':')[1]
            elif "failed" in line:
                self.fail("Failed to set password, analyze:  conpath = \"/dev/console\",wfh.flush(), OSError: [Errno 5] Input/output error; root cause:  should same with BZ2034588")
        # From cloud-init-21.1-3.el8 or cloud-init-21.1-4.el9 the password should not in the output and cloud-init-output.log
        if "test5_pw" in vars() or "test6_pw" in vars():
            self.fail("Should not show random passwords in the output")
        self._check_cloudinit_log()
         
        
    def tearDown(self):
        logging.debug("=========Now we getinto tearDown procedure=========")
        if not self.session.connect(timeout=10) and self.vm.exists():
            self.vm.delete()
            return
        if self.case_short_name in [
                "test_cloudinit_swapon_with_xfs_filesystem",
                #"test_cloudinit_provision_vm_with_multiple_nics", #comment this line cause vm already be deleted in case excecution then will cause 500 error here
                "test_cloudinit_upgrade_downgrade_package",
                "test_cloudinit_mount_with_noexec_option",
                "test_cloudinit_no_networkmanager"
        ]:
            self.vm.delete(wait=False)
        time.sleep(10) #Add 10 seconds casue sometimes some case can query the VM but canno login after deleting in above case in full run
        self.session.close()
        
if __name__ == "__main__":
    main()
