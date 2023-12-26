import os
import re
import time
import yaml
from avocado import Test
from avocado import main
from avocado_cloud.app import Setup
from avocado_cloud.app.azure import AzureAccount
from avocado_cloud.app.azure import AzureNIC
from avocado_cloud.app.azure import AzurePublicIP
from avocado_cloud.app.azure import AzureNicIpConfig
from avocado_cloud.app.azure import AzureImage
from distutils.version import LooseVersion
from avocado_cloud.utils import utils_azure

BASEPATH = os.path.abspath(__file__ + "/../../../")


class D(dict):
    # Don't raise exception if cannot get key value
    def __missing__(self, key):
        self[key] = D()
        return self[key]


class CloudinitTest(Test):
    def setUp(self):
        account = AzureAccount(self.params)
        account.login()
        self.project = self.params.get("rhel_ver", "*/VM/*")
        self.case_short_name = re.findall(r"Test.(.*)", self.name.name)[0]
#        if self.case_short_name == "test_cloudinit_verify_customized_file_in_authorizedkeysfile":
#            self.cancel("BZ#1862967 has not been fixed yet. Skip.")
        self.pwd = os.path.abspath(os.path.dirname(__file__))
        if LooseVersion(self.project) >= LooseVersion('9.0.0'):
            if self.case_short_name in [
                "test_cloudinit_no_networkmanager"
            ]:
                self.cancel(
                    "Skip case because RHEL-{} doesn't support this feature".format(self.project)
                )
            
        if self.case_short_name in [
            "test_cloudinit_provision_gen2_vm",
            "test_cloudinit_verify_storage_rule_gen2"
        ]:
            if LooseVersion(self.project) < LooseVersion('7.8'):
                self.cancel(
                    "Skip case because RHEL-{} ondemand image doesn't support gen2".format(self.project))
            cloud = Setup(self.params, self.name, size="DS2_v2")
            cloud.vm.vm_name += "-gen2"
            self.image = AzureImage(self.params, generation="V2")
            if not self.image.exists():
                self.image.create()
            cloud.vm.image = self.image.name
            cloud.vm.use_unmanaged_disk = False
        else:
            cloud = Setup(self.params, self.name)
        self.vm = cloud.vm
        self.package = self.params.get("packages", "*/Other/*")
        if self.case_short_name in [
            "test_cloudinit_login_with_password",
            "test_cloudinit_remove_cache_and_reboot_password",
            "test_cloudinit_update_existing_password",
        ]:
            self.vm.vm_name += "-pw"
        if self.case_short_name == "test_cloudinit_mount_with_noexec_option":
            self.vm.vm_name += "-noexec"
        if self.case_short_name == "test_cloudinit_no_networkmanager":
            self.vm.vm_name += "-nonm"
        if self.case_short_name in [
                "test_cloudinit_login_with_password",
                "test_cloudinit_login_with_publickey",
                "test_cloudinit_save_and_handle_customdata_script",
                "test_cloudinit_save_and_handle_customdata_cloudinit_config",
                "test_cloudinit_save_and_handle_userdata_script",
                "test_cloudinit_save_and_handle_userdata_cloudinit_config",
                "test_cloudinit_assign_identity",
                "test_cloudinit_update_existing_password",
        ]:
            if self.vm.exists():
                self.vm.delete()
            self.session = cloud.init_session()
            return
        authentication = "publickey"
        if self.case_short_name in [
                "test_cloudinit_remove_cache_and_reboot_password",
        ]:
            self.vm.ssh_key_value = None
            self.vm.generate_ssh_keys = None
            self.vm.authentication_type = "password"
            authentication = "password"
        if self.case_short_name == \
                "test_cloudinit_provision_vm_with_multiple_nics":
            self.vm.vm_name += "2nics"
            if self.vm.exists():
                self.vm.delete()
            publicip_name = self.vm.vm_name + "publicip"
            publicip = AzurePublicIP(self.params, name=publicip_name)
            if not publicip.exists():
                publicip.create()
            nic_name_list = []
            for n in range(0, 2):
                nic_name = "{}nic{}".format(self.vm.vm_name, n)
                subnet = self.vm.subnet if n == 0 else self.vm.subnet + str(n)
                n_publicip = publicip_name if n == 0 else None
                nic = AzureNIC(self.params,
                               name=nic_name,
                               subnet=subnet,
                               vnet=self.vm.vnet_name,
                               publicip=n_publicip)
                if not nic.exists():
                    nic.create()
                nic_name_list.append(nic_name)
            self.vm.nics = ' '.join(nic_name_list)
            self.session = cloud.init_session()
            return
        if self.case_short_name == "test_cloudinit_provision_vm_with_sriov_nic":
            self.vm.vm_name += "sriov"
            if self.vm.exists():
                self.vm.delete()
            publicip_name = self.vm.vm_name + "publicip"
            publicip = AzurePublicIP(self.params, name=publicip_name)
            if not publicip.exists():
                publicip.create()
            self.vm.nics = "{}nic".format(self.vm.vm_name)
            nic = AzureNIC(self.params,
                           name=self.vm.nics,
                           subnet=self.vm.subnet,
                           vnet=self.vm.vnet_name,
                           publicip=publicip_name,
                           sriov=True)
            if not nic.exists():
                nic.create()
            self.session = cloud.init_session()
            self.vm.size = "Standard_D3_v2"
            return
        if self.name.name.endswith("test_cloudinit_provision_vm_with_ipv6"):
            self.vm.vm_name += "ipv6"
            if self.vm.exists():
                self.vm.delete()
            publicip_name = self.vm.vm_name + "publicip"
            publicip = AzurePublicIP(self.params,
                                     name=publicip_name)
            if not publicip.exists():
                publicip.create()
            self.vm.nics = "{}nic".format(self.vm.vm_name)
            nic = AzureNIC(self.params,
                           name=self.vm.nics,
                           subnet=self.vm.subnet,
                           vnet=self.vm.vnet_name,
                           publicip=publicip_name)
            if not nic.exists():
                nic.create()
            ipv6_config = AzureNicIpConfig(self.params,
                                           name=self.vm.nics+"ipv6",
                                           nic_name=self.vm.nics,
                                           ip_version="IPv6")
            if not ipv6_config.exists():
                ipv6_config.create()
            self.session = cloud.init_session()
            return
        self.session = cloud.init_vm(authentication=authentication)
        if self.case_short_name == "test_cloudinit_upgrade_downgrade_package":
            rhel7_old_pkg_url = "http://download.eng.bos.redhat.com/brewroot/vol/rhel-7/packages/cloud-init/18.2/1.el7/x86_64/cloud-init-18.2-1.el7.x86_64.rpm"
            rhel8_old_pkg_url = "http://download.eng.bos.redhat.com/brewroot/vol/rhel-8/packages/cloud-init/18.2/1.el8/noarch/cloud-init-18.2-1.el8.noarch.rpm"
            try:
                self.assertEqual(0, self.session.cmd_status_output("ls /tmp/{}".format(self.package))[0],
                                 "No new pakcage in guest VM")
                import requests
                if str(self.project).startswith('7'):
                    old_pkg_url = rhel7_old_pkg_url
                elif str(self.project).startswith('8'):
                    old_pkg_url = rhel8_old_pkg_url
                self.old_pkg = old_pkg_url.split('/')[-1]
                if not os.path.exists("/tmp/{}".format(self.old_pkg)):
                    r = requests.get(old_pkg_url, allow_redirects=True)
                    open("/tmp/{}".format(self.old_pkg), 'wb').write(r.content)
                self.session.copy_files_to(
                    local_path="/tmp/{}".format(self.old_pkg),
                    remote_path="/tmp/{}".format(self.old_pkg))
                self.assertEqual(0, self.session.cmd_status_output("ls /tmp/{}".format(self.old_pkg))[0],
                                 "No old pakcage in guest VM")
            except:
                self.cancel(
                    "No old or new package in guest VM. Skip this case.")
        if self.case_short_name in [
            "test_cloudinit_auto_register_with_subscription_manager",
            "test_cloudinit_auto_install_package_with_subscription_manager",
            "test_cloudinit_verify_rh_subscription_enablerepo_disablerepo"
        ]:
            self.subscription_username = self.params.get("username", "*/Subscription/*")
            self.subscription_password = self.params.get("password", "*/Subscription/*")
            self.session.cmd_output("sudo su -")
            self.session.cmd_output("rpm -e rhui-azure-rhel{}".format(self.project.split('.')[0]))

    @property
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
        self.vm.ssh_key_value = None
        self.vm.generate_ssh_keys = None
        self.vm.authentication_type = "password"
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

    def _get_boot_temp_devices(self):
        boot_dev = self.session.cmd_output("mount|grep 'boot'|head -1|cut -c1-8")
        temp_dev = '/dev/sda' if boot_dev == '/dev/sdb' else '/dev/sdb'
        return(boot_dev, temp_dev)

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
            utils_azure.command("mkdir -p {}".format(host_logpath))
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

    def test_cloudinit_create_ovfenv_under_waagent_folder(self):
        """
        :avocado: tags=tier1,cloudinit
        RHEL7-103834 - CLOUDINIT-TC: [Azure]Create ovf-env.xml under /var/lib/waagent folder
        Check if file "/var/lib/waagent/ovf-env.xml" exists
        """
        self.log.info("RHEL7-103834 - CLOUDINIT-TC: [Azure]Create ovf-env.xml "
                      "under /var/lib/waagent folder")
        self.assertEqual(
            self.session.cmd_status_output(
                "sudo ls /var/lib/waagent/ovf-env.xml")[0], 0,
            "File /var/lib/waagent/ovf-env.xml doesn't exist")

    def test_cloudinit_publish_hostname_to_dns(self):
        """
        :avocado: tags=tier1,cloudinit
        RHEL7-103835 - CLOUDINIT-TC: [Azure]Publish VM hostname to DNS server
        1. Get FQDN hostname(RHEL-9+ not support)
        2. Check FQDN name can be resolved by DNS server
        """
        self.log.info("RHEL7-103835 - CLOUDINIT-TC: [Azure]Publish VM hostname to DNS server")
        if self.project.split('.')[0] < 9:
            self.assertIn(".internal.cloudapp.net",
                        self.session.cmd_output("hostname -f"),
                        "Cannot get whole FQDN")
        else:
            self.log.info("For RHEL-{}, skip checking hostname -f".format(self.project))
        self.assertNotIn(
            "NXDOMAIN",
            self.session.cmd_output("nslookup %s" % self.vm.vm_name),
            "Fail to publish hostname to DNS")

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
        # Verify cloud.cfg ssh_deletekeys:   1        
        self.assertEqual(
            self.session.cmd_status_output(
                "grep -E '(ssh_deletekeys: *1)|(ssh_deletekeys: *true)' /etc/cloud/cloud.cfg")[0], 0,
            "ssh_deletekeys: 1 is not in cloud.cfg")
        old_md5 = self.session.cmd_output("md5sum /etc/ssh/ssh_host_rsa_key "
                                          "/etc/ssh/ssh_host_ecdsa_key "
                                          "/etc/ssh/ssh_host_ed25519_key")
        # Deprovision image
        if self.session.cmd_status_output(
                "systemctl is-enabled waagent")[0] == 0:
            mode = "cloudinit_wala"
        else:
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
        osdisk = self.vm.properties["storageProfile"]["osDisk"]["vhd"]["uri"]
        self.vm.delete()
        self.vm.image = osdisk
        self.vm.vm_username = origin_username
        self.vm.os_disk_name += "-new"
        self.vm.create()
        self.session.connect()
        new_md5 = self.session.cmd_output(
            "sudo md5sum /etc/ssh/ssh_host_rsa_key "
            "/etc/ssh/ssh_host_ecdsa_key "
            "/etc/ssh/ssh_host_ed25519_key")
        self.assertNotEqual(old_md5, new_md5,
                            "The ssh host keys are not regenerated.")

    def test_cloudinit_save_and_handle_customdata_script(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL7-103837 - CLOUDINIT-TC: Save and handle customdata(script)
        1. Create VM with custom data
        2. Get CustomData from ovf-env.xml, decode it and compare with
           original custom data file
        3. Check if custom data script is executed
        """
        self.log.info("RHEL7-103837 - CLOUDINIT-TC: Save and handle customdata(script)")
        # Prepare custom script
        script = """\
#!/bin/bash
echo 'teststring' >> /var/log/test.log\
"""
        with open("/tmp/customdata.sh", 'w') as f:
            f.write(script)
        # 1. Create VM with custom data
        self.vm.custom_data = "/tmp/customdata.sh"
        self.vm.create()
        self.session.connect()
        # 2. Compare custom data
        custom_data = self.session.cmd_output(
            "sudo grep -o -P '(?<=CustomData>).*(?=<.*CustomData>)' "
            "/var/lib/waagent/ovf-env.xml|base64 -d")
        self.assertEqual(
            custom_data,
            self.session.cmd_output(
                "sudo cat /var/lib/cloud/instance/user-data.txt"),
            "Custom data in ovf-env.xml is not equal to user-data.txt")
        # 3. Check if custom data script is executed
        for retry in range(1, 11):
            if utils_azure.file_exists("/var/log/test.log", self.session):
                break
            self.log.info("/var/log/test.log doesn't exist. Wait for 10s and retry...({}/10)".format(retry))
            time.sleep(10)
        self.assertEqual("teststring",
                         self.session.cmd_output("cat /var/log/test.log"),
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
        customdata_ori = """\
#cloud-config
cloud_config_modules:
 - mounts
 - locale
 - set-passwords
 - yum-add-repo
 - disable-ec2-metadata
 - runcmd
"""
        with open("/tmp/customdata.conf", 'w') as f:
            f.write(customdata_ori)
        # 1. Create VM with custom data
        self.vm.custom_data = "/tmp/customdata.conf"
        self.vm.create()
        self.session.connect()
        # 2. Compare custom data
        custom_data = self.session.cmd_output(
            "sudo grep -o -P '(?<=CustomData>).*(?=<.*CustomData>)' "
            "/var/lib/waagent/ovf-env.xml|base64 -d")
        self.assertEqual(
            custom_data,
            self.session.cmd_output(
                "sudo cat /var/lib/cloud/instance/user-data.txt"),
            "Custom data in ovf-env.xml is not equal to user-data.txt")
        # 3. Check if the new cloud-init configuration is handled correctly
        # (There should be 6 modules ran in cloud-init.log)
        output = self.session.cmd_output(
            "sudo grep 'running modules for config' "
            "/var/log/cloud-init.log -B 100")
        version = self.session.cmd_output("cloud-init -v|awk '{print $2}'")
        if LooseVersion(version) < LooseVersion("23.1"):
            self.assertIn("Ran 6 modules", output,
                        "The user data is not handled correctly")
        else:
            self.assertIn("Ran 3 modules", output,
                        "The user data is not handled correctly")
            self.assertIn("Skipping modules 'yum-add-repo,disable-ec2-metadata,runcmd' because no applicable config is provided",
                        output,
                        "The user data is not handled correctly")

    def test_cloudinit_save_and_handle_userdata_script(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-286797 - CLOUDINIT-TC: Save and handle userdata(script)
        1. Create VM with user data
        2. Check if user data script is executed
        """
        self.log.info("RHEL-286797 - CLOUDINIT-TC: Save and handle userdata(script)")
        # Prepare user script
        script = """\
#!/bin/bash
echo 'teststring' >> /var/log/test.log\
"""
        with open("/tmp/userdata.sh", 'w') as f:
            f.write(script)
        # 1. Create VM with user data
        self.vm.user_data = "/tmp/userdata.sh"
        self.vm.create()
        self.session.connect()
        # 2. Check if user data script is executed
        for retry in range(1, 11):
            if utils_azure.file_exists("/var/log/test.log", self.session):
                break
            self.log.info("/var/log/test.log doesn't exist. Wait for 10s and retry...({}/10)".format(retry))
            time.sleep(10)
        self.assertEqual("teststring",
                         self.session.cmd_output("cat /var/log/test.log"),
                         "The user data script is not executed correctly.")

    def test_cloudinit_save_and_handle_userdata_cloudinit_config(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-286798 - CLOUDINIT-TC: Save and handle userdata(cloud-init configuration)
        1. Create VM with user data
        2. Check if the new cloud-init configuration is handled correctly
        """
        self.log.info(
            "RHEL-286798 - CLOUDINIT-TC: Save and handle userdata(cloud-init configuration)")
        # Prepare user data
        userdata_ori = """\
#cloud-config
cloud_config_modules:
 - mounts
 - locale
 - set-passwords
 - yum-add-repo
 - disable-ec2-metadata
 - runcmd
"""
        with open("/tmp/userdata.conf", 'w') as f:
            f.write(userdata_ori)
        # 1. Create VM with custom data
        self.vm.user_data = "/tmp/userdata.conf"
        self.vm.create()
        self.session.connect()
        # 2. Check if the new cloud-init configuration is handled correctly
        # (There should be 6 modules ran in cloud-init.log)
        output = self.session.cmd_output(
            "sudo grep 'running modules for config' "
            "/var/log/cloud-init.log -B 100")
        version = self.session.cmd_output("cloud-init -v|awk '{print $2}'")
        if LooseVersion(version) < LooseVersion("23.1"):
            self.assertIn("Ran 6 modules", output,
                        "The user data is not handled correctly")
        else:
            self.assertIn("Ran 3 modules", output,
                        "The user data is not handled correctly")
            self.assertIn("Skipping modules 'yum-add-repo,disable-ec2-metadata,runcmd' because no applicable config is provided",
                        output,
                        "The user data is not handled correctly")

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
        # Skip the case if this is LVM root partition, as not support it currently
        boot_dev = self._get_boot_temp_devices()[0].split('/')[-1]
        if self.session.cmd_status_output(
                "lsblk /dev/{} --output NAME,TYPE -r|grep 'lvm'".format(boot_dev))[0] == 0:
            self.session.cmd_output("lsblk /dev/{}".format(boot_dev))
            self.cancel("Skip this case as cloud-init not support LVM root partition")
        # 1. Install cloud-utils-growpart gdisk
        if self.session.cmd_status_output(
                "rpm -q cloud-utils-growpart gdisk")[0] != 0:
            self.session.cmd_output("sudo rpm -ivh /root/rhui-azure-*.rpm")
            self.session.cmd_output(
                "sudo yum install -y cloud-utils-growpart gdisk")
            if self.session.cmd_status_output(
                    "rpm -q cloud-utils-growpart gdisk")[0] != 0:
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
        os_disk_size = self.vm.properties["storageProfile"]["osDisk"][
            "diskSizeGb"]
        self.assertAlmostEqual(
            first=float(dev_size),
            second=float(os_disk_size),
            delta=1,
            msg="Device size is incorrect. Raw disk: %s, real: %s" %
            (dev_size, os_disk_size))
        self.assertAlmostEqual(first=float(fs_size),
                               second=float(os_disk_size),
                               delta=1.5,
                               msg="Filesystem size is incorrect. "
                               "FS: %s, real: %s" % (fs_size, os_disk_size))
        # 3. Enlarge os disk size
        self.vm.stop()
        new_os_disk_size = os_disk_size + 2
        self.vm.osdisk_resize(new_os_disk_size)
        # 4. Start VM and login. Check os disk and fs capacity
        self.vm.start()
        self.session.connect()
        boot_dev = self._get_boot_temp_devices()[0].split('/')[-1]
        partition = self.session.cmd_output(
            "find /dev/ -name {}[0-9]|sort|tail -n 1".format(boot_dev))
        new_dev_size = self.session.cmd_output(
            "lsblk /dev/{0} --output NAME,SIZE -r"
            "|grep -o -P '(?<={0} ).*(?=G)'".format(boot_dev))
        new_fs_size = self.session.cmd_output(
            "df {} --output=size -h|grep -o '[0-9]\+'".format(partition))
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

    def test_cloudinit_verify_temporary_disk_mount_point(self):
        """
        :avocado: tags=tier1,cloudinit
        RHEL-131780: WALA-TC: [Cloudinit] Check temporary disk mount point
        1. New VM. Check if temporary disk is mounted
        2. Restart VM from azure cli. Check mount point again
        """
        self.log.info("RHEL-131780: WALA-TC: [Cloudinit] Check temporary \
disk mount point")
        # boot_dev = self.session.cmd_output("mount|grep 'boot ' | cut -c1-8")
        # temp_dev = '/dev/sda' if boot_dev == '/dev/sdb' else '/dev/sdb'
        # temp_dev = utils_azure.get_temporary_device()
        status = self.session.cmd_status_output(
            "mount|grep '/mnt '")[0]
        # self.log.info(
        #     self.session.cmd_output("sudo fdisk -l {}".format(temp_dev)))
        self.assertEqual(
            status, 0, "After create VM, temporary disk is not mounted to /mnt")
        # Redeply VM (move to another host. The ephemeral disk will be new)
        self.vm.redeploy()
        self.session.connect()
        status = self.session.cmd_status_output(
            "mount|grep '/mnt '")[0]
        # self.log.info(
        #     self.session.cmd_output("sudo fdisk -l {}".format(temp_dev)))
        self.assertEqual(
            status, 0,
            "After redeploy VM, temporary disk is not mounted to /mnt")

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

    def test_cloudinit_assign_identity(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-152186: WALA-TC: [Cloudinit] Assign identity
        CVE BZ#1680165
        """
        self.log.info("RHEL-152186: WALA-TC: [Cloudinit] Assign identity")
        self.vm.assign_identity = True
        self.vm.create(wait=True)
        self.session.connect()
        self.assertEqual(
            '1',
            self.session.cmd_output(
                "cat /home/{0}/.ssh/authorized_keys|wc -l".format(
                    self.vm.vm_username)),
            "More then 1 public keys in /home/{0}/.ssh/authorized_keys".format(
                self.vm.vm_username))

    def test_cloudinit_check_networkmanager_dispatcher(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-170749 - CLOUDINIT-TC: [Azure]Check NetworkManager dispatcher
        BZ#1707725
        """
        version = self.session.cmd_output("cloud-init -v|awk '{print $2}'")
        if LooseVersion(version) >= LooseVersion("23.2"):
            self.cancel(
                    "Skip case because cloud-init-{} doesn't support this feature".format(version)
                    )
        self.log.info(
            "RHEL-170749 - CLOUDINIT-TC: [Azure]Check NetworkManager dispatcher"
        )
        self.session.cmd_output("sudo su -")
        # 1. cloud-init is enabled
        self.assertEqual(
            self.session.cmd_status_output("ls /run/cloud-init/enabled")[0], 0,
            "No /run/cloud-init/enabled when cloud-init is enabled")
        self.session.cmd_output("rm -rf /run/cloud-init/dhclient.hooks/*.json")
        self.session.cmd_output("systemctl restart NetworkManager")
        time.sleep(3)
        self.assertEqual(
            self.session.cmd_status_output(
                "ls /run/cloud-init/dhclient.hooks/*.json")[0], 0,
            "Cannot run cloud-init if it is enabled")
        # 2. cloud-init is disabled
        self.session.cmd_output("mv /run/cloud-init/enabled /tmp/")
        self.session.cmd_output("rm -f /run/cloud-init/dhclient.hooks/*.json")
        self.session.cmd_output("systemctl restart NetworkManager")
        time.sleep(3)
        self.assertNotEqual(
            self.session.cmd_status_output(
                "sudo ls /run/cloud-init/dhclient.hooks/*.json")[0], 0,
            "Should not run cloud-init if it is not enabled")

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
        self.vm.create()
        self.session.connect(timeout=60)
        vm_ip_list = self.session.cmd_output(
            "ip addr|grep -Po 'inet \\K.*(?=/)'|grep -v '127.0.0.1'").split(
                '\n').sort()
        azure_ip_list = self.vm.properties.get("privateIps").split(',').sort()
        self.assertEqual(
            vm_ip_list, azure_ip_list, "The private IP addresses are wrong.\n"
            "Expect: {}\nReal: {}".format(azure_ip_list, vm_ip_list))

    def test_cloudinit_provision_vm_with_sriov_nic(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-171394	WALA-TC: [Network] Provision VM with SR-IOV NIC
        1. Create a VM with 1 SRIOV NIC
        2. Check if can provision and connect to the VM successfully
        """
        self.log.info(
            "RHEL-171394	WALA-TC: [Network] Provision VM with SR-IOV NIC")
        self.vm.create()
        self.session.connect(timeout=60)
        vm_ip = self.session.cmd_output(
            "ip addr|grep -Po 'inet \\K.*(?=/)'|grep -v '127.0.0.1'")
        azure_ip = self.vm.properties.get("privateIps")
        self.assertEqual(
            vm_ip, azure_ip, "The private IP addresses are wrong.\n"
            "Expect: {}\nReal: {}".format(azure_ip, vm_ip))

    def test_cloudinit_provision_vm_with_ipv6(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-176198 - CLOUDINIT-TC: [Azure]Provision VM with IPv6 address
        1. Create a VM with NIC in IPv6 subnet
        2. Check if can provision and connect to the VM successfully
        3. Restart the VM. Check if this NIC is up and can get ip address
        """
        self.log.info(
            "RHEL-176198 - CLOUDINIT-TC: [Azure]Provision VM with IPv6 address")
        # 1. Create a VM with NIC in IPv6 subnet
        self.vm.create()
        self.session.connect(timeout=60)
        self.session.cmd_output("sudo su -")
        # 2. Verify can get IPv6 IP
        azure_ip = self.vm.properties.get("privateIps").split(',')[1]
        vm_ip = self.session.cmd_output(
            "ip addr|grep global|grep -Po 'inet6 \\K.*(?=/)'")
        self.assertEqual(
            vm_ip, azure_ip, "The private IPv6 address is wrong.\n"
            "Expect: {}\nReal: {}".format(azure_ip, vm_ip))
        self.assertEqual(0, self.session.cmd_status_output("ping6 ace:cab:deca::fe -c 1")[0],
                         "Cannot ping6 though vnet")
        # 3. Restart VM
        self.session.close()
        self.vm.reboot()
        time.sleep(10)
        self.session.connect(timeout=60)
        vm_ip_list = self.session.cmd_output(
            "ip addr|grep global|grep -Po 'inet6 \\K.*(?=/)'")
        self.assertEqual(
            vm_ip_list, azure_ip, "The private IPv6 address is wrong after restart.\n"
            "Expect: {}\nReal: {}".format(azure_ip, vm_ip_list))
        self.assertEqual(0, self.session.cmd_status_output("ping6 ace:cab:deca::fe -c 1")[0],
                         "Cannot ping6 though vnet after restart")

    def test_cloudinit_provision_gen2_vm(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-176836 CLOUDINIT-TC: [Azure]Provision UEFI VM
        """
        self.log.info(
            "RHEL-176836 CLOUDINIT-TC: [Azure]Provision UEFI VM")
        error_msg = ""
        # Verify hostname is correct
        try:
            self.assertEqual(self.session.cmd_output("hostname"), self.vm.vm_name,
                             "Hostname is not the one we set")
        except:
            error_msg += "Verify hostname failed\n"
        # Verify hostname is published to DNS
        try:
            self.assertNotIn(
                "NXDOMAIN",
                self.session.cmd_output("nslookup {0}".format(
                    self.vm.vm_name)), "Fail to publish hostname to DNS")
        except:
            error_msg += "Verify publish to DNS failed\n"
        # Verify mountpoint
        try:
            self.assertEqual(
                0, self.session.cmd_status_output("mount|grep /mnt")[0],
                "Resource Disk is not mounted after provisioning")
        except:
            error_msg += "Verify mountpoint failed\n"
        if error_msg:
            self.fail(error_msg)

    def test_cloudinit_upgrade_downgrade_package(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL7-95122	WALA-TC: [Cloudinit] Upgrade cloud-init
        1. Downgrade through rpm
        2. Upgrade through rpm
        3. (if have repo)Downgrade through yum
        4. (if have repo)Upgrade through yum
        """
        self.log.info(
            "RHEL7-95122 WALA-TC: [Cloudinit] Upgrade cloud-init")
        self.session.cmd_output("sudo su -")
        self.assertEqual(0, self.session.cmd_status_output(
            "rpm -Uvh --oldpackage /tmp/{}".format(self.old_pkg))[0],
            "Fail to downgrade package through rpm")
        self.assertEqual(0, self.session.cmd_status_output(
            "rpm -Uvh /tmp/{}".format(self.package))[0],
            "Fail to upgrade package through rpm")
        self.assertNotIn("disabled", self.session.cmd_output("systemctl is-enabled cloud-init-local cloud-init cloud-config cloud-final"),
                         "After upgrade through rpm, the cloud-init services are not enabled")
        self.assertNotIn("inactive", self.session.cmd_output("systemctl is-active cloud-init-local cloud-init cloud-config cloud-final"),
                         "After upgrade through rpm, the cloud-init services are not active")
        self.assertEqual(0, self.session.cmd_status_output(
            "yum downgrade /tmp/{} -y --disablerepo=*".format(self.old_pkg))[0],
            "Fail to downgrade package through yum")
        self.assertEqual(0, self.session.cmd_status_output(
            "yum upgrade /tmp/{} -y --disablerepo=*".format(self.package))[0],
            "Fail to upgrade package through yum")
        self.assertNotIn("disabled", self.session.cmd_output("systemctl is-enabled cloud-init-local cloud-init cloud-config cloud-final"),
                         "After upgrade through yum, the cloud-init services are not enabled")
        self.assertNotIn("inactive", self.session.cmd_output("systemctl is-active cloud-init-local cloud-init cloud-config cloud-final"),
                         "After upgrade through yum, the cloud-init services are not active")
        self.session.cmd_output("rm -f /var/log/cloud-init*")
        self.session.close()
        self.vm.reboot()
        self.session.connect()
        try:
            self.test_cloudinit_check_cloudinit_log()
        except:
            self.log.warn("There are error/fail logs")

    def _check_in_link(self, device, links):
        self.assertIn(device, links,
                      "No {0} link in disk links".format(device))
        self.log.info("{0} is in disk links. Pass.".format(device))

    def _verify_storage_rule(self):
        links = self.session.cmd_output("ls -l /dev/disk/cloud")
        devices_list = re.findall(r"\w+",
                                  self.session.cmd_output("cd /dev;ls sd*"))
        for device in devices_list:
            self._check_in_link(device, links)
        # There should be azure_root and azure_resource links
        self._check_in_link('azure_root', links)
        self._check_in_link('azure_resource', links)
        # Verify the azure_root and azure_resource link to the correct disks
        root_disk = self.session.cmd_output("df|grep boot")[:8]
        resource_disk = self.session.cmd_output(
            "find /dev/sd*|grep -v '{}'".format(root_disk))[:8]
        self.log.debug("Root disk: {}".format(root_disk))
        self.log.debug("Resource disk: {}".format(resource_disk))
        self.assertEqual(self.session.cmd_output("realpath /dev/disk/cloud/azure_root"),
                         root_disk, "The azure_root link disk is incorrect")
        self.assertEqual(self.session.cmd_output("realpath /dev/disk/cloud/azure_resource"),
                         resource_disk, "The azure_root link disk is incorrect")

    def test_cloudinit_verify_storage_rule_gen1(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-188923	CLOUDINIT-TC: Verify storage rule - Gen1
        1. Prepare Gen1 VM.
        Check /dev/disk/cloud/, there should be azure_root and azure_resource
        soft links to sda and sdb.
        """
        self.log.info("RHEL-188923 CLOUDINIT-TC: Verify storage rule - Gen1")
        self._verify_storage_rule()

    def test_cloudinit_verify_storage_rule_gen2(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-188924	CLOUDINIT-TC: Verify storage rule - Gen2
        1. Prepare Gen2 VM.
        Check /dev/disk/cloud/, there should be azure_root and azure_resource
        soft links to sda and sdb.
        """
        self.log.info("RHEL-188924 CLOUDINIT-TC: Verify storage rule - Gen2")
        self._verify_storage_rule()

    def _verify_authorizedkeysfile(self, keyfiles):
        self.session.cmd_output("sudo su")
        # 1. Modify /etc/ssh/sshd_config
        self.session.cmd_output(
            "sed -i 's/^AuthorizedKeysFile.*$/AuthorizedKeysFile {}/g' /etc/ssh/sshd_config".format(keyfiles.replace('/', '\/')))
        self.assertEqual(self.session.cmd_status_output("grep '{}' /etc/ssh/sshd_config".format(keyfiles))[0], 0,
                         "Fail to change /etc/ssh/sshd_config AuthorizedKeysFile value.")
        self.session.cmd_output("systemctl restart sshd")
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
        self.session.cmd_output("sudo rm -rf /var/lib/cloud/instances/*")
        self.vm.reboot()
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

    def test_cloudinit_auto_install_package_with_subscription_manager(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-186182	CLOUDINIT-TC:auto install package with subscription manager
        1. Add content to /etc/cloud/cloud.cfg.d/test_rh_subscription.cfg
'       rh_subscription:
          username: ******
          password: ******
          auto-attach: True
          disable-repo: ['rhel-8-for-x86_64-baseos-htb-rpms', 'rhel-8-for-x86_64-appstream-htb-rpms']
        packages:
          - dos2unix
        2. Run cloud-init config phase
        3. Verify can register with subscription-manager and install package by cloud-init
        """
        self.log.info("RHEL-186182 CLOUDINIT-TC:auto install package with subscription manager")
        package = "dos2unix"
        self.session.cmd_output("rpm -e {}".format(package))
        CONFIG='''\
rh_subscription:
  username: {}
  password: {}
  auto-attach: True
packages:
  - {}'''.format(self.subscription_username, self.subscription_password, package)
        self._verify_rh_subscription(CONFIG)
        self.assertNotEqual("",
            self.session.cmd_output("subscription-manager list --consumed --pool-only"),
            "Cannot auto-attach pools")
        self.assertEqual(0,
            self.session.cmd_status_output("rpm -q {}".format(package))[0],
            "Fail to install package {} by cloud-init".format(package))

    def test_cloudinit_verify_rh_subscription_enablerepo_disablerepo(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-189134 - CLOUDINIT-TC: Verify rh_subscription enable-repo and disable-repo
        1. rh_subscription config is:
        rh_subscription:
          username: ******
          password: ******
          auto-attach: True
          disable-repo: []
          Verify no error logs.
        2. rh_subscription config is:
        rh_subscription:
          username: ******
          password: ******
          add-pool: [ '8a85f98960dbf6510160df23eb447470' ]
          enable-repo: ['rhel-8-for-x86_64-baseos-rpms'] 
          Verify no error logs.
          Verify pool id matches the consumed pool.
          Verify enable-repo is enabled.
        3. Verify no error if rh_subscription config is:
        rh_subscription:
          username: ******
          password: ******
          add-pool: [ '8a85f98960dbf6510160df23eb447470' ]
          enable-repo: ['rhel-8-for-x86_64-baseos-rpms', 'rhel-8-for-x86_64-appstream-e4s-rpms']
          disable-repo: ['rhel-8-for-x86_64-appstream-rpms']
          Verify no error logs.
          Verify enable-repos are enabled and disable-repo is disabled
        """
        self.log.info("RHEL-189134 CLOUDINIT-TC: Verify rh_subscription enable-repo and disable-repo")
        pool = '8a85f98960dbf6510160df23eb447470'
        if int(self.project.split('.')[0]) >= 8:
            enable_repo_1 = 'rhel-8-for-x86_64-baseos-rpms'
            enable_repo_2 = 'rhel-8-for-x86_64-appstream-e4s-rpms'
            disable_repo = 'rhel-8-for-x86_64-appstream-rpms'
        else:
            enable_repo_1 = 'rhel-7-server-rpms'
            enable_repo_2 = 'rhel-rs-for-rhel-7-server-htb-debug-rpms'
            disable_repo = 'rhel-7-server-htb-rpms'
        # 1. Disable-repo is empty
        self.log.info("1. Disable-repo is empty")
        CONFIG='''\
rh_subscription:
  username: {}
  password: {}
  auto-attach: True
  disable-repo: []'''.format(self.subscription_username, self.subscription_password)
        self._verify_rh_subscription(CONFIG)
        # 2. Disable-repo is null
        self.log.info("2. Disable-repo is null")
        CONFIG='''\
rh_subscription:
  username: {}
  password: {}
  add-pool: ["{}"]
  enable-repo: ["{}"]'''.format(self.subscription_username, self.subscription_password, 
                             pool, enable_repo_1)
        self._verify_rh_subscription(CONFIG)
        self.assertEqual(pool, 
            self.session.cmd_output("subscription-manager list --consumed --pool-only"), 
            "The consumed pool id does not correct.")
        self.assertIn(enable_repo_1, 
            self.session.cmd_output("yum repolist|awk '{print $1}'").split('\n'),
            "Repo {} is not enabled".format(enable_repo_1))
        # 3. Verify enable-repo and disable-repo
        self.log.info("3. Verify enable-repo and disable-repo")
        CONFIG='''\
rh_subscription:
  username: {}
  password: {}
  add-pool: ['{}']
  enable-repo: ['{}', '{}']
  disable-repo: ['{}']'''.format(self.subscription_username, self.subscription_password, 
                             pool, enable_repo_1, enable_repo_2, disable_repo)
        self._verify_rh_subscription(CONFIG)
        repolist = self.session.cmd_output("yum repolist|awk '{print $1}'").split('\n')
        self.assertIn(enable_repo_1, repolist,
            "Repo {} is not enabled".format(enable_repo_1))
        self.assertIn(enable_repo_2, repolist,
            "Repo {} is not enabled".format(enable_repo_2))
        self.assertNotIn(disable_repo, repolist,
            "Repo {} is not disabled".format(disable_repo))


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
        # Clear old swap by cloud-init
        self.session.cmd_output("swapoff /datatest/swap.img")
        self.session.cmd_output("umount /datatest")
        self.session.cmd_output("rm -rf /datatest")
        self.session.cmd_output("sed -i '/.*\/datatest.*/d' /etc/fstab")
        # Get previous swap size
        old_swap = self.session.cmd_output("free -m|grep Swap|awk '{print $2}'")
        # Attach data disk
        self.disk_name = "disk1-{}".format(self._postfix)
        self.vm.unmanaged_disk_attach(self.disk_name, 5)
        self.assertEqual(self.session.cmd_status_output("ls /dev/sdc")[0], 0,
            "No /dev/sdc device after attach data disk")
        self.session.cmd_output("parted /dev/sdc rm 1 -s")
        self.session.cmd_output("parted /dev/sdc mklabel msdos -s")
        self.session.cmd_output("parted /dev/sdc mkpart primary xfs 1048k 4000M -s")
        self.session.cmd_output("mkfs.xfs -f /dev/sdc1")
        self.session.cmd_output("mkdir -p /datatest")
        self.session.cmd_output("mount /dev/sdc1 /datatest")
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
        utils_azure.command("az vm boot-diagnostics enable -n {} -g {} --storage https://{}.blob.core.windows.net/"\
            .format(self.vm.vm_name, self.vm.resource_group, self.vm.storage_account), timeout=120)
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
        for line in output.split('\n'):
            if "test5" in line:
                test5_pw = line.split(':')[1]
            elif "test6" in line:
                test6_pw = line.split(':')[1]
        # From cloud-init-21.1-3.el8 or cloud-init-21.1-4.el9 the password should not in the output and cloud-init-output.log
        if "test5_pw" in vars() or "test6_pw" in vars():
            self.fail("Should not show random passwords in the output")
        # Verify serial output. Sleep 20s to wait for the serial console log refresh
        time.sleep(30)
        serial_output = utils_azure.command("az vm boot-diagnostics get-boot-log -n {} -g {}".format(self.vm.vm_name, self.vm.resource_group), timeout=10, ignore_status=True).stdout
        for line in serial_output.split('\r\n'):
            if "test5" in line:
                test5_pw = line.split(':')[1]
            elif "test6" in line:
                test6_pw = line.split(':')[1]
        if "test5_pw" not in vars() or "test6_pw" not in vars():
            self.fail("Not show random passwords in the serial console")
        test4_salt = self.session.cmd_output("getent shadow test4").split('$')[2]
        test5_salt = self.session.cmd_output("getent shadow test5").split('$')[2]
        test6_salt = self.session.cmd_output("getent shadow test6").split('$')[2]
        shadow_dict = {
            "test1": pw_config_dict['test1'],
            "test2": pw_config_dict['test2'],
            "test3": pw_config_dict['test3'],
            "test4": "test4:{}:0:0:99999:7:::".format(self._generate_password(base_pw, "sha-512", test4_salt)),
            "test5": "test5:{}:0:0:99999:7:::".format(self._generate_password(test5_pw, "sha-512", test5_salt)),
            "test6": "test6:{}:0:0:99999:7:::".format(self._generate_password(test6_pw, "sha-512", test6_salt)),
        }
        for user in shadow_dict:
            real = self.session.cmd_output("getent shadow {}".format(user))
            expect = shadow_dict.get(user)
            self.assertIn(expect, real,
                "The {} password in /etc/shadow doesn't meet the expectation. Real:{} Expect:{}".format(user, real, expect))
        self._check_cloudinit_log()
                

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
        2. Verify "ds-identify rc=0" in /usr/libexec/cloud-init/ds-identify
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
            "grep 'ds-identify rc=0' /run/cloud-init/cloud-init-generator.log")[0], 0,
            "Cannot find 'ds-identify rc=0' in /run/cloud-init/cloud-init-generator.log")

    def test_cloudinit_enable_swap_in_temporary_disk(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-189229	CLOUDINIT-TC: [Azure]Enable swap in temporary disk
        1. Add additional data disk and format to xfs, mount to /datatest and add to /etc/fstab
        2. Configure cloud-config and run mounts module
        # cat /etc/cloud/cloud.cfg.d/test_swap.cfg 
        swap:
          filename: /mnt/swapfile
          size: 2048M
        3. Check the swap, verify /mnt/swapfile exists, verify no error logs in cloud-init.log
        """
        self.log.info("RHEL-189229 CLOUDINIT-TC: [Azure]Enable swap in temporary disk")
        self.session.cmd_output("sudo su -")
        # Clear old swap by cloud-init
        self.assertEqual(self.session.cmd_status_output("mount|grep /mnt")[0], 0,
            "/mnt is not mounted. Cannot run this case")
        self.session.cmd_output("swapoff /mnt/swapfile")
        self.session.cmd_output("rm -f /mnt/swapfile")
        self.session.cmd_output("sed -i '/.*swapfile.*/d' /etc/fstab")
        # Get previous swap size
        old_swap = self.session.cmd_output("free -m|grep Swap|awk '{print $2}'")
        # Test begin
        CONFIG='''\
swap:
  filename: /mnt/swapfile
  size: 2048M'''
        self.session.cmd_output("echo '''{}''' > /etc/cloud/cloud.cfg.d/test_swap.cfg".format(CONFIG))
        self.session.cmd_output("rm -f /var/lib/cloud/instance/sem/config_mounts /var/log/cloud-init*.log")
        self.session.cmd_output("cloud-init single --name mounts")
        new_swap = self.session.cmd_output("free -m|grep Swap|awk '{print $2}'")
        self.assertAlmostEqual(first=int(old_swap)+2047, second=int(new_swap), delta=1,
            msg="The enabled swap size does not correct.")
        self.assertEqual(self.session.cmd_status_output("ls /mnt/swapfile")[0], 0,
            "/mnt/swapfile doesn't exist.")
        self.assertEqual(self.session.cmd_status_output("grep swapfile /etc/fstab")[0], 0,
            "Fail to add swap to /etc/fstab")
        self._check_cloudinit_log()
        self.assertNotEqual(self.session.cmd_status_output(
            "grep 'Permission denied' /var/log/cloud-init-output.log")[0], 0,
            "There are Permission denied logs in /var/log/cloud-init-output.log")

    def test_cloudinit_check_random_password_len(self):
        '''
        :avocado: tags=tier2,cloudinit
        RHEL-189226 - CLOUDINIT-TC: checking random password and its length
        Verify the random password length is 20
        '''
        self.log.info("RHEL-189226 - CLOUDINIT-TC: checking random password and its length")
        utils_azure.command("az vm boot-diagnostics enable -n {} -g {} --storage https://{}.blob.core.windows.net/"\
            .format(self.vm.vm_name, self.vm.resource_group, self.vm.storage_account), timeout=120)
        self.session.cmd_output("sudo su -")
        self.session.cmd_output("rm -f /var/log/cloud-init*.log /var/lib/cloud/instance/sem/config_set_passwords")
        # Add user for test
        testuser = "test1"
        self.session.cmd_output("useradd {}".format(testuser))
        CONFIG = """\
user: {}
password: R
chpasswd: 
    expire: false
ssh_pwauth: 1
""".format(testuser)
        self.session.cmd_output("echo '''{}''' > /etc/cloud/cloud.cfg.d/test_random_pw_len.cfg".format(CONFIG))
        self.session.cmd_output("cloud-init single -n set_passwords", timeout=30)
        # Wait for serial log to refresh
        time.sleep(60)
        serial_output = str(utils_azure.acommand("az vm boot-diagnostics get-boot-log -n {} -g {}".format(self.vm.vm_name, self.vm.resource_group), timeout=10, ignore_status=True).stdout)
        for line in serial_output.split('\r\n'):
            if "test1" in line:
                test1_pw = line.split(':')[1]
        self.assertEqual(len(test1_pw), 20,
            "Random password length is {} not 20".format(len(test1_pw)))

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
        # fix the aexpect output issue (0, u'/usr/bin/cl\noud-init\n21.1-8.el9')
        self.session.cmd_output("cloud-init --version>/tmp/1 2>&1")
        output = self.session.cmd_output("cat /tmp/1")
        package = self.session.cmd_output("rpm -q cloud-init")
        cloudinit_path = self.session.cmd_output("which cloud-init")
        expect = package.rsplit(".", 1)[0].replace("cloud-init-", cloudinit_path+' ')
        self.assertEqual(output, expect, 
            "cloud-init --version doesn't show full version. Real: {}, Expect: {}".format(output, expect))

    def test_cloudinit_check_default_config(self):
        '''
        :avocado: tags=tier2,cloudinit
        RHEL-196560 - CLOUDINIT-TC: Check the cloud-init default config file /etc/cloud/cloud.cfg is not changed
        '''
        self.log.info("RHEL-196560 - CLOUDINIT-TC: Check the cloud-init default config file /etc/cloud/cloud.cfg is not changed")
        self.session.cmd_output("cat /etc/cloud/cloud.cfg")
        self.assertNotIn("/etc/cloud/cloud.cfg", self.session.cmd_output("sudo rpm -V cloud-init"),
            "The /etc/cloud/cloud.cfg is changed")

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
            if real_time.endswith('ms'):
                real_time = 1
            else:
                real_time = float(real_time.rstrip('s'))
            total += real_time
            self.assertTrue(real_time < limit, "{} service startup time is {}s >= {}s".format(service, real_time, limit))
        self.assertTrue(total < total_limit, "All the services startup time is {}s >= {}s".format(total, total_limit))

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
        self.vm.reboot()
        time.sleep(10)
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
        self.vm.reboot()
        time.sleep(10)
        self.assertTrue(self.session.connect(timeout=120), "Fail to connect to VM after remove NetworkManager and restart VM")
        self.assertIn("active (exited)", self.session.cmd_output("sudo systemctl status cloud-final"),
            "cloud-final.service status is not active (exited)")

    def test_cloudinit_growpart_over_2TB_gpt_disk(self):
        """
        :avocado: tags=tier1,cloud_utils_growpart
        RHEL-276281 CLOUDINIT-TC: Can growpart over 2TB gpt disk	
        1. Prepare a VM in Azure and install cloud-utils-growpart package
        2. Attach a 4T data disk to the VM.  Device is /dev/sdc
        3. # parted /dev/sdc mklabel gpt
        4. Make 2 partitions: 
        # parted -s /dev/sdc mkpart xfs 0 1000 
        # parted -s /dev/sdc mkpart xfs 2000 4096
        5. # growpart /dev/sdc 2
        6. # parted /dev/sdc print
        """
        self.log.info("RHEL-276281 CLOUDINIT-TC: Can growpart over 2TB gpt disk")
        self.session.cmd_output("sudo su -")        
        # Attach data disk
        self.disk_name = "disk1-{}".format(self._postfix)
        self.vm.unmanaged_disk_attach(self.disk_name, 4094)
        self.assertEqual(self.session.cmd_status_output("ls /dev/sdc")[0], 0,
            "No /dev/sdc device after attach data disk")
        # Parted 2 gpt partitions
        self.session.cmd_output("parted /dev/sdc mklabel gpt")
        self.session.cmd_output("parted -s /dev/sdc mkpart xfs 0 1000")
        self.session.cmd_output("parted -s /dev/sdc mkpart xfs 2000 4096")
        self.session.cmd_output("parted -s /dev/sdc print")
        # Growpart partition 2
        exit_status, output = self.session.cmd_status_output(
            "growpart /dev/sdc 2")
        self.assertEqual(exit_status, 0,
                         "Run growpart failed: {}".format(output))
        # Check growpart to disk size
        self.assertEqual(
            "4396GB",
            self.session.cmd_output(
                "parted -s /dev/sdc print|grep ' 2 '|awk '{print $3}'"),
            "Fail to resize partition")

    def test_cloudinit_dhclient_hook_disable_cloudinit(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-287483: CLOUDINIT-TC: cloud-init dhclient-hook script shoud exit
                     while cloud-init services are disabled
        1. Install cloud-init package in VM on Azure, disable cloud-init related services:
           # systemctl disable cloud-{init-local,init,config,final}
           # touch /etc/cloud/cloud-init.disabled
        2. Deprovision the VM and use this os disk to create a new VM
        3. Check the new VM status
           The cloud-init should not run , and the related services are disabled
        """
        self.log.info("RHEL-287483: CLOUDINIT-TC: cloud-init dhclient-hook script shoud exit\
             while cloud-init services are disabled.")
        # Disable cloud-init
        self.session.cmd_output("sudo systemctl disable cloud-{init-local,init,config,final}")
        time.sleep(1)
        self.assertNotIn("enabled",
                    self.session.cmd_output("sudo systemctl is-enabled cloud-{init-local,init,config,final}"),
                    "Fail to disable cloud-init related services")
        self.session.cmd_output("sudo touch /etc/cloud/cloud-init.disabled")
        # Clean the VM
        self.session.cmd_output("sudo rm -rf /var/lib/cloud /var/log/cloud-init* \
            /var/log/messages /var/lib/NetworkManager/dhclient-* \
                 /etc/resolv.conf /run/cloud-init")
        # Restart the VM
        self.session.close()
        self.vm.reboot()
        time.sleep(10)
        self.session.connect(timeout=60)

        # # Deprovision the VM
        # self.session.cmd_output("sudo rm -rf /var/lib/cloud /var/log/cloud-init* \
        #     /var/log/messages /var/lib/NetworkManager/dhclient-* \
        #          /etc/resolv.conf /run/cloud-init")      
        # self.session.close()
        # # Create new VM with this os disk
        # osdisk = self.vm.properties["storageProfile"]["osDisk"]["vhd"]["uri"]
        # self.vm.delete()
        # self.vm.image = osdisk        
        # self.vm.os_disk_name += "-new"
        # self.vm.create()
        # self.session.connect()

        # Check the VM status
        self.assertNotIn("enabled",
                    self.session.cmd_output("sudo systemctl is-enabled cloud-{init-local,init,config,final}"),
                    "Fail to disable cloud-init related services!")
        self.assertIn("status: disabled",
                    self.session.cmd_output("sudo cloud-init status"),
                    "Cloud-init status is wrong!")
        self.assertIn("inactive",
                    self.session.cmd_output("sudo systemctl is-active cloud-init-local"),
                    "cloud-init-local service status is wrong!")

    def test_cloudinit_update_existing_password(self):
        """
        :avocado: tags=tier2,cloudinit
        RHEL-198376: [Azure]Update existing user password
        1. Create a VM with user azuredebug and new password(diffrent with password in image)
        2. Login with the new password, should have sudo privilege
        """
        self.log.info(
            "RHEL-198376: [Azure]Update existing user password")
        self.vm.ssh_key_value = None
        self.vm.generate_ssh_keys = None
        self.vm.authentication_type = "password"
        self.vm.vm_username = "azuredebug"
        self.vm.vm_password = "RHEL99@Azure"
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

    def test_cloudinit_update_network_every_boot(self):
        """
        :avocado: tags=tier2,cloudinit
        VIRT-296904: [Azure]cloud-init updates network config on every boot
        1. Manually add DNS search example.com via nmcli
        2. The DNS is over-written by cloud-init after reboot
        """        
        version = self.session.cmd_output("cloud-init -v|awk '{print $2}'")
        if LooseVersion(version) < LooseVersion("22.1"):
            self.cancel(
                    "Skip case because cloud-init-{} doesn't support this feature".format(version)
                    )
        self.log.info(
            "VIRT-296904: [Azure]cloud-init updates network config on every boot")
        self.assertNotIn("search example.com",
                    self.session.cmd_output("grep 'search example.com' /etc/resolv.conf"),
                    "The dns already existed in resolv.conf before adding it")
        self.assertNotIn("DOMAIN=example.com",
                    self.session.cmd_output("grep -i DOMAIN=example.com /etc/sysconfig/network-scripts/ifcfg-eth0"),
                    "The dns already existed in ifcfg-eth0 before adding it")
        # Manually add DNS
        self.session.cmd_output("sudo nmcli con modify 'System eth0' +ipv4.dns-search example.com")
        self.assertIn("DOMAIN=example.com",
                    self.session.cmd_output("grep -i DOMAIN=example.com /etc/sysconfig/network-scripts/ifcfg-eth0"),
                    "The dns does not exist in ifcfg-eth0 after adding it")
        # Reboot VM
        self.vm.reboot()
        time.sleep(10)
        self.session.connect(timeout=60)
        self.assertNotIn("search example.com",
                    self.session.cmd_output("grep 'search example.com' /etc/resolv.conf"),
                    "The manually added dns is in resolv.conf after reboot")
        self.assertNotIn("DOMAIN=example.com",
                    self.session.cmd_output("grep -i DOMAIN=example.com /etc/sysconfig/network-scripts/ifcfg-eth0"),
                    "The manually added dns is in ifcfg-eth0 after reboot")        

    def tearDown(self):
        if not self.session.connect(timeout=10):
            self.vm.delete()
            return
        if self.case_short_name == \
                "test_cloudinit_check_networkmanager_dispatcher":
            self.session.cmd_output("sudo mv /tmp/enabled /run/cloud-init/")
            self.session.cmd_output("sudo systemctl restart NetworkManager")
        elif self.case_short_name in [
                "test_cloudinit_verify_multiple_files_in_authorizedkeysfile",
                "test_cloudinit_verify_customized_file_in_authorizedkeysfile"
        ]:
            self.session.cmd_output(
                "mv /root/sshd_config /etc/ssh/sshd_config")
        elif self.case_short_name in [
                "test_cloudinit_auto_register_with_subscription_manager",
                "test_cloudinit_auto_install_package_with_subscription_manager",
                "test_cloudinit_verify_rh_subscription_enablerepo_disablerepo"
        ]:
            self.session.cmd_output("sudo subscription-manager unregister")
        elif self.case_short_name in [
                "test_cloudinit_enable_swap_in_temporary_disk",
        ]:
            self.session.cmd_output("swapoff -a")
            self.session.cmd_output("rm -f /mnt/swapfile")
            self.session.cmd_output("sed -i '/.*swapfile.*/d' /etc/fstab")
            self.session.cmd_output("rm -f /etc/cloud/cloud.cfg.d/test_*.cfg")
        elif self.case_short_name in [
                "test_cloudinit_swapon_with_xfs_filesystem"
        ]:
            self.session.cmd_output("sudo swapoff -a")
            self.session.cmd_output("sudo umount -l /dev/sdc1")
            self.vm.unmanaged_disk_detach(self.disk_name)
            self.session.cmd_output("sed -i '/.*datatest.*/d' /etc/fstab")
            self.session.cmd_output("rm -f /etc/cloud/cloud.cfg.d/test_*.cfg")
        elif self.case_short_name in [
                "test_cloudinit_auto_register_with_subscription_manager",
                "test_cloudinit_auto_install_package_with_subscription_manager",
                "test_cloudinit_verify_rh_subscription_enablerepo_disablerepo",
                "test_cloudinit_chpasswd_with_hashed_passwords",
                "test_cloudinit_runcmd_module_execute_command",
                "test_cloudinit_check_random_password_len",
        ]:
            self.session.cmd_output("sudo rm -f /etc/cloud/cloud.cfg.d/test_*.cfg")
            if self.case_short_name in [
                "test_cloudinit_check_random_password_len",
                "test_cloudinit_chpasswd_with_hashed_passwords",
            ]:
                for user in self.session.cmd_output("sudo grep ^test /etc/passwd|cut -d: -f1").split('\n'):
                    self.session.cmd_output("sudo userdel -r {}".format(user))
        elif self.case_short_name in [
                "test_cloudinit_provision_vm_with_multiple_nics",
                "test_cloudinit_provision_vm_with_sriov_nic",
                "test_cloudinit_provision_vm_with_ipv6",
                "test_cloudinit_verify_storage_rule_gen2",
                "test_cloudinit_upgrade_downgrade_package",
                "test_cloudinit_remove_cache_and_reboot_password",
                "test_cloudinit_mount_with_noexec_option",
                "test_cloudinit_no_networkmanager",
                "test_cloudinit_dhclient_hook_disable_cloudinit",
                "test_cloudinit_update_existing_password"
        ]:
            self.vm.delete(wait=False)

    # def test_cloudinit_waagent_depro_user_with_cloudinit(self):
    #     """
    #     RHEL7-95001: WALA-TC: [Cloudinit] waagent -deprovision+user with
    #                  cloud-init enabled
    #     Description: waagent -deprovision+user should remove cloud-init
    #                  sudoers file. If not +user, should not remove this file
    #     1. Prepare a VM with wala and cloud-init installed. Enable
    #        cloud-init related services. Edit /etc/waagent.conf:
    #            Provisioning.Enabled=n
    #            Provisioning.UseCloudInit=y
    #        Deprovision this VM, shutdown, capture it as an image.
    #        Create a new VM base on this image.
    #     2. Check if /etc/sudoers.d/90-cloud-init-users exists
    #     3. Do not remove user account
    #        # waagent -deprovision -force
    #        Check if /etc/sudoers.d/90-cloud-init-users is not removed
    #     4. Remove the VM. Use the image to create a new one.
    #        Login. Remove user account
    #        # waagent -deprovision+user -force
    #        Check if /etc/sudoers.d/90-cloud-init-users is removed
    #     """
    #     self.log.info("waagent -deprovision+user with cloud-init enabled")
    #     self.log.info("Enable cloud-init related services. Edit /etc/\
    # waagent.conf. Deprovision, shutdown and capture.")
    #     self.session.cmd_output("systemctl enable cloud-{init-local,init,\
    # config,final}")
    #     time.sleep(1)
    #     self.assertNotIn("Disabled",
    #                      self.session.cmd_output("systemctl is-enabled \
    # cloud-{init-local,init,config,final}"),
    #                      "Fail to enable cloud-init related services")
    #     self.vm_test01.modify_value("Provisioning.Enabled", "n")
    #     self.vm_test01.modify_value("Provisioning.UseCloudInit", "y")
    #     self.session.cmd_output("waagent -deprovision+user -force")
    #     self.assertEqual(self.vm_test01.shutdown(), 0,
    #                      "Fail to shutdown VM")
    #     self.assertTrue(self.vm_test01.wait_for_deallocated(),
    #                     "VM status is not deallocated")
    #     cmd_params = {"os_state": "Generalized"}
    #     vm_image_name = self.vm_test01.name + "-cloudinit" + \
    #         self.vm_test01.postfix()
    #     self.assertEqual(self.vm_test01.capture(vm_image_name, cmd_params),
    #                      0,
    #                      "Fails to capture the vm: azure cli fail")
    #     self.assertTrue(self.vm_test01.wait_for_delete(check_cloudservice=False))
    #     new_vm_params = copy.deepcopy(self.vm_params)
    #     new_vm_params["Image"] = vm_image_name
    #     self.assertEqual(self.vm_test01.vm_create(new_vm_params), 0,
    #                      "Fail to create new VM base on the capture image: \
    # azure cli fail")
    #     self.assertTrue(self.vm_test01.wait_for_running() and \
    #         self.vm_test01.verify_alive(), "VM status is not running")
    #     self.log.info("2. Check if /etc/sudoers.d/90-cloud-init-users \
    # exists")
    #     self.assertTrue(self.vm_test01.is_file_exist("/etc/sudoers.d/90-cloud-init-users"),
    #                     "Fail to create /etc/sudoers.d/90-cloud-init-users")
    #     self.log.info("3. Do not remove user account")
    #     self.session.cmd_output("waagent -deprovision -force")
    #     # Login with root account because azure user account will be deleted
    #     self.assertTrue(self.vm_test01.verify_alive(username="root",
    #         password=self.vm_test01.password))

    # def test_cloudinit_upgrade_cloudinit(self):
    #     """
    #     RHEL7-95122: WALA-TC: [Cloudinit] Upgrade cloud-init
    #     1. Copy old cloud-init into VM. Get old and new cloud-init packages
    #     2. Remove new cloud-init. Install old cloud-init
    #     3. Upgrade to new cloud-init
    #     4. Deprovision. Use vhd to create a new VM. Check if works well
    #     """
    #     self.log.info("RHEL7-95122: WALA-TC: [Cloudinit] Upgrade cloud-init")
    #     # Login with root
    #     self.session.cmd_output("/usr/bin/cp -a /home/{0}/.ssh /root/;chown \
    # -R root:root /root/.ssh".format(self.vm_test01.username))
    #     self.vm_test01.session_close()
    #     self.vm_test01.verify_alive(username="root",
    #         authentication="publickey")
    #     # 1. Copy old cloud-init into VM
    #     ret = utils_misc.command(
    #         "ls %s/../tools/cloud-init-*.rpm" % REALPATH)
    #     self.assertEqual(0, ret.exit_status,
    #         "Fail to find old cloud-init package in host")
    #     old_pkg = os.path.basename(ret.stdout)
    #     self.vm_test01.copy_files_from(
    #         host_path="%s/../tools/%s" % (REALPATH, old_pkg),
    #         guest_path="/root/")
    #     self.assertTrue(self.vm_test01.is_file_exist("/root/"+old_pkg),
    #         "Cannot find %s in VM" % old_pkg)
    #     new_pkg = self.session.cmd_output("rpm -q cloud-init") + ".rpm"
    #     if not self.vm_test01.is_file_exist("/root/%s" % new_pkg):
    #         pattern=re.compile("cloud-init-(.*)-(\d+.el.*).(x86_64|noarch).rpm")
    #         res=pattern.search(new_pkg).groups()
    #         url="http://download-node-02.eng.bos.redhat.com/brewroot/packages/cloud-init/{0}/{1}/{2}/{3}"\
    #             .format(res[0],res[1],res[2],new_pkg)
    #         ret = utils_misc.command(
    #             "wget {0} -O /tmp/{1}".format(url, new_pkg)).exit_status
    #         self.assertEqual(0, ret,
    #             "Fail to download package from %s" % url)
    #         self.vm_test01.copy_files_from(host_path="/tmp/"+new_pkg,
    #                                        guest_path="/root/")
    #     self.assertTrue(self.vm_test01.is_file_exist("/root/"+new_pkg),
    #         "Cannot find %s in VM" % new_pkg)
    #     # 2. Remove new cloud-init. Install old cloud-init
    #     self.session.cmd_output("rpm -e cloud-init")
    #     self.session.cmd_output("rpm -ivh %s" % old_pkg)
    #     self.assertEqual(old_pkg, self.session.cmd_output(
    #         "rpm -q cloud-init")+".rpm",
    #         "%s is not installed successfully" % old_pkg)
    #     # 3. Upgrade to new cloud-init


if __name__ == "__main__":
    main()
