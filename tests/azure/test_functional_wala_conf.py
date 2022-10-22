import time
import re
import os
from avocado import Test
from avocado import main
from avocado_cloud.app import Setup
from avocado_cloud.app.azure import AzureAccount
from distutils.version import LooseVersion
from avocado_cloud.utils.utils_azure import file_exists
from avocado_cloud.utils import utils_azure

BASEPATH = os.path.abspath(__file__ + "/../../../")


class WALAConfTest(Test):
    """
    :avocado: tags=wala
    """

    def setUp(self):
        account = AzureAccount(self.params)
        account.login()
        self.case_short_name = re.findall(r"Test.(.*)", self.name.name)[0]
        if self.case_short_name == "test_resource_disk_gpt_partition":
            cloud = Setup(self.params, self.name, size="M64ls")
        else:
            cloud = Setup(self.params, self.name)
        self.vm = cloud.vm
        self.session = cloud.init_vm()
        self.session.cmd_output("sudo /usr/bin/cp /etc/waagent.conf{,-bak}")
        if self.case_short_name != "test_self_update" and \
           not self.case_short_name.startswith("test_http_proxy"):
            self._modify_value("AutoUpdate.Enabled", "n")
        self.project = self.params.get("rhel_ver", "*/VM/*")
        self.username = self.vm.vm_username
        # if self.case_short_name.startswith("test_http_proxy"):
        #     proxy = Setup(self.params, self.name, size="D1_v2")
        #     proxy.vm.vm_name = "walaautoproxy"
        #     proxy.vm.vm_username = "root"
        #     self.proxy_vm = proxy.vm
        #     self.proxy_session = proxy.init_vm()
        #     if self.proxy_session.cmd_status_output(
        #             "netstat -antp|grep squid")[0] != 0:
        #         self.proxy_session.cmd_output("systemctl start squid")
        #         time.sleep(5)
        #         if self.proxy_session.cmd_status_output(
        #                 "netstat -antp|grep squid")[0] != 0:
        #             self.error("Cannot enable squid proxy")
        #     self.proxy_ip = self.proxy_vm.properties["privateIps"]

    def _recovery(self):
        self.session.cmd_output("sudo /usr/bin/cp -a ~/.ssh /root/;\
sudo chown -R root:root /root/.ssh")
        self.session.close()
        self.vm.vm_username = "root"
        self.session.connect()
        self.session.cmd_output(
            "/usr/bin/mv -f /tmp/waagent-bak /var/lib/waagent")
        self.session.cmd_output("useradd {}".format(self.username))
        self.session.cmd_output(
            "/usr/bin/cp -a /root/.ssh /home/{0}/;chown -R {0}:{0} \
/home/{0}/.ssh".format(self.username))
        self.session.cmd_output("hostnamectl set-hostname {0}".format(
            self.vm.vm_name))
        self.session.cmd_output("systemctl start waagent")
        self.session.cmd_output(
            "mount {}1 /mnt/resource".format(self._get_temporary_disk()))
        self.session.cmd_output("rm -f /tmp/deprovisioned")

#     def _deprovision(self):
#         self.session.cmd_output(
#             "sudo /usr/bin/cp -a ~/.ssh /root/;sudo chown -R root:root \
# /root/.ssh")
#         self.session.close()
#         self.vm.vm_username = "root"
#         self.session.connect()
#         self.session.cmd_output("systemctl stop waagent")
#         self.session.cmd_output(
#             "/usr/bin/mv /var/lib/waagent /tmp/waagent-bak")
#         self.session.cmd_output("userdel -rf {}".format(self.username))
#         if self.session.cmd_status_output('id {}'.format(self.username))[0] == 0:
#             self.log.debug("Fail to delete user! Retry...")
#             time.sleep(1)
#             self.session.cmd_output("ps aux|grep {}".format(self.username))
#             self.session.cmd_output("userdel -rf {}".format(self.username))
#         self.session.cmd_output("rm -f /var/log/waagent.log")
#         self.session.cmd_output("touch /tmp/deprovisioned")

    def _modify_value(self,
                      key,
                      value,
                      conf_file="/etc/waagent.conf",
                      sepr='='):
        self.log.info("Setting {0}{1}{2} in {3}...".format(
            key, sepr, value, conf_file))
        self.session.cmd_output(
            "sudo sed -i -e '$a{0}{1}{2}' -e '/^.*{0}.*$/d' {3}".format(
                key, sepr, value, conf_file))
        self.session.cmd_output("sync", timeout=60)
        self._verify_value(key, value, conf_file, sepr)

    def _verify_value(self,
                      key,
                      value,
                      conf_file="/etc/waagent.conf",
                      sepr='='):
        self.assertEqual(
            0,
            self.session.cmd_status_output("grep -R \'^{0}{1}{2}\' {3}".format(
                key, sepr, value, conf_file))[0],
            "{0}{1}{2} is not in {3}".format(key, sepr, value, conf_file))

    # def _recreate_vm(self, tag, timeout=1200, **kwargs):
    #     osdisk_uri = self.vm.properties["storageProfile"]["osDisk"]["vhd"][
    #         "uri"]
    #     cloud = Setup(self.params, self.name)
    #     cloud.vm.vm_name = self.vm.vm_name + "-" + tag
    #     cloud.vm.image = osdisk_uri
    #     cloud.vm.os_disk_name = self.vm.vm_name + "_os" + \
    #         time.strftime("%m%d%H%M%S", time.localtime())
    #     for key in kwargs:
    #         if key not in dir(cloud.vm):
    #             self.log.debug(
    #                 "No such property in AzureVM class: {}".format(key))
    #         value = kwargs.get(key)
    #         if value not in [True, False, None]:
    #             value = "\"{}\"".format(value)
    #         exec("cloud.vm.{0} = {1}".format(key, value))
    #     cloud.vm.show()
    #     if cloud.vm.exists():
    #         cloud.vm.delete(wait=True)
    #     session = None
    #     wait = kwargs.get("wait", True)
    #     try:
    #         cloud.vm.create(wait=wait)
    #         session = cloud.init_session()
    #         if kwargs.get("connect", True) is True:
    #             session.connect()
    #     except Exception:
    #         raise
    #     finally:
    #         return (cloud.vm, session)

    def _get_temporary_disk(self):
        boot_dev = self.session.cmd_output("mount|grep 'boot'|head -1| cut -c1-8")
        if boot_dev == '/dev/sda':
            return '/dev/sdb'
        elif boot_dev == '/dev/sdb':
            return '/dev/sda'
        else:
            self.error('Cannot get temporary disk name!')

    def test_delete_root_passwd(self):
        """
        :avocado: tags=tier1
        RHEL7-41709	WALA-TC: [WALA conf] Delete root password
        Check Provisioning.DeleteRootPassword = n or y
        """
        self.log.info("RHEL7-41709 WALA-TC: [WALA conf] Delete root password")
        # 1. Provisioning.DeleteRootPassword=y
        self._modify_value("Provisioning.DeleteRootPassword", "y")
        self.session.cmd_output(
            r"sudo sed -i -e '1i\root:*teststring*:14600::::::' \
-e '/^root.*$/d' /etc/shadow")
        self.session.cmd_output("sync")
        utils_azure.deprovision(self)
        self.vm_1, session_1 = utils_azure.recreate_vm(self, "delrootpw-y")
        self.assertTrue(
            session_1.connect(), "Fail to connect to VM after setting \
                        Provisioning.DeleteRootPassword=y and recreat VM.")
        self.assertIn("LOCK",
                      session_1.cmd_output("sudo cat /etc/shadow|grep root"),
                      "Fail to delete root password")
        # 2. Provisioning.DeleteRootPassword=n
        self._modify_value("Provisioning.DeleteRootPassword", "n")
        self.vm_2, session_2 = utils_azure.recreate_vm(self, "delrootpw-n")
        self.assertTrue(
            session_2.connect(), "Fail to connect to VM after setting \
                        Provisioning.DeleteRootPassword=n and recreat VM.")
        self.assertNotIn(
            "LOCK", session_2.cmd_output("sudo cat /etc/shadow|grep root"),
            "Should not delete root password")

    def test_enable_verbose_logging(self):
        """
        :avocado: tags=tier2
        Check Logs.Verbose=y or n
        """
        self.log.info("WALA conf: Enable verbose logging")
        wala_log = "/var/log/waagent.log"
        # 1. Logs.Verbose=y
        self._modify_value("Logs.Verbose", "y")
        self.session.cmd_output("sudo service waagent restart")
        time.sleep(5)
        self.assertEqual(
            self.session.cmd_status_output(
                "grep VERBOSE {} > /dev/null".format(wala_log))[0], 0,
            "Fail to enable Verbose log")
        # 2. Logs.Verbose=n
        self._modify_value("Logs.Verbose", "n")
        self.session.cmd_output("sudo service waagent stop")
        self.session.cmd_output("sudo rm -f {}".format(wala_log))
        self.session.cmd_output("sudo service waagent start")
        time.sleep(5)
        self.assertEqual(
            self.session.cmd_status_output(
                "grep VERBOSE {}".format(wala_log))[0], 1,
            "Fail to disable Verbose log")

    def test_regenerate_ssh_host_key(self):
        """
        :avocado: tags=tier2
        """
        self.log.info("WALA conf: Regenerate ssh host key pairs")
        # 1. Provisioning.RegenerateSshHostKeyPair=n
        self._modify_value("Provisioning.RegenerateSshHostKeyPair", "n")
        self._modify_value("Provisioning.SshHostKeyPairType", "dsa")
        self.session.cmd_output("sudo /usr/bin/cp /etc/ssh/sshd_config{,-bak}")
        self.session.cmd_output(
            "sudo sed -i '/ssh_host_dsa_key/d' /etc/ssh/sshd_config")
        self.session.cmd_output("sudo ssh-keygen -A")
        self.session.cmd_output("sudo sync")
        md5_0 = self.session.cmd_output(
            "sudo md5sum /etc/ssh/ssh_host_dsa_key")
        deprovision_output = self.session.cmd_output(
            "echo 'n'|sudo waagent -deprovision")
        warn_msg = "WARNING! All SSH host key pairs will be deleted"
        self.assertNotIn(
            warn_msg, deprovision_output,
            "BZ#1314734: Should not have warning message: {0}. \n"
            "Real messages:\n{1}".format(warn_msg, deprovision_output))
        # md5_1b = self.session.cmd_output("sudo md5sum /etc/ssh/\
        # ssh_host_dsa_key")
        # self.assertEqual(md5_1a, md5_1b,
        #                  "Should not remove old ssh host keys in \
        # deprovisioning")
        utils_azure.deprovision(self)
        self.vm_1, session_1 = utils_azure.recreate_vm(self, "regsshkey-n")
        md5_1 = session_1.cmd_output("sudo md5sum /etc/ssh/ssh_host_dsa_key")
        self.assertEqual(
            md5_0, md5_1,
            "Should not regenerate ssh host keys in provisioning")
        session_1.close()
        # 2. Provisioning.RegenerateSshHostKeyPair=y
        self._modify_value("Provisioning.RegenerateSshHostKeyPair", "y")
        # md5_2a = self.session.cmd_output("sudo md5sum /etc/ssh/\
        # ssh_host_dsa_key")
        deprovision_output = self.session.cmd_output(
            "echo 'n'|sudo waagent -deprovision")
        self.assertIn(
            warn_msg, deprovision_output, "Don't have warning message: {0}. \n"
            "Real messages:\n{1}".format(warn_msg, deprovision_output))
        # md5_2b = self.session.cmd_output("sudo md5sum /etc/ssh/\
        # ssh_host_dsa_key")
        # self.assertNotEqual(md5_2a, md5_2b,
        #                     "Fail to remove old ssh host keys in \
        # deprovisioning")
        self.vm_2, session_2 = utils_azure.recreate_vm(self, "regsshkey-y")
        md5_2 = session_2.cmd_output("sudo md5sum /etc/ssh/ssh_host_dsa_key")
        self.assertNotEqual(
            md5_0, md5_2, "Fail to regenerate ssh host keys in provisioning")

    def test_resource_disk_mount_point(self):
        """
        :avocado: tags=tier2
        Check changing ResourceDisk.MountPoint
        """
        self.log.info("WALA conf: Resource disk mount point")
        # 1. ResourceDisk.MountPoint=/mnt/resource-new
        #    ResourceDisk.Format=y
        temporary_disk = self._get_temporary_disk()
        self._modify_value("ResourceDisk.MountPoint", "/mnt/resource-new")
        self._modify_value("ResourceDisk.Format", "y")
        self.session.cmd_output("sudo umount -l {}1".format(temporary_disk))
        self.session.cmd_output("sudo service waagent restart")
        max_retry = 10
        for retry in range(1, max_retry + 1):
            if self.session.cmd_status_output(
                    "ls /mnt/resource-new/DATALOSS_WARNING_README.txt"
            )[0] == 0:
                break
            else:
                self.log.info("Retry %d/%d times" % (retry, max_retry))
                time.sleep(10)
        else:
            self.fail("There's no DATALOSS_WARNING_README.txt in the \
new resource path")
        # 2. ResourceDisk.Format=n
        self._modify_value("ResourceDisk.Format", "n")
        self.session.cmd_output("sudo umount -l {}1".format(temporary_disk))
        self.session.cmd_output("sudo service waagent restart")
        self.assertEqual(
            self.session.cmd_status_output(
                "mount|grep {}".format(temporary_disk))[0], 1,
            "Fail to disable resource disk format")

    def test_resource_disk_file_type(self):
        """
        :avocado: tags=tier1
        Check changing ResourceDisk.Filesystem=ext4/xfs
        """
        self.log.info("WALA conf: Resource disk file type")
        # 1. ResourceDisk.Filesystem=ext4 (Default)
        self._verify_value("ResourceDisk.Filesystem", "ext4")
        self._modify_value("ResourceDisk.Format", "y")
        self._modify_value("ResourceDisk.SwapSizeMB", "2048")
        max_retry = 3
        for retry in range(1, max_retry + 1):
            if "ext4" in self.session.cmd_output("mount|grep /mnt/resource"):
                break
            else:
                self.log.info("Retry %d/%d times." % (retry, max_retry))
                time.sleep(30)
        else:
            self.fail("Fail to set resource disk file system to ext4")
        # Disable default swap
        if LooseVersion(self.project) < LooseVersion("7.0"):
            self.session.cmd_output(
                "sudo swapoff /dev/mapper/VolGroup-lv_swap")
        else:
            self.session.cmd_output("sudo swapoff /dev/mapper/rhel-swap")
        max_retry = 3
        for retry in range(1, max_retry + 1):
            swapsize = self.session.cmd_output(
                "free -m|grep Swap|awk '{print $2}'")
            if swapsize == "2047":
                break
            else:
                self.log.info("Swap size is wrong. Retry %d/%d times." %
                              (retry, max_retry))
                time.sleep(30)
        else:
            self.fail("After retry %d times, swap is not enabled \
in ext4 file system." % max_retry)
        # 2. ResourceDisk.Filesystem=xfs(Not available for RHEL-6)
        if LooseVersion(self.project) < LooseVersion("7.0"):
            self.log.info("RHEL-%s doesn't support xfs type. Skip this step." %
                          self.project)
        else:
            self.log.info("ResourceDisk.Filesystem=xfs")
            self._modify_value("ResourceDisk.Filesystem", "xfs")
            self._modify_value("ResourceDisk.Format", "y")
            self._modify_value("ResourceDisk.SwapSizeMB", "2048")
            self.session.cmd_output(
                "sudo rm -rf /var/lib/waagent/* /var/log/waagent.log")
            self.vm_1, session_1 = utils_azure.recreate_vm(self, "fstype-xfs")
            self.assertIn(
                "xfs", session_1.cmd_output("mount|grep /mnt/resource"),
                "Bug 1372276. "
                "Fail to set resource disk file system to xfs")
        if LooseVersion(self.project) < LooseVersion("7.0"):
            session_1.cmd_output("sudo swapoff /dev/mapper/VolGroup-lv_swap")
        else:
            session_1.cmd_output("sudo swapoff /dev/mapper/rhel-swap")
            max_retry = 3
            for retry in range(1, max_retry + 1):
                swapsize = session_1.cmd_output(
                    "free -m|grep Swap|awk '{print $2}'")
                if swapsize == "2047":
                    break
                else:
                    self.log.info("Swap size is wrong. Retry %d/%d times." %
                                  (retry, max_retry))
                    time.sleep(30)
            else:
                self.fail("Bug 1386494. After retry %d times, swap is \
not enabled in xfs file system." % max_retry)

    def _swapsize_check(self, swapsize, std_swapsize=None, max_retry=30):
        # 1. ResourceDisk.Enable=y
        #    ResourceDisk.SwapSizeMB=swapsize
        self.log.info("ResourceDisk.SwapSizeMB={0}".format(swapsize))
        self._modify_value("ResourceDisk.EnableSwap", "y")
        self._modify_value("ResourceDisk.SwapSizeMB", swapsize)
        self.session.cmd_output("sudo systemctl restart waagent")
        time.sleep(10)
        # Retry 30 times (300s in total) to wait for the swap file created.
        # The real swapsize is a little smaller than standard. So the
        # std_swapsize is swapsize-1
        if not isinstance(std_swapsize, int):
            try:
                std_swapsize = int(std_swapsize)
            except:
                if int(swapsize) == 0:
                    std_swapsize = swapsize
                else:
                    std_swapsize = int(swapsize) - 1
        for retry in range(1, max_retry + 1):
            real_swapsize = self.session.cmd_output(
                "free -m|grep Swap|awk '{print $2}'")
            if real_swapsize == str(std_swapsize):
                break
            else:
                self.log.info("Swap size is wrong. Retry %d/%d times." %
                              (retry, max_retry))
                time.sleep(10)
        else:
            self.fail("After retry {0} times, \
ResourceDisk.SwapSizeMB={1} doesn't work.".format(max_retry, swapsize))

    def test_resource_disk_swap_check(self):
        """
        :avocado: tags=tier1
        Check ResourceDisk.SwapSizeMB=1024 or ResourceDisk.Enable=n
        """
        self.log.info("WALA conf: Resource disk swap check")
        # Disable the default swap
        if LooseVersion(self.project) < LooseVersion("7.0"):
            self.session.cmd_output("sudo sed -i '/^\/dev\/mapper\/\
VolGroup-lv_swap/s/^/#/' /etc/fstab")
        else:
            self.session.cmd_output(
                "sudo sed -i '/^\/dev\/mapper\/rhel-swap/s/^/#/' /etc/fstab")
        # 1.ResourceDisk.Enable=n
        self.log.info("ResourceDisk.EnableSwap=n")
        self._modify_value("ResourceDisk.EnableSwap", "n")
        self.session.close()
        self.vm.reboot()
        self.session.connect()
        self.assertEqual(
            self.session.cmd_output("free -m|grep Swap|awk '{print $2}'"), "0",
            "Fail to disable ResourceDisk swap.")
        # 2. ResourceDisk.Enable=y
        #    ResourceDisk.SwapSizeMB=2048
        self._swapsize_check(swapsize="2048")

    def test_resource_disk_swap_unusual_check(self):
        """
        :avocado: tags=tier2
        Resource disk - swap - unusual check
        """
        self.log.info("Resource disk - swap size - unusual check")
        # Disable the default swap
        if LooseVersion(self.project) < LooseVersion("7.0"):
            self.session.cmd_output("sudo sed -i '/^\/dev\/mapper\/\
VolGroup-lv_swap/s/^/#/' /etc/fstab")
        else:
            self.session.cmd_output("sudo sed -i '/^\/dev\/mapper\/\
rhel-swap/s/^/#/' /etc/fstab")
        result_error_msg = ""
        self.log.info("1. non-integer multiple of 64M size check")
        try:
            self._swapsize_check(swapsize="1025")
        except:
            result_error_msg += \
                "BZ#1977216:non-integer multiple of 64M size check failed\n"
        self.log.info("2. large swap check")
        try:
            self._swapsize_check(swapsize="50070")
        except:
            result_error_msg += "large swap check failed\n"
        self.log.info("3. zero size")
        try:
            self._swapsize_check(swapsize="0")
        except:
            result_error_msg += "zero size swap check failed\n"
        self.assertEqual(result_error_msg, "", result_error_msg)

    def test_resource_disk_gpt_partition(self):
        """
        :avocado: tags=tier2
        Resource disk GPT partition
        """
        self.log.info("WALA conf: Resource disk GPT partition")
        self.session.cmd_output("sudo su -")
        temporary_disk = self._get_temporary_disk()
        self.assertNotEqual(
            self.session.cmd_output(
                "parted {} print|grep gpt".format(temporary_disk)), "",
            "{} is not GPT partition. Exit.".format(temporary_disk))
        # Set resource disk
        self._swapsize_check(swapsize="2048")
        # Ignore this checkpoint because of won't fix BZ#1814143
        # # Check waagent.log
        # with open("{}/data/azure/ignore_waagent_messages".format(BASEPATH),
        #           'r') as f:
        #     ignore_message_list = f.read().split('\n')
        # cmd = "sudo sh -c \"grep -iE '(error|fail)' /var/log/waagent.log\""
        # if ignore_message_list:
        #     cmd += "|grep -vE '({})'".format('|'.join(ignore_message_list))
        # error_log = self.session.cmd_output(cmd)
        # if error_log:
        #     self.log.warn("Error logs in waagent.log: \n{}".format(error_log))


    def test_monitor_hostname(self):
        """
        :avocado: tags=tier1
        Check Provisioning.MonitorHostName=y or n
        """
        self.log.info("WALA conf: Monitor Hostname")
        # eth_file = "/etc/sysconfig/network-scripts/ifcfg-eth0"
        # The time of waiting for the hostname to be publish
        WAIT_TIME = 40
        hostname0 = self.vm.vm_name
        hostname1 = "walahostcheck1"
        hostname2 = "walahostcheck2"
        # Verify default value is y
        self._verify_value("Provisioning.MonitorHostName", "y")
        # Change monitor period to 10s
        self._modify_value("Provisioning.MonitorHostNamePeriod", "10")
        # 1. Provisioning.MonitorHostName=n
        self.log.info("Provisioning.MonitorHostName=n")
        self._modify_value("Provisioning.MonitorHostName", "n")
        self.session.cmd_output("sudo service waagent restart")
        time.sleep(5)
        # self.session.cmd_output("sed -i '/^DHCP_HOSTNAME/d' %s" % eth_file)
        if LooseVersion(self.project) < LooseVersion("7.0"):
            self.session.send_line("sudo hostname %s" % hostname1)
        else:
            self.session.cmd_output("sudo hostnamectl set-hostname %s" %
                                    hostname1)
        time.sleep(WAIT_TIME)
        self.session.connect()
        if LooseVersion(self.project) < LooseVersion("7.0"):
            cmd = "sudo grep '' /etc/sysconfig/network"
        else:
            cmd = "sudo grep '' /etc/hostname"
        self.assertIn(hostname1, self.session.cmd_output(cmd),
                      "Fail to set hostname in disable MinitorHostName case")
        # From WALinuxAgent-2.7.0.6-3.el8/el9, use nmcli instead of DHCP_HOSTNAME
        # to publish hostname to DNS
        # Old hostname should be in DNS
        self.assertNotIn(
            "NXDOMAIN",
            self.session.cmd_output("nslookup {}".format(
                hostname0)), "Old hostname should be in DNS when MonitorHostName=n")
        # New hostname should not be in DNS
        self.assertIn(
            "NXDOMAIN",
            self.session.cmd_output("nslookup {0}".format(
                hostname1)), "New hostname should not be in DNS when MonitorHostName=n")
        # 2. Provisioning.MonitorHostName=y
        self.log.info("Provisioning.MonitorHostName=y")
        self._modify_value("Provisioning.MonitorHostName", "y")
        self.session.cmd_output("sudo service waagent restart")
        time.sleep(5)
        # self.session.cmd_output("sudo sed -i '/^DHCP_HOSTNAME/d' %s" %
        #                         eth_file)
        if LooseVersion(self.project) < LooseVersion("7.0"):
            self.session.send_line("sudo hostname %s" % hostname2)
        else:
            self.session.cmd_output("sudo hostnamectl set-hostname %s" %
                                    hostname2)
        self.session.close()
        time.sleep(WAIT_TIME)
        self.session.connect()
        if LooseVersion(self.project) < LooseVersion("7.0"):
            cmd = "sudo grep '' /etc/sysconfig/network"
        else:
            cmd = "sudo grep '' /etc/hostname"
        self.assertIn(hostname2, self.session.cmd_output(cmd),
                      "Fail to set hostname in enable MinitorHostName case")
        max_retry = 10
        for retry in (1, max_retry+1):
            output = self.session.cmd_output("nslookup {}".format(hostname2))
            if "NXDOMAIN" not in output:
                break
            # Old hostname should not be in DNS
            self.log.debug("New hostname is not published. Wait for 5s and try again...({}/{})".format(retry, max_retry))
            time.sleep(5)
        else:
            self.fail("New hostname should be in DNS when MonitorHostName=n")
        self.assertIn(
            "NXDOMAIN",
            self.session.cmd_output("nslookup {}".format(
                hostname0)), "Old hostname should not be in DNS when MonitorHostName=n")

        # self.assertEqual(
        #     self.session.cmd_output("sudo grep DHCP_HOSTNAME %s" % eth_file),
        #     "DHCP_HOSTNAME=%s" % hostname2,
        #     "DHCP_HOSTNAME is not changed when Provisioning.MonitorHostName=y")

    def test_device_timeout(self):
        """
        :avocado: tags=tier2
        Check the root device timeout
        """
        self.log.info("WALA conf: Check root device timeout")
        # 1. OS.RootDeviceScsiTimeout=100
        self.log.info("OS.RootDeviceScsiTimeout=100")
        self._modify_value("OS.RootDeviceScsiTimeout", "100")
        self.session.cmd_output("sudo service waagent restart")
        time.sleep(15)
        self.assertEqual(
            self.session.cmd_output("sudo cat /sys/block/sda/device/timeout"),
            "100", "OS.RootDeviceScsiTimeout=100 doesn't work for sda.")
        self.assertEqual(
            self.session.cmd_output("sudo cat /sys/block/sdb/device/timeout"),
            "100", "OS.RootDeviceScsiTimeout=100 doesn't work for sdb.")

    def test_disable_provisioning(self):
        """
        :avocado: tags=tier2
        Check if Provisioning.Enabled works well
        """
        self.log.info(
            "WALA conf: Enable and disable the instance creation(provisioning)"
        )
        # 1. Provisioning.Enabled=n
        self._modify_value("Provisioning.Enabled", "n")
        utils_azure.deprovision(self)
        new_username = "azureuser1"
        self.vm_1, session_1 = utils_azure.recreate_vm(self, "disableprovision",
                                                 connect=False,
                                                 vm_username=new_username)
        self.vm_1.vm_username = 'root'
        session_1.connect()
        # Check if not create new user
        self.assertIn("no such user", session_1.cmd_output("id {}".format(
            new_username)))
        # Check if create provisioned file
        self.assertTrue(file_exists("/var/lib/waagent/provisioned", session_1),
                        "Fail to generate provisioned file")

    def test_reset_system_account(self):
        """
        :avocado: tags=tier2
        Provisioning.AllowResetSysUser
        """
        self.log.info("WALA conf: reset system account")
        # Login with root account
        old_username = self.vm.vm_username
        old_password = self.vm.vm_password
        new_password = old_password + "new"
        # self.session.cmd_output("echo %s | sudo passwd --stdin root"
        #     % self.vm.vm_password)
        self.session.cmd_output("sudo sed -i 's/^PasswordAuthentication.*$/\
PasswordAuthentication yes/g' /etc/ssh/sshd_config")
        self.session.cmd_output("sudo service sshd restart")
        # 1. Provisioning.AllowResetSysUser=n
        self.log.info("Provisioning.AllowResetSysUser=n")
        self._modify_value("Provisioning.AllowResetSysUser", "n")
        utils_azure.deprovision(self)
        # Set 400 uid to azureuser
        self.session.cmd_output("useradd -u 400 %s" % old_username)
        self.assertEqual(
            "400", self.session.cmd_output("id -u {}".format(old_username)),
            "Fail to set uid to 400")
        self.session.cmd_output("echo {0}|passwd --stdin {1}".format(
            old_password, old_username))
        self.vm_1, session_1 = utils_azure.recreate_vm(
            self,
            tag="resetsysuser-n",
            authentication_type="password",
            vm_password=new_password,
            ssh_key_value=None,
            generate_ssh_keys=None,
            wait=False,
            connect=False)
        time.sleep(120)
        self.vm_1.vm_password = old_password
        self.vm_1.show()
        self.assertTrue(session_1.connect(authentication="password"),
                        "Cannot login with the old password.")
        # 2. Provisioning.AllowResetSysUser=y
        self.log.info("Provisioning.AllowResetSysUser=y")
        self._modify_value("Provisioning.AllowResetSysUser", "y")
        self.vm_2, session_2 = utils_azure.recreate_vm(
            self,
            tag="resetsysuser-y",
            authentication_type="password",
            vm_password=new_password,
            ssh_key_value=None,
            generate_ssh_keys=None,
            connect=False)
        self.vm_2.vm_password = new_password
        self.assertTrue(session_2.connect(authentication="password"),
                        "Cannot login with the new password.")

    def test_http_proxy_host_port(self):
        """
        :avocado: tags=tier2
        Check if waagent can work well with proxy
        """
        # 1. Check http proxy host and port
        self._modify_value("HttpProxy.Host", "10.0.0.254")
        self._modify_value("HttpProxy.Port", "3128")
        self.session.cmd_output("sudo rm -rf /var/lib/waagent/WALinuxAgent-*")
        self.session.cmd_output("sudo service waagent restart")
        self.assertEqual(
            self.session.cmd_status_output(
                "sudo timeout 30 tcpdump host 10.0.0.254 and "
                "tcp -iany -nnn -s 0 -c 1",
                timeout=120)[0], 0, "Bug 1368002. "
            "waagent doesn't use http proxy")

    def test_http_proxy_system_environment(self):
        """
        :avocado: tags=tier2
        WALA-TC: [WALA conf] Use system http_proxy environment
        Check if waagent can work well with system environment http_proxy
        1. HttpProxy.Host=None HttpProxy.Port=None
        2. Set http_proxy in system environment; restart waagent service
        3. Catch packages
        """
        # 1. HttpProxy.Host=None HttpProxy.Port=None
        self._modify_value("HttpProxy.Host", "None")
        self._modify_value("HttpProxy.Port", "None")
        # 2. Set http_proxy in system environment; restart waagent service
        self.session.cmd_output("sudo service waagent stop")
        self.session.cmd_output("sudo sed -i '/Service/a\Environment=\
\"https_proxy=https://10.0.0.254:3128\"' \
/usr/lib/systemd/system/waagent.service")
        self.session.cmd_output("sudo systemctl daemon-reload")
        self.session.cmd_output("sudo rm -rf /var/lib/waagent/WALinuxAgent-*")
        self.session.cmd_output("sudo service waagent start")
        # 3. Catch traffic
        self.assertEqual(
            self.session.cmd_status_output(
                "sudo timeout 30 tcpdump host 10.0.0.254 and "
                "tcp -iany -nnn -s 0 -c 1",
                timeout=120)[0], 0, "Bug 1368002. "
            "waagent doesn't use system environment proxy")

    def test_attach_disk_check_device_timeout(self):
        """
        :avocado: tags=tier2
        Attach new disk and check root device timeout
        """
        self.log.info("Attach new disk and check root device timeout")
        # Ensure the default root device timeout is 300
        self._modify_value("OS.RootDeviceScsiTimeout", "300")
        # Attach a new data disk

        self.disk_name = self.vm.vm_name + "-disk1-" + time.strftime(
            "%m%d%H%M%S", time.localtime())
        self.vm.unmanaged_disk_attach(self.disk_name, 1)
        time.sleep(5)
        # Check the new device timeout
        self.assertEqual(
            "300",
            self.session.cmd_output("sudo cat /sys/block/sdc/device/timeout"),
            "Fail to set the new data disk timeout to 300")

    def test_autorecover_device_timeout(self):
        """
        :avocado: tags=tier2
        Auto-recover root device timeout
        """
        self.log.info("Auto-recover root device timeout")
        # Ensure the timeout is 300
        self.assertEqual(
            self.session.cmd_output("sudo cat /sys/block/sda/device/timeout"),
            "300", "Original timeout is not 300")
        self.assertEqual(
            self.session.cmd_output("sudo cat /sys/block/sdb/device/timeout"),
            "300", "Original timeout is not 300")
        # Modify device timeout to 100
        self.session.cmd_output(
            "sudo echo 100 | tee /sys/block/sd*/device/timeout")
        # Wait for 5s, check device timeout
        time.sleep(5)
        self.assertEqual(
            self.session.cmd_output("sudo cat /sys/block/sda/device/timeout"),
            "300", "Device timeout is not recovered to 300")
        self.assertEqual(
            self.session.cmd_output("sudo cat /sys/block/sdb/device/timeout"),
            "300", "Device timeout is not recovered to 300")

    def test_check_useless_parameters(self):
        """
        :avocado: tags=tier2
        Check useless parameters
        """
        self.log.info("Check useless parameters")
        useless_param_list = [
            "Role.StateConsumer", "Role.ConfigurationConsumer",
            "Role.TopologyConsumer"
        ]
        output = self.session.cmd_output(
            "sudo grep -E \"{0}\" /etc/waagent.conf".format(
                '|'.join(useless_param_list)))
        self.assertEqual(output, "",
                         "There're useless parameters: {0}".format(output))

    def _wait_for_exthandlers(self):
        max_retry = 10
        for retry in range(1, max_retry + 1):
            output = self.session.cmd_output("ps aux|grep [-]run-exthandlers")
            if output != '':
                return output
            self.log.info("Wait for run-exthandlers start. Retry %d/%d times" %
                          (retry, max_retry))
            time.sleep(10)
        else:
            self.fail("Fail to start run-exthandlers after retry %d times" %
                      max_retry)

    def test_self_update(self):
        """
        :avocado: tags=tier2
        AutoUpdate.Enabled
        """
        self.log.info("WALA conf: self-update")
        self.session.cmd_output("sudo su -")
        x, y, z = self.session.cmd_output("rpm -q WALinuxAgent").split(
            '-')[1].split('.')[:3]
        low_version = "2.0.0"
        high_version = "{0}.{1}.{2}".format(int(x) + 10, y, z)
        self.log.info("Low version: " + low_version)
        self.log.info("High version: " + high_version)
        if LooseVersion(self.project) < LooseVersion("8.0"):
            python = "python"
        else:
            python = "python3"
        import re
        _, px, py, pz = re.split(
            '[ .]', self.session.cmd_output("%s --version" % python))
        version_file = "/usr/lib/python%s.%s/site-packages/\
azurelinuxagent/common/version.py" % (px, py)
        # 1. AutoUpdate.Enabled=y
        self._modify_value("AutoUpdate.Enabled", "y")
        # 1.1 local version is lower than new version
        self.log.info("1.1 local version is lower than new version")
        self.session.cmd_output(
            "sed -i \"s/^AGENT_VERSION.*$/AGENT_VERSION = '{0}'/g\" {1}".
            format(low_version, version_file))
        self.assertEqual(
            "AGENT_VERSION = '%s'" % low_version,
            self.session.cmd_output("grep -R '^AGENT_VERSION' %s" %
                                    version_file),
            "Fail to modify local version to %s" % low_version)
        self.session.cmd_output("service waagent restart")
        # Check feature
        time.sleep(10)
        max_retry = 10
        for retry in range(1, max_retry + 1):
            if "egg" in self.session.cmd_output(
                    "ps aux|grep [-]run-exthandlers"):
                break
            self.log.info("Wait for updating. Retry %d/%d times" %
                          (retry, max_retry))
            time.sleep(30)
        else:
            self.fail("[RHEL-6]Bug 1371071. "
                      "Fail to enable AutoUpdate after retry %d times" %
                      max_retry)
        # 1.2 local version is higher than new version
        self.log.info("1.2 local version is higher than new version")
        self.session.cmd_output(
            "sed -i \"s/^AGENT_VERSION.*$/AGENT_VERSION = '{0}'/g\" {1}".
            format(high_version, version_file))
        self.assertEqual(
            "AGENT_VERSION = '%s'" % high_version,
            self.session.cmd_output("grep -R '^AGENT_VERSION' %s" %
                                    version_file),
            "Fail to modify local version to %s" % high_version)
        self.session.cmd_output("service waagent restart")
        time.sleep(10)
        # Check feature
        output = self._wait_for_exthandlers()
        self.assertIn(
            "/usr/sbin/waagent -run-exthandlers",
            output,
            #   self.session.cmd_output("ps aux|grep [-]run-exthandlers"),
            "Should not use new version if local version is higher")
        # 1.3 restart again
        self.log.info("1.3 Restart waagent service again and check")
        self.session.cmd_output("service waagent restart")
        time.sleep(10)
        output = self._wait_for_exthandlers()
        self.assertIn(
            "/usr/sbin/waagent -run-exthandlers",
            output,
            #   self.session.cmd_output("ps aux|grep [-]run-exthandlers"),
            "Should not use new version if local version is higher")
        # 2. AutoUpdate.Enabled=n
        self.log.info("2. AutoUpdate.Enabled=n")
        self._modify_value("AutoUpdate.Enabled", "n")
        self.session.cmd_output("service waagent restart")
        time.sleep(10)
        # Check feature
        output = self._wait_for_exthandlers()
        self.assertIn(
            "/usr/sbin/waagent -run-exthandlers",
            output,
            #   self.session.cmd_output("ps aux|grep [-]run-exthandlers"),
            "Fail to disable AutoUpdate")
        # 3. Remove AutoUpdate.enabled parameter and check the default value
        self.log.info("3. Remove AutoUpdate.enabled parameter and check \
the default value")
        self.session.cmd_output(
            "sed -i '/AutoUpdate.Enabled/d' /etc/waagent.conf")
        self.assertEqual(
            "",
            self.session.cmd_output(
                "grep 'AutoUpdate.Enabled' /etc/waagent.conf"),
            "Fail to remove AutoUpdate.Enabled line")
        self.session.cmd_output("service waagent restart")
        time.sleep(10)
        # Check feature
        output = self._wait_for_exthandlers()
        self.assertIn(
            "/usr/sbin/waagent -run-exthandlers",
            output,
            #   self.session.cmd_output("ps aux|grep [-]run-exthandlers"),
            "The AutoUpdate.enabled is not False by default.")

    def test_resource_disk_mount_options(self):
        """
        :avocado: tags=tier2
        ResourceDisk.MountOptions
        """
        self.log.info("WALA conf: Resource disk mount options")
        # 1. ResourceDisk.MountOptions=sync,noatime
        self._modify_value("ResourceDisk.MountOptions", "sync,noatime")
        self.session.close()
        self.vm.reboot()
        self.session.connect()
        # if LooseVersion(self.project) < LooseVersion("7.0"):
        #     self.assertIn("(rw,sync,noatime)",
        #                   self.session.cmd_output("mount|grep /dev/sdb"),
        #                   "Fail to set mount options")
        # else:
        #     self.assertIn("(rw,noatime,sync,seclabel,data=ordered)",
        #                   self.session.cmd_output("mount|grep /dev/sdb"),
        #                   "Fail to set mount options")
        mount_output = self.session.cmd_output(
            "mount|grep {}".format(self._get_temporary_disk()))
        self.assertTrue(("sync" in mount_output)
                        and ("noatime" in mount_output),
                        "Fail to set mount options to sync,noatime")
        # 2. ResourceDisk.MountOptions=None
        self._modify_value("ResourceDisk.MountOptions", "None")
        self.session.close()
        self.vm.reboot()
        self.session.connect()
        # if LooseVersion(self.project) < LooseVersion("7.0"):
        #     self.assertIn("(rw)",
        #                   self.session.cmd_output("mount|grep /dev/sdb"),
        #                   "Fail to set mount options")
        # else:
        #     self.assertIn("(rw,relatime,seclabel,data=ordered)",
        #                   self.session.cmd_output("mount|grep /dev/sdb"),
        #                   "Fail to set mount options")
        mount_output = self.session.cmd_output(
            "mount|grep {}".format(self._get_temporary_disk()))
        self.assertTrue(("sync" not in mount_output)
                        and ("noatime" not in mount_output),
                        "Fail to set mount options to None")

    def test_extension_log_dir(self):
        """
        :avocado: tags=tier2
        [WALA conf] Customize the extension log directory
        1. Extension.LogDir=/var/log/azurenew, then restart waagent service, \
           check new log folder
        2. Reset remote access. Check new log folder
        """
        self.session.cmd_output("sudo su -")
        new_dir = "/var/log/azurenew"
        self.log.info("1. Extension.LogDir={0}, then restart waagent service, \
check new log folder".format(new_dir))
        self._modify_value("Extension.LogDir", new_dir)
        self.session.cmd_output("service waagent restart")
        time.sleep(3)
        self.assertEqual(
            self.session.cmd_status_output("ls {}".format(new_dir))[0], 0,
            "{0} is not created.".format(new_dir))
        self.log.info("2. Run command. Check new log folder.")
        self.vm.run_command(scripts='echo "hello"')
        max_retry = 10
        for retry in range(0, max_retry):
            if self.session.cmd_status_output(
                    "ls {0}/Microsoft.CPlat.Core.RunCommandLinux".format(
                        new_dir))[0] == 0:
                break
            time.sleep(30)
            self.log.info(
                "Wait for Extension installed. Retry ({0}/{1})".format(
                    retry + 1, max_retry))
        else:
            self.fail("Extension log is not written in {0}.".format(new_dir))

    def test_customize_ssh_key_conf_path(self):
        """
        :avocado: tags=tier2
        WALA-TC: [WALA conf] Customize the path of ssh key and ssh 
                 configuration file
        1. Modify "/etc/waagent.conf":
             OS.SshDir=/home/sshnew
             Provisioning.SshHostKeyPairType=dsa
           Copy /etc/ssh folder to /home/sshnew and remove sshnew/ssh_host_*
           files
        2. Deprovision this VM and use this as a template to create a new VM
        3. After the VM finishing provisioning,login and Check if dsa ssh keys
           are generated in "sshnew"
        4. Deprovision this VM and check whether ssh key is removed under
           "sshnew"
        """
        self.session.cmd_output("sudo su -")
        self.log.info("WALA-TC: [WALA conf] Customize the path of ssh key \
and ssh configuration file")
        self.sshnew = "/home/sshnew"
        self.log.info("1. Modify /etc/waagent.conf, Copy /etc/ssh folder to " +
                      self.sshnew)
        self._modify_value("OS.SshDir", self.sshnew)
        self._modify_value("Provisioning.SshHostKeyPairType", "dsa")
        self.session.cmd_output("cp -a /etc/ssh " + self.sshnew)
        self.session.cmd_output("rm -f {0}/ssh_host_*".format(self.sshnew))
        self.log.info("2. Deprovision this VM and use this as a template \
to create a new VM")
        utils_azure.deprovision(self)
        self.vm_1, session_1 = utils_azure.recreate_vm(self, "ssh-path")
        session_1.cmd_output("sudo su -")
        self.log.info("3. After provisioning,login and check if dsa ssh keys \
are generated in " + self.sshnew)
        for key in [
                self.sshnew + "/ssh_host_dsa_key",
                self.sshnew + "/ssh_host_dsa_key.pub"
        ]:
            for retry in range(1, 11):
                if file_exists(key, session_1):
                    break
                self.log.info("No file {}. Retry: {}/10".format(key, retry))
                time.sleep(10)
            else:
                self.fail("{} is not generated".format(key))
        self.log.info("4. Deprovision this VM and check whether \
ssh key is removed under " + self.sshnew)
        session_1.cmd_output("waagent -deprovision -force")
        self.assertFalse(
            file_exists("{}/ssh_host_dsa*".format(self.sshnew), session_1),
            "Fail to remove ssh_host_dsa keys from new path")

    def test_customize_ssh_client_alive_interval(self):
        """
        :avocado: tags=tier2
        WALA-TC: [WALA conf] Customize ssh SshClientAliveInterval value
        1. OS.SshClientAliveInterval=0
        2. Deprovision this VM. Create a new VM base on this os disk
        3. grep ClientAliveInterval /etc/ssh/sshd_config
        """
        self.session.cmd_output("sudo su -")
        self.log.info(
            "WALA-TC: [WALA conf] Customize ssh SshClientAliveInterval value")
        new_interval = 0
        self._modify_value("OS.SshClientAliveInterval", new_interval)
        utils_azure.deprovision(self)
        self.vm_1, session_1 = utils_azure.recreate_vm(self, "ssh-interval")
        session_1.cmd_output("sudo su -")
        self.assertEqual(
            session_1.cmd_status_output(
                "grep '^ClientAliveInterval {}' /etc/ssh/sshd_config".format(
                    new_interval))[0], 0,
            "Fail to change ClientAliveInterval to {}".format(new_interval))

    def test_decode_execute_custom_data(self):
        """
        :avocado: tags=tier2
        execute custom data
        """
        self.log.info("execute custom data")
        # Prepare custom script
        script = """\
#!/bin/bash
echo 'teststring' >> /tmp/test.log\
"""
        with open("/tmp/customdata.sh", 'w') as f:
            f.write(script)

        def _decode_execute_customdata(decode,
                                       execute,
                                       invoke_customdata=True):
            self.log.info("### Testcase: decode={}, execute={}".format(
                decode, execute))
            # Provisioning.DecodeCustomData
            self._modify_value("Provisioning.DecodeCustomData", decode)
            # Provisioning.ExecuteCustomData
            self._modify_value("Provisioning.ExecuteCustomData", execute)
            # Capture VM and create new
            utils_azure.deprovision(self)
            tag = "custom-{}{}".format(decode, execute)
            custom_data = None
            if invoke_customdata:
                custom_data = "/tmp/customdata.sh"
            vm, session_1 = utils_azure.recreate_vm(self, tag, custom_data=custom_data)
            setattr(self, 'vm_' + decode + execute, vm)
            if execute == "y":
                self.assertEqual(session_1.cmd_output("cat /tmp/test.log"),
                                 "teststring",
                                 "The custom script is not executed")
                self.assertEqual(
                    session_1.cmd_output(
                        "sudo grep '' /var/lib/waagent/CustomData"), script,
                    "The custom data is not decoded")
            else:
                self.assertFalse(file_exists('/tmp/test.log', session_1),
                                 "The custom script should not be executed")
                if decode == "y":
                    self.assertEqual(
                        session_1.cmd_output(
                            "sudo grep '' /var/lib/waagent/CustomData"),
                        script, "The custom data is not decoded")
                else:
                    self.assertNotIn(
                        "teststring",
                        session_1.cmd_output(
                            "sudo grep '' /var/lib/waagent/CustomData"),
                        "The custom data should not be decoded")

        _decode_execute_customdata(decode="n", execute="n")
        _decode_execute_customdata(decode="y", execute="n")
        _decode_execute_customdata(decode="y", execute="y")
        _decode_execute_customdata(decode="n", execute="y")

    def test_ssh_host_key_pair_type(self):
        """
        :avocado: tags=tier2
        Ssh host key pair type
        """
        self.log.info("ssh host key pair type")

        def _key_pair_check(key_type):
            self.log.info("Key type: {0}".format(key_type))
            # Provisioning.SshHostKeyPairType
            self._verify_value("Provisioning.RegenerateSshHostKeyPair", "y")
            self._modify_value("Provisioning.SshHostKeyPairType", key_type)
            # Generate all key files by sshd
            utils_azure.deprovision(self)
            self.session.cmd_output("sudo service sshd restart")
            if key_type == "auto":
                old_md5_list = self.session.cmd_output(
                    "md5sum /etc/ssh/ssh_host_{rsa,dsa,ecdsa,ed25519}_key"
                ).split("\n")
            else:
                old_md5 = self.session.cmd_output(
                    "md5sum /etc/ssh/ssh_host_{0}_key".format(key_type))
            # Capture VM and create new
            vm, session_1 = utils_azure.recreate_vm(self, key_type)
            setattr(self, 'vm_' + key_type, vm)
            # Check if regenerate the ssh host key pair
            if key_type == "auto":
                new_md5_list = session_1.cmd_output(
                    "md5sum /etc/ssh/ssh_host_{rsa,dsa,ecdsa,ed25519}_key"
                ).split("\n")
                for new_md5 in new_md5_list:
                    self.assertNotIn(
                        new_md5, old_md5_list,
                        "The key is not regenerated: {0}".format(new_md5))
            else:
                new_md5 = session_1.cmd_output(
                    "md5sum /etc/ssh/ssh_host_{0}_key".format(key_type))
                self.assertNotEqual(
                    old_md5, new_md5,
                    "The {0} key pair is not regenerated.".format(key_type))

        _key_pair_check("dsa")
        if LooseVersion(self.project) >= LooseVersion("7.0"):
            _key_pair_check("auto")
        comment = '# The "auto" option is supported on OpenSSH 5.9 \
(2011) and later.'

        self.assertIn(
            comment, self.session.cmd_output("grep auto /etc/waagent.conf"),
            'The {} line is not in /etc/waagent.conf'.format(comment))

    def test_enable_disable_extension(self):
        """
        :avocado: tags=tier2
        RHEL-151927 WALA-TC: [WALA conf] Enable/disable extension
        1. Extensions.Enabled=n, reset remote access,
           should not install extension
        2. Extensions.Enabled=y, restart waagent service,
           should install extension
        """
        self.log.info(
            "RHEL-151927 WALA-TC: [WALA conf] Enable/disable extension")
        self.session.cmd_output("sudo su -")
        self.log.info("1. Extensions.Enabled=n")
        self._modify_value("Extensions.Enabled", 'n')
        self.session.cmd_output("service waagent restart")
        self.session.cmd_output("rm -f /etc/ssh/sshd_config_*")
        try:
            self.vm.user_reset_ssh(timeout=60)
        except:
            self.log.info("Timeout. Kill process.")
        self.assertFalse(
            file_exists("/etc/ssh/sshd_config_*", self.session),
            "Should not install extension when Extensions.Enabled=n")
        self.log.info("2. Extensions.Enabled=y")
        self._modify_value("Extensions.Enabled", 'y')
        self.session.cmd_output("service waagent restart")
        time.sleep(10)
        for retry in range(1, 11):
            if file_exists("/etc/ssh/sshd_config_*", self.session):
                break
            self.log.info(
                "Waiting for extension installed. Retry: {}/10".format(retry))
            time.sleep(10)
        else:
            self.fail("Fail to run extension when Extension.Enabled=y")

    def test_enable_fips(self):
        """
        :avocado: tags=tier2
        Enable FIPS
        1.1 Ensure these packages are installed:
        fipscheck
        fipscheck-lib
        dracut-fips
        Disable prelink if exists
        1.2 Add fips=1 in kernel parameters
        RHEL-7:
        # grubby --update-kernel=$(grubby --default-kernel) --args=fips=1
        # uuid=$(findmnt -no uuid /boot)
        [[ -n $uuid ]] && grubby --update-kernel=$(grubby --default-kernel)
            --args=boot=UUID=${uuid}
        RHEL-6:
        Add fips=1 in /etc/grub/grub.conf
        1.3 Rebuild initramfs:
        # mv /boot/initramfs-3.10.0-675.el7.x86_64.img{,.bak}
        # dracut
        1.4 Reboot
        1.5 Check /proc/sys/crypto/fips_enabled
        * Detail steps are here: https://access.redhat.com/solutions/137833
        2. Enable FIPS in waagent.conf. Restart waagent service
        3. Run "reset remote access" to install an Extension to the VM.
        Wait for the extension installed, check if there's error log in
        /var/log/waagent.log
        """
        self.session.cmd_output("sudo su -")
        self.log.info("Enable FIPS")
        self.log.info("1. Environment prepare. Enable FIPS in RHEL")
        # 1.1 Check fips packages, disable prelink
        if file_exists("ls /root/dracut-fips-*.rpm", self.session):
            self.session.cmd_output("rpm -ivh /root/dracut-fips-*.rpm")
        else:
            self.session.cmd_output("yum -y install dracut-fips")
        time.sleep(10)
        if not file_exists("/etc/system-fips", self.session):
            self.fail("Fail to install dracut-fips")
        for pkg in ["filscheck", "filscheck-lib"]:
            self.assertEqual(
                self.session.cmd_status_output("rpm -q {}".format(pkg))[0], 0,
                "No {} package.".format(pkg))
        if "is not installed" not in self.session.cmd_output("rpm -q \
prelink && sed -i '/^PRELINKING/s,yes,no,' /etc/sysconfig/prelink"):
            self.session.cmd_output("rpm -q prelink && prelink -uav")
        # 1.2 Add fips=1 in kernel parameters
        uuid = self.session.cmd_output("findmnt -no uuid /boot")
        if LooseVersion(self.project) < LooseVersion("7.0"):
            self.session.cmd_output("sed -i '/^\tkernel/s/$/ fips=1 \
boot=UUID={0}/g' /etc/grub.conf".format(uuid))
        else:
            self.session.cmd_output("sed -i '/^GRUB_CMDLINE_LINUX=/s/\"$/ \
fips=1 boot=UUID={0}\"/g' /etc/default/grub".format(uuid))
            self.session.cmd_output("grub2-mkconfig -o /boot/grub/grub.cfg")
            self.session.cmd_output(
                "grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg")
            # self.session.cmd_output("grubby --update-kernel=$(grubby \
            # --default-kernel) --args=fips=1")
            # self.session.cmd_output("[[ -n {0} ]] && grubby \
            # --update-kernel=$(grubby --default-kernel) \
            # --args=boot=UUID={0}".format(uuid))
        # 1.3 Rebuild initramfs
        self.session.cmd_output("dracut -f -v")
        # Set EnableFIPS in waagent.conf
        self._modify_value("OS.EnableFIPS", "y")
        self.session.cmd_output("rm -f /var/log/waagent.log")
        # 1.4 Reboot
        self.session.close()
        self.vm.reboot()
        self.session.connect()
        self.session.cmd_output("sudo su -")
        # 1.5 Check /proc/sys/crypto/fips_enabled
        self.assertEqual(
            '1', self.session.cmd_output("cat /proc/sys/crypto/fips_enabled"),
            "Fail to enable FIPS in RHEL")
        self.log.info(
            "3. Run 'reset remote access' to install an Extension to the VM."
            "Wait for the extension installed, check if there's error log in \
/var/log/waagent.log")
        self.session.cmd_output("rm -f /etc/ssh/sshd_config_*")
        self.assertEqual(0, self.vm.user_reset_ssh(),
                         "Fail to reset remote access")
        time.sleep(60)
        self.assertTrue(file_exists("/etc/ssh/sshd_config_*", self.session),
                        "Reset remote access failed")
        with open("{}/data/azure/ignore_waagent_messages".format(BASEPATH),
                  'r') as f:
            ignore_message_list = f.read().split('\n')
        cmd = "sh -c \"grep -iE '(error|fail)' /var/log/waagent.log\""
        if ignore_message_list:
            cmd += "|grep -vE '({})'".format('|'.join(ignore_message_list))
        error_log = self.session.cmd_output(cmd)
        self.assertEqual(
            error_log, "",
            "There's error log in the waagent.log: \n%s" % error_log)

    def test_provision_agent(self):
        """
        :avocado: tags=tier2
        RHEL-187583	WALA-TC: [WALA conf] Provisioning.Agent
        1. Verify default configuration in waagent.conf is auto
        2. Verify default value is auto
        3. Provisioning.Agent=waagent and provision with wala
        4. Provisioning.Agent=disabled
        5. Provisioning.Agent=cloud-init and provision with cloud-init
        6. Provisioning.Agent=auto and provision with cloud-init
        """
        self.log.info("RHEL-187583	WALA-TC: [WALA conf] Provisioning.Agent")
        self.session.close()
        self.vm.vm_username = 'root'
        self.session.connect()
        script_name = "deprovision_package.sh"
        self.session.copy_files_to(local_path="{}/scripts/{}".format(BASEPATH, script_name),
                                   remote_path="/tmp/{}".format(script_name))
        # 1. Verify default configuration in waagent.conf is auto
        self._verify_value("Provisioning.Agent", "auto")
        # 2. Verify default value is auto
        self.session.cmd_output("sed -i '/Provisioning.Agent/d' /etc/waagent.conf")
        self.assertEqual(self.session.cmd_output("waagent -show-configurations|grep 'Provisioning.Agent'"),
                         "Provisioning.Agent = auto",
                         "Default value of Provisioning.Agent is not auto")
        # 3. Provisioning.Agent=waagent and provision with wala
        self._modify_value("Provisioning.Agent", "waagent")
        utils_azure.deprovision(self)
        self.vm_1, session_1 = utils_azure.recreate_vm(self, "pa-wa")
        self.assertEqual(session_1.cmd_output("hostname"), self.vm.vm_name + "-pa-wa",
            "Using waagent to provision failed with Provisioning.Agent=waagent")
        # 4. Provisioning.Agent=disabled
        self._modify_value("Provisioning.Agent", "disabled")
        self.vm_2, session_2 = utils_azure.recreate_vm(self, "pa-dis", connect=False)
        self.vm_2.vm_username = "root"
        session_2.connect()
        self.assertEqual(session_2.cmd_output("hostname"), self.vm.vm_name,
            "Provisioning is not skipped with Provisioning.Agent=disabled")
        # 5. Provisioning.Agent=cloud-init and provision with cloud-init
        if self.session.cmd_status_output("rpm -q cloud-init")[0] != 0:
            self.log.warn("cloud-init is not pre-installed. Skip the following 2 steps.")
        else:
            self._modify_value("Provisioning.Agent", "cloud-init")
            self.assertEqual(self.session.cmd_status_output("/tmp/{} all cloudinit_wala".format(script_name))[0], 0,
                             "Fail to deprovision VM with cloudinit_wala")
            self.vm_3, session_3 = utils_azure.recreate_vm(self, "pa-ci")
            self.assertEqual(session_3.cmd_output("hostname"), self.vm.vm_name + "-pa-ci",
                "Using cloud-init to provision failed with Provisioning.Agent=cloud-init")
            self.assertEqual(session_3.cmd_status_output("grep 'Using cloud-init for provisioning' /var/log/waagent.log")[0], 0,
                "No such log in waagent.log: 'Using cloud-init for provisioning'")
            # 6. Provisioning.Agent=auto and provision with cloud-init
            self._modify_value("Provisioning.Agent", "cloud-init")
            self.vm_4, session_4 = utils_azure.recreate_vm(self, "pa-aci")
            self.assertEqual(session_4.cmd_output("hostname"), self.vm.vm_name + "-pa-aci",
                "Using cloud-init to provision failed with Provisioning.Agent=auto")
            self.assertEqual(session_4.cmd_status_output("grep 'Using cloud-init for provisioning' /var/log/waagent.log")[0], 0,
                "No such log in waagent.log: 'Using cloud-init for provisioning'")


    # def test_enable_cgroups_limits(self):
    #     """
    #     :avocado: tags=tier2
    #     RHEL-151938	WALA-TC: [WALA conf] Enable CGroups Limits and exclude extensions
    #     1. Set wagaent.conf then restart waagent service
    #     CGroups.EnforceLimits=y
    #     CGroups.Excluded=vmaccess
    #     2. Check if set WALinuxAgent cpu and memory limit in CGroup
    #     3. Run reset remote access to install VMAccessForLinux extension
    #     4. Check if not set extension cpu and memory limit in CGroup
    #     5. Modify "/etc/waagent.conf",
    #     CGroups.Excluded=
    #     6. Check if set extension cpu and memory limit in CGroup
    #     7. Modify "/etc/waagent.conf", then reboot
    #     CGroups.EnforceLimits=n
    #     8. Check if not set WALinuxAgent and extension cpu and memory limit in CGroup
    #     """
    #     self.session.cmd_output("sudo su -")
    #     self._modify_value("CGroups.EnforceLimits", "y")
    #     self._modify_value("CGroups.Excluded", "vmaccess")
    #     self.session.cmd_output("service waagent restart")
    #     self.session.cmd_output("cat /sys/fs/cgroup/cpu/WALinuxAgent/WALinuxAgent/cpu.cfs_quota_us")

    def tearDown(self):
        if not self.session.connect(timeout=20):
            self.vm.delete()
            return
        # recover_list = ["test_delete_root_passwd",
        #                 "test_monitor_hostname",
        #                 "test_reset_system_account",
        #                 "test_regenerate_ssh_host_key",
        #                 "test_customize_ssh_key_conf_path",
        #                "test_customize_ssh_client_alive_interval",
        #                "test_ssh_host_key_pair_type"]
        reboot_list = [
            "test_resource_disk_swap_check",
            "test_resource_disk_swap_unusual_check",
            "test_resource_disk_mount_options"
        ]
        delete_list = [
            "test_resource_disk_gpt_partition",
            "test_customize_ssh_key_conf_path",
            "test_provision_agent"
        ]
        # Remove temporary VMs
        for i in [x for x in self.__dict__ if 'vm_' in x]:
            vm = eval("self.{}".format(i))
            vm.delete(wait=False)
        if self.case_short_name in delete_list:
            self.vm.delete(wait=False)
            return
        # Recover VM
        if self.case_short_name == "test_reset_system_account":
            self.session.cmd_output("sudo userdel -rf {}".format(
                self.username))
        if self.case_short_name == "test_monitor_hostname":
            self.session.cmd_output("sudo hostnamectl set-hostname {}".format(
                self.vm.vm_name))
            time.sleep(5)
        if self.case_short_name == "test_attach_disk_check_device_timeout":
            self.vm.unmanaged_disk_detach(self.disk_name)
        if self.case_short_name == "test_http_proxy_system_environment":
            self.session.cmd_output("sudo service waagent stop")
            self.session.cmd_output("sudo sed -i 's/Environment/d' \
/usr/lib/systemd/system/waagent.service")
            self.session.cmd_output("sudo systemctl daemon-reload")
            self.session.cmd_output("sudo service waagent start")
        if self.case_short_name in [
                "test_extension_log_dir",
                "test_enable_disable_extension"]:
            self.vm.extension_delete(name="enablevmaccess")
            self.session.cmd_output(
                "sudo rm -rf /var/log/azure* /etc/ssh/sshd_config_*")
        if self.case_short_name == "test_customize_ssh_key_conf_path":
            self.session.cmd_output("sudo rm -rf {}".format(self.sshnew))
        if ("session" in self.__dict__) and self.session.connect():
            self.session.cmd_output(
                "sudo /usr/bin/cp /etc/waagent.conf-bak /etc/waagent.conf")
            self.session.cmd_output("sudo service waagent restart")
            self.session.cmd_output("sudo tail -1 /etc/waagent.conf")
            if file_exists("/tmp/deprovisioned", self.session):
                self._recovery()
            if self.case_short_name in reboot_list:
                self.vm.reboot()
        else:
            self.vm.delete(wait=True)


'''
    def test_allow_fallback_to_http(self):
        """
        WALA-TC: [WALA conf] Allow fallback to http (RHEL6 only)
        1. Modify /etc/waagent.conf:
        OS.AllowHTTP=y
        HttpProxy.Host=172.20.0.254
        HttpProxy.Port=3128
        Logs.Verbose=y
        Restart waagent service
        Check waagent.log
        2. OS.AllowHTTP=n, then repeat step 1
        """
        self.log.info("1. OS.AllowHTTP=y")
        self.assertTrue(self.vm.modify_value("OS.AllowHTTP", "y"))
        self.assertTrue(self.vm.modify_value("HttpProxy.Host",
            self.proxy_params["proxy_ip"], self.conf_file))
        self.assertTrue(self.vm.modify_value("HttpProxy.Port",
            self.proxy_params["proxy_port"], self.conf_file))
        self.assertTrue(self.vm.modify_value("Logs.Verbose", "y"))
        self.session.cmd_output("rm -f /var/log/waagent.log")
        self.vm.waagent_service_restart()
        time.sleep(20)
        self.assertIn("Python does not support HTTPS tunnelling",
                      self.session.cmd_output("cat /var/log/waagent.log"),
                      "OS.AllowHTTP=y doesn't work")
        self.log.info("2. OS.AllowHTTP=n")
        self.vm.waagent_service_stop()
        self.session.cmd_output("rm -f /var/log/waagent.log")
        self.assertTrue(self.vm.modify_value("OS.AllowHTTP", "y"))
        self.vm.waagent_service_start()
        time.sleep(20)
        self.assertIn("HTTPS tunnelling is unavailable and required",
                      self.session.cmd_output("cat /var/log/waagent.log"),
                      "OS.AllowHTTP=n doesn't work")
'''

if __name__ == "__main__":
    main()
