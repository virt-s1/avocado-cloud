import time
import re
import os
from avocado import Test
from avocado import main
from avocado_cloud.app import Setup
from avocado_cloud.app.azure import AzureAccount, AzureImage
from distutils.version import LooseVersion
from avocado_cloud.utils import utils_azure

BASEPATH = os.path.abspath(__file__ + "/../../../")

class GeneralTest(Test):
    """
    :avocado: tags=wala,general
    """

    def setUp(self):
        account = AzureAccount(self.params)
        account.login()
        self.project = self.params.get("rhel_ver", "*/VM/*")
        self.case_short_name = re.findall(r"Test.(.*)", self.name.name)[0]
        if self.case_short_name == "test_provision_gen2_vm":
            if LooseVersion(self.project) < LooseVersion('7.8'):
                self.cancel(
                    "Skip case because RHEL-{} ondemand image doesn't support gen2".format(self.project))
            cloud = Setup(self.params, self.name, size="DS1_v2")
            cloud.vm.vm_name += "-gen2"
            self.image = AzureImage(self.params, generation="V2")
            if not self.image.exists():
                self.image.create()
            cloud.vm.image = self.image.name
            cloud.vm.use_unmanaged_disk = False
        else:
            cloud = Setup(self.params, self.name)
        self.vm = cloud.vm
        pre_delete = False
        if self.case_short_name == "test_provision_with_2_keys":
            pre_delete = True
            self.vm.vm_name += "-2keys"
            key1 = "{}/.ssh/id_rsa.pub".format(os.path.expanduser('~'))
            key2 = "/tmp/newkey.pub"
            if not os.path.exists(key2):
                utils_azure.command("ssh-keygen -f {} -q -N ''".format(key2.split('.')[0]))
            self.assertTrue(os.path.exists(key1),
                            "Key {} doesn't exist".format(key1))
            self.assertTrue(os.path.exists(key2),
                            "Key {} doesn't exist".format(key2))
            self.vm.ssh_key_value = "{} {}".format(key1, key2)
            with open(key1) as f:
                self.key1_value = f.read().rsplit(' ', 1)[0]
            with open(key2) as f:
                self.key2_value = f.read().rsplit(' ', 1)[0]
        self.session = cloud.init_vm(pre_delete=pre_delete)
        self.username = self.vm.vm_username
        self.package = self.params.get("packages", "*/Other/*")
        if not self.package:
            self.package = self.session.cmd_output("rpm -qa|grep WALinuxAgent|sed 's/$/.rpm/g'|paste -sd ',' -")
        if self.case_short_name == "test_install_uninstall_package":
            if self.session.cmd_status_output("ls /tmp/{}".format(self.package.split(',')[0]))[0] != 0:
                self.log.info("Package doesn't exist. Download from brew.")
                nvr = self.package.split(',')[0].replace('-udev', '')
                utils_azure.command("brew download-build {}".format(nvr)) 
                self.session.copy_files_to(
                    local_path=' '.join(self.package.split(',')),
                    remote_path="/tmp/"
                )
        if self.case_short_name.startswith("test_host_plugin"):
            self.session.cmd_output(
                "sudo /usr/bin/cp /etc/waagent.conf{,-bak}")
        if self.case_short_name == "test_upgrade_downgrade_package":
            new_nvr = self.package.split(',')[0].replace('-udev', '').replace('.noarch.rpm', '')
            if self.session.cmd_status_output("ls /tmp/{}".format(self.package.split(',')[0]))[0] != 0:
                self.log.info("No new package in guest VM. Trying to download it.")
                utils_azure.command("mkdir -p newpkg;cd newpkg;brew download-build {};rm -f oldpkg/*.src.*".format(new_nvr))
                self.session.copy_files_to(
                    local_path="{}".format('./newpkg/*'),
                    remote_path="/tmp/"
                )
            self.assertEqual(0, self.session.cmd_status_output("ls /tmp/{}".format(self.package.split(',')[0]))[0],
                                "No new package in guest VM")
            # Get the previous version to get the old package
            # rhel7 project has 2 units(7.9), rhel8+ has 3 units(8.7.0). Need to handle both formats
            xyz_list = self.project.split('.')
            y_version = int(xyz_list[1])
            def get_old_pkg(y):
                if y == '0':
                    self.cancel('This is the first y-stream. No old package. Skip.')
                xyz_list[1] = str(int(y)-1)
                old_version = '.'.join(xyz_list)
                if str(self.project).startswith('7'):
                    old_tag = "extras-rhel-{}-candidate".format(old_version)
                else:
                    old_tag = "rhel-{}-candidate".format(old_version)
                # python2 prints warning message. So write to file as a workaround
                utils_azure.command("brew latest-build {} WALinuxAgent --quiet > oldpkgnvr".format(old_tag))
                old_nvr = utils_azure.command("cat oldpkgnvr|awk '{print $1}'").stdout.strip('\n')
                if old_nvr == new_nvr:
                    self.log.info("Old package equal to new package. Find the previous one...")
                    return get_old_pkg(int(y)-1)
                else:
                    return old_nvr
            # There's no previous version for 10.0. So hardcode the old version
            if str(self.project) == '10.0':
                old_nvr = 'WALinuxAgent-2.9.1.1-3.el10'
            else:
                old_nvr = get_old_pkg(y_version)
            if not os.path.exists("./oldpkg/{}.noarch.rpm".format(old_nvr)):
                utils_azure.command('mkdir oldpkg;cd oldpkg;brew download-build {}'.format(old_nvr))
                utils_azure.command('rm -f oldpkg/*.src.*')
            self.session.copy_files_to(
                local_path="{}".format('./oldpkg'),
                remote_path="/tmp/"
            )
            self.assertEqual(0, self.session.cmd_status_output("ls /tmp/oldpkg/{}.noarch.rpm".format(old_nvr))[0],
                                "No old pakcage in guest VM")
        if self.case_short_name == "test_change_python_version":
            if LooseVersion(self.project) >= LooseVersion('9.0'):
                self.cancel(
                    "Skip case because RHEL-{} doesn't have another python version".format(self.project))


    @property
    def wala_version(self):
        return LooseVersion(self.session.cmd_output("rpm -q WALinuxAgent").split("-")[1])

    def test_check_hostname(self):
        """
        :avocado: tags=tier1
        Check if the hostname is what we set
        """
        self.log.info("Check the hostname")
        self.assertEqual(self.session.cmd_output("hostname"), self.vm.vm_name,
                         "Hostname is not the one we set")

    def test_check_mountpoint(self):
        """
        :avocado: tags=tier1
        Check if the temporary disk is mounted
        Verify the /mnt/resource is writable
        """
        self.log.info("1. Verify /mnt/resource is mounted")
        self.assertNotEqual(
            self.session.cmd_output("mount|grep /mnt/resource"), '',
            "Resource Disk is not mounted after provisioning")
        self.log.info("2. Verify /mnt/resource is writable")
        self.session.cmd_output("sudo su -")
        self.session.cmd_output("echo DONE > /mnt/resource/try.txt")
        self.assertEqual("DONE", self.session.cmd_output("cat /mnt/resource/try.txt"),
            "Failed to write data into the /mnt/resource")
        self.assertEqual(0, self.session.cmd_status_output("rm -f /mnt/resource/try.txt")[0],
            "Failed to delete file from /mnt/resource")

    def test_check_DATALOSS_WARNING_README(self):
        """
        :avocado: tags=tier3
        RHEL-178586	WALA-TC: [General] Verify DATALOSS_WARNING_README.txt in /mnt/resource
        """
        self.log.info("RHEL-178586	WALA-TC: [General] Verify DATALOSS_WARNING_README.txt in /mnt/resource")
        self.assertEqual(
            "WARNING: THIS IS A TEMPORARY DISK.",
            self.session.cmd_output("head -1 /mnt/resource/DATALOSS_WARNING_README.txt"),
            "Cannot read DATALOSS_WARNING_README.txt in /mnt/resource"
        )

    def test_verify_no_waagent_extn_logrotate(self):
        """
        :avocado: tags=tier2
        RHEL-288307 - WALA-TC: [General] Verify no waagent-extn.logrotate	
        """
        self.log.info("RHEL-178586	WALA-TC: [General] Verify DATALOSS_WARNING_README.txt in /mnt/resource")
        self.assertFalse(
            utils_azure.file_exists("/etc/logrotate.d/waagent-extn.logrotate", self.session),
            "/etc/logrotate.d/waagent-extn.logrotate should not exist!")

    def test_check_waagent_service(self):
        """
        :avocado: tags=tier1
        Verify waagent service commands
        """
        self.log.info("Check the waagent service")
        # systemctl stop waagent
        self.assertEqual(
            self.session.cmd_status_output("sudo systemctl stop waagent")[0], 0,
            "Fail to stop waagent: command fail")
        # systemctl start waagent
        self.assertEqual(
            self.session.cmd_status_output("sudo systemctl start waagent")[0], 0,
            "Fail to start waagent: command fail")
        time.sleep(5)
        output = self.session.cmd_output(
            "sudo ps aux|grep -E 'waagent|exthandlers'")
        self.assertIn("waagent -daemon", output,
                      "Fail to start waagent: no -daemon process")
        self.assertIn("-run-exthandlers", output,
                      "Fail to start waagent: no -run-exthandlers process")
        # systemctl restart waagent
        old_pid = self.session.cmd_output(
            "sudo ps aux|grep [w]aagent\ -daemon|awk '{print $2}'")
        self.assertEqual(
            self.session.cmd_status_output("sudo systemctl restart waagent")[0],
            0, "Fail to restart waagent: command fail")
        self.assertIn(
            "waagent -daemon",
            self.session.cmd_output("sudo ps aux|grep -E 'waagent|WAL'"),
            "Fail to restart waagent: cannot start waagent service")
        new_pid = self.session.cmd_output(
            "sudo ps aux|grep [w]aagent|awk '{print $2}'")
        self.assertNotEqual(
            old_pid, new_pid,
            "Fail to restart waagent: service is not restarted")
        # 3. kill waagent -daemon then start
        self.session.cmd_output(
            "sudo ps aux|grep [w]aagent|awk '{print $2}'|xargs sudo kill -9")
        if LooseVersion(self.project) < LooseVersion("7.0"):
            self.assertEqual(
                "waagent dead but pid file exists",
                self.session.cmd_output("sudo service waagent status"),
                "waagent service status is wrong after killing process")
        else:
            self.assertIn(
                "code=killed, signal=KILL",
                self.session.cmd_output("sudo service waagent status"),
                "waagent service status is wrong after killing process")
        if LooseVersion(self.project) < LooseVersion("7.0"):
            start_cmd = "sudo systemctl start waagent"
            status_cmd = "sudo service waagent status"
        else:
            start_cmd = "sudo systemctl start waagent"
            status_cmd = "sudo systemctl status waagent"
        self.assertEqual(
            self.session.cmd_status_output(start_cmd)[0], 0,
            "Fail to start waagent after killing process: command fail")
        self.assertIn("running", self.session.cmd_output(status_cmd),
                      "waagent service status is not running.")
        self.assertIn(
            "waagent -daemon",
            self.session.cmd_output("sudo ps aux|grep [w]aagent"),
            "Fail to start waagent after killing process: result fail")

    def test_start_waagent_repeatedly(self):
        """
        :avocado: tags=tier2
        If start waagent service repeatedly, check if there's only one waagent
        process
        """
        self.log.info("Start waagent service repeatedly")
        self.session.cmd_output("sudo systemctl start waagent")
        self.session.cmd_output("sudo systemctl start waagent")
        waagent_count = self.session.cmd_output(
            "sudo ps aux|grep [w]aagent\ -daemon|wc -l")
        self.assertEqual(
            waagent_count, "1",
            "There's more than 1 waagent process. Actually: %s" %
            waagent_count)

    def test_verify_autoupdate_enabled(self):
        """
        :avocado: tags=tier1
        Verify AutoUpdate is enabled
        """
        self.log.info("Verify AutoUpdate is enabled")
        # 1. Check AutoUpdate.enabled value
        self.assertNotEqual(
            0,
            self.session.cmd_status_output(
                "sudo grep ^AutoUpdate.Enabled=n /etc/waagent.conf")[0],
            "AutoUpdate.enabled=n is default value")

    def test_logrotate(self):
        """
        :avocado: tags=tier2
        1. Verify waagent logrotate
        2. Verify waagent extension logrotate (<2.3.0.2)
        """
        self.log.info("logrotate")
        self.session.cmd_output("sudo su -")
        # 1. Verify waagent logrotate
        # Preparation
        self.session.cmd_output(
            "rm -f /tmp/waagent.log;cp /var/log/waagent.log /tmp/")
        test_str = "teststring"
        self.session.cmd_output("rm -f /var/log/waagent.log-*")
        self.session.cmd_output(
            "echo '%s' >> /var/log/waagent.log" % test_str)
        # Rotate log
        # logrotate filename is different in RHEL-8/9. Get name first.
        logrotate_file = self.session.cmd_output("ls -d /etc/logrotate.d/*|grep -E '(WALinuxAgent|waagent)'")
        self.session.cmd_output(
            "logrotate -vf {}".format(logrotate_file))
        # Check rotated log
        ret,rotate_log = self.session.cmd_status_output("ls /var/log/waagent.log-*.gz")
        self.assertEqual(ret, 0,
                         "Fail to rotate waagent log")
        self.assertNotEqual(
            self.session.cmd_status_output(
                "grep %s /var/log/waagent.log" % test_str)[0], 0,
            "The waagent.log is not cleared")
        self.session.cmd_output("gunzip %s" % rotate_log)
        self.assertEqual(
            test_str,
            self.session.cmd_output("grep %s %s" %
                                    (test_str, rotate_log[:-3])),
            "The rotated log doesn't contain the old logs")
        # 2. Verify waagent extension logrotate(<2.2.54)
        if self.wala_version < LooseVersion('2.2.54'):
            # Preparation
            extension_dir = "/var/log/azure/test"
            self.session.cmd_output(
                "rm -rf {0};mkdir {0}".format(extension_dir))
            self.session.cmd_output(
                "echo '{}' >> {}/test.log".format(test_str, extension_dir))
            # Rotate log
            self.session.cmd_output(
                "logrotate -vf /etc/logrotate.d/waagent-extn.logrotate")
            # Check rotated log
            ret,rotate_log = self.session.cmd_status_output("ls {}/test.log-*.gz".format(extension_dir))
            self.assertEqual(ret, 0,
                            "Fail to rotate extension log")
            self.assertNotEqual(
                self.session.cmd_status_output(
                    "grep {} {}/test.log".format(test_str, extension_dir))[0], 0,
                "The {}/test.log is not cleared".format(extension_dir))
            self.session.cmd_output("gunzip %s" % rotate_log)
            self.assertEqual(
                test_str,
                self.session.cmd_output("grep %s %s" %
                                        (test_str, rotate_log[:-3])),
                "The extension rotated log doesn't contain the old logs")

    def _check_file_permission(self, filename, std_permission):
        """
        :avocado: tags=tier1
        Check file permission
        """
        self.log.info("Check {0} permission".format(filename))
        real_permission = self.session.cmd_output(
            "stat -c %a {0}".format(filename))
        self.assertEqual(
            str(real_permission), str(std_permission),
            "The {0} permission is wrong. Standard: {1}, Real: {2}".format(
                filename, std_permission, real_permission))

    def test_check_shadow_permission(self):
        """
        :avocado: tags=tier1
        Check /etc/shadow permission
        """
        self._check_file_permission("/etc/shadow", 0)

    def test_check_sshdconfig_permission(self):
        """
        :avocado: tags=tier1
        Check /etc/ssh/sshd_config permission
        """
        self._check_file_permission("/etc/ssh/sshd_config", 600)

    def test_check_selinux_status(self):
        """
        :avocado: tags=tier1
        Check on-demand RHEL image selinux status. Should be Enforcing.
        """
        self.log.info("Check selinux status")
        selinux = self.session.cmd_output("getenforce")
        self.assertEqual(
            selinux, "Enforcing",
            "SELinux status is wrong. Standard: Enforcing. Real: {0}".format(
                selinux))

    def test_check_swapfile_permission(self):
        """
        :avocado: tags=tier1
        Check /etc/shadow permission
        https://bugzilla.redhat.com/show_bug.cgi?id=1688276
        """
        self._check_file_permission("/mnt/resource/swapfile", 600)

    def _check_waagent_log(self, additional_ignore_message_list=None):
        self.log.info("Check the waagent log")
        with open("{}/data/azure/ignore_waagent_messages".format(BASEPATH),
                  'r') as f:
            base_ignore_message_list = f.read().split('\n')
        # Check waagent.log
        cmd = "sudo sh -c \"grep -iE '(error|fail)' /var/log/waagent.log\""
        ignore_message_list = []
        if base_ignore_message_list:
            ignore_message_list += base_ignore_message_list
        if additional_ignore_message_list:
            ignore_message_list += additional_ignore_message_list
        if ignore_message_list:
            cmd += "|grep -vE '({})'".format('|'.join(ignore_message_list))
        error_log = self.session.cmd_output(cmd)
        self.assertEqual(
            error_log, "",
            "There's error in the /var/log/waagent.log: \n%s" % error_log)

    def test_check_waagent_log(self):
        """
        :avocado: tags=tier2
        Check if there's error logs in /var/log/waagent.log
        """
        self._check_waagent_log()

    def test_event_clean_up_when_above1000(self):
        """
        :avocado: tags=tier2
        Event clean up when > 1000
        1. Create test0001, then create 999 files in /var/lib/waagent/events.
           Restart waagent service.
        2. Check if the test0001 file is removed.
        """
        self.log.info("1. Create test0001, then create 999 files in \
/var/lib/waagent/events")
        self.session.cmd_output("sudo su -")
        event_path = "/var/lib/waagent/events"
        self.session.cmd_output("rm -f {0}/*".format(event_path))
        self.session.cmd_output("touch {0}/test0001".format(event_path))
        self.session.cmd_output(
            "touch {0}/test{{0002..1000}}".format(event_path))
        self.session.cmd_output("rm -f /var/log/waagent.log")
        self.session.cmd_output("systemctl restart waagent")
        self.log.info("2. Check if the test0001 file is removed.")
        max_retry = 10
        for retry in range(1, max_retry + 1):
            if "no" in self.session.cmd_output(
                    "if [ -f {0}/test0001 ];then echo 'yes';"
                    "else echo 'no';fi".format(event_path)):
                break
            self.log.info(
                "Waiting for removing the oldest event. Retry {0}/{1}".format(
                    retry, max_retry))
            time.sleep(10)
        else:
            self.fail("Fail to remove the oldest event file")

    def test_cleanup_runexthandlers_pid(self):
        """
        :avocado: tags=tier2
        RHEL7-98389 - WALA-TC: [General] Clean up run-exthandlers pid
        1. Ensure the waagent -run-exthandlers process is running. Check pid
           file
        2. Restart waagent service. The old pid file should be removed and a
           new *_waagent.pid file is generated
        """
        self.log.info("1. Ensure the waagent -run-exthandlers process is \
running. Check pid file")
        self.session.cmd_output("sudo su -")
        if self.session.cmd_output("ps aux|grep run-exthandlers") == "":
            self.session.cmd_output("systemctl restart waagent")
        old_pid_file = self.session.cmd_output("ls /var/run/*_waagent.pid")
        self.log.info("2. Restart waagent service. The old pid file should \
be removed and a new *_waagent.pid file is generated")
        self.session.cmd_output("systemctl restart waagent")
        time.sleep(5)
        new_pid_file = self.session.cmd_output("ls /var/run/*_waagent.pid")
        if len(new_pid_file.split('\n')) > 1 or (old_pid_file in new_pid_file):
            self.fail("Old pid files are not removed. \nOld pid file: \
{0}\nNew pid file: {1}".format(old_pid_file, new_pid_file))

    def test_not_cause_python_ftbfs(self):
        """
        :avocado: tags=tier2
        RHEL-171506 - WALA-TC: [General] Not cause python FTBFS
        BZ#1534509
        """
        self.log.info(
            "RHEL-171506 - WALA-TC: [General] Not cause python FTBFS")
        self.assertEqual(
            '',
            self.session.cmd_output("sudo rpm -ql WALinuxAgent|"
                                    "grep \"site-packages/__main__.py\""),
            "site-packages/__main__.py should not in WALA package")

    def test_provision_gen2_vm(self):
        """
        :avocado: tags=tier2
        RHEL-178728	WALA-TC: [General] Verify provision Gen2 VM
        BZ#1714167
        """
        self.log.info(
            "RHEL-178728	WALA-TC: [General] Verify provision Gen2 VM")
        error_msg = ""
        # Verify is Gen2
        if self.session.cmd_status_output("sudo dmesg|grep -w EFI")[0] != 0:
            self.error('This is not Gen2 VM! Abort the test.')
        # Verify hostname is correct
        try:
            self.test_check_hostname()
        except:
            error_msg += "Verify hostname correctess failed\n"
        # Verify hostname is published to DNS
        fqdn = self.session.cmd_output("hostname -f")
        if ".internal.cloudapp.net" not in fqdn:
            error_msg += "#RHEL-39537(RHEL-10):Cannot get whole FQDN: {}\n".format(fqdn)
        if "NXDOMAIN" in self.session.cmd_output("nslookup {0}".format(self.vm.vm_name)):
            error_msg += "Fail to publish hostname to DNS"
        # Verify mountpoint
        try:
            self.test_check_mountpoint()
        except:
            error_msg += "Verify mountpoint failed\n"
        if error_msg:
            self.fail(error_msg)

    def test_install_uninstall_package(self):
        """
        :avocado: tags=tier2
        RHEL7-41625	WALA-TC: [General] Installing and Uninstalling the WALinuxAgent package
        """
        self.log.info(
            "RHEL7-41625 WALA-TC: [General] Installing and Uninstalling the WALinuxAgent package")
        self.session.cmd_output("sudo su -")
        # Workaround of BZ#2099552. Create waagent.service.d folder manually
        serviced_path = "/usr/lib/systemd/system/waagent.service.d"
        cpuquota = '''
[Service]
CPUQuota=75%
'''
        self.session.cmd_output("[ -d {0} ] || ( mkdir -p {0}; echo '{1}' > {0}/12-CPUQuota.conf )".format(serviced_path, cpuquota))
        # rpm uninstall
        pkgs = self.package.replace(',', ' ')
        self.assertEqual(0, self.session.cmd_status_output(
            "rpm -e {}".format(pkgs.replace('.noarch.rpm', '')), timeout=120)[0], "Fail to uninstall package through rpm")
        # Verify no /usr/lib/systemd/system/waagent* left
        self.assertNotEqual(0, self.session.cmd_status_output(
            "ls /usr/lib/systemd/system/waagent*")[0], "#RHEL-40966(RHEL-10):Some files are left after package is removed!"
        )
        # rpm install
        self.session.cmd_output("rm -f /usr/lib/udev/rules.d/66-azure-storage.rules /usr/lib/udev/rules.d/99-azure-product-uuid.rules")
        self.assertEqual(0, self.session.cmd_status_output(
            "cd /tmp;rpm -ivh --force {};cd ~".format(pkgs))[0], "Fail to install package through rpm")
        file_list = [
            "/usr/lib/udev/rules.d/99-azure-product-uuid.rules",
            "/usr/lib/udev/rules.d/66-azure-storage.rules"
        ]
        if 'WALinuxAgent-cvm' in self.package:
            file_list += [
            "/usr/lib/udev/rules.d/90-tpm2-import.rules",
            "/usr/sbin/tpm2-luks-import.sh"
        ]
        for filename in file_list:
            self.assertTrue(utils_azure.file_exists(filename, self.session),
                "{} is not installed".format(filename))
        # yum uninstall
        yum_remove = "yum remove {} -y --disablerepo=*".format(pkgs.replace('.noarch.rpm', ''))
        if LooseVersion(self.project) >= LooseVersion("8.0"):
            # Don't remove dependencies
            yum_remove += " --noautoremove"
        self.assertEqual(0, self.session.cmd_status_output(
            yum_remove)[0], "Fail to uninstall package through yum")
        # yum install
        self.assertEqual(0, self.session.cmd_status_output(
            "cd /tmp;yum install -y {} --disablerepo=*;cd ~".format(pkgs))[0], "Fail to install package through yum")

    def test_upgrade_downgrade_package(self):
        """
        :avocado: tags=tier2
        RHEL7-41626	WALA-TC: [General] Upgrading and downgrading the WALinuxAgent package
        """
        self.log.info(
            "RHEL7-41626 WALA-TC: [General] Upgrading and downgrading the WALinuxAgent package")
        self.session.cmd_output("sudo su -")

        # Downgrade through rpm
        self.assertEqual(0, self.session.cmd_status_output(
            "rpm -Uvh --oldpackage /tmp/oldpkg/*.rpm", timeout=300)[0],
            "Fail to downgrade package through rpm")
        # Verify can restart service after rpm downgrade
        self.assertEqual(0, self.session.cmd_status_output(
            "systemctl restart waagent")[0],
            "Fail to restart waagent service after rpm downgrade")
        old_pid = self.session.cmd_output(
            "ps aux|grep '[w]aagent -daemon'|awk '{print $2}'")
        # Modify waagent.conf and waagent.logrotate before update
        self.session.cmd_output("echo '# teststring' >> /etc/waagent.conf")
        self.session.cmd_output("echo '# teststring' >> /etc/logrotate.d/waagent.logrotate")
        # Upgrade through rpm
        self.assertEqual(0, self.session.cmd_status_output(
            "cd /tmp/; rpm -Uvh --replacepkgs {}".format(self.package.replace(',', ' ')), timeout=300)[0],
            "Fail to upgrade package through rpm")
        self.assertEqual("enabled", self.session.cmd_output("systemctl is-enabled waagent"),
                         "After upgrade, the waagent service is not enabled")
        self.assertEqual("active", self.session.cmd_output("systemctl is-active waagent"),
                         "After upgrade, the waagent service is not active")
        self.assertIn("# teststring", self.session.cmd_output("tail -1 /etc/waagent.conf"),
            "Cannot keep the /etc/waagent.conf after upgrade")
        self.assertIn("# teststring", self.session.cmd_output("tail -1 /etc/logrotate.d/waagent.logrotate"),
            "Cannot keep the /etc/logrotate.d/waagent.logrotate after upgrade")
        new_pid = self.session.cmd_output(
            "ps aux|grep '[w]aagent -daemon'|awk '{print $2}'")
        self.assertNotEqual(old_pid, new_pid,
                            "waagent service is not restarted after upgrade through rpm")
        # Verify can restart service after rpm upgrade
        self.assertEqual(0, self.session.cmd_status_output(
            "systemctl restart waagent")[0],
            "Fail to restart waagent service after rpm upgrade")

        # Downgrade through yum
        self.assertEqual(0, self.session.cmd_status_output(
            "yum downgrade /tmp/oldpkg/* --disablerepo=* -y", timeout=300)[0],
            "Fail to downgrade package through yum")
        old_pid = self.session.cmd_output(
            "ps aux|grep '[w]aagent -daemon'|awk '{print $2}'")
        # Upgrade through yum
        self.assertEqual(0, self.session.cmd_status_output(
            "cd /tmp; yum upgrade -y {} --disablerepo=*".format(self.package.replace(',', ' ')), timeout=300)[0],
            "Fail to upgrade package through yum")
        new_pid = self.session.cmd_output(
            "ps aux|grep '[w]aagent -daemon'|awk '{print $2}'")
        self.assertEqual("enabled", self.session.cmd_output("systemctl is-enabled waagent"),
                            "After upgrade, the waagent service is not enabled")
        self.assertEqual("active", self.session.cmd_output("systemctl is-active waagent"),
                            "After upgrade, the waagent service is not active")
        self.assertNotEqual(old_pid, new_pid,
                            "waagent service is not restarted after upgrade through rpm")
        self.session.cmd_output("rm -f /var/log/waagent.log")
        self.session.close()
        self.vm.reboot()
        self.session.connect()
        additional_ignore_message_list = ["Error getting cloud-init enabled status from"]
        self._check_waagent_log(additional_ignore_message_list)

    def test_provision_with_2_keys(self):
        """
        :avocado: tags=tier2
        RHEL-151963	WALA-TC: [General] Provision with 2 public keys
        """
        self.log.info(
            "RHEL-151963 WALA-TC: [General] Provision with 2 public keys")
        authorized_key_list = self.session.cmd_output(
            "cat /home/{}/.ssh/authorized_keys".format(self.vm.vm_username)).strip('\n').split('\n')
        self.assertEqual(set([self.key1_value, self.key2_value]), set(authorized_key_list),
                         "The keys are not match. \nExpect:\n{}\n{}\nReal:\n{}\n{}"
                         .format(self.key1_value, self.key2_value, authorized_key_list[0], authorized_key_list[1]))

    def _block_output_443(self):
        self.session.cmd_output(
            "iptables -I OUTPUT -p tcp --dport 443 -j DROP")
        self.assertEqual(0, self.session.cmd_status_output(
            "iptables-save|grep -E '(--dport 443 -j DROP)'")[0],
            "Fail to add iptables rule to drop port 443 traffic")
        time.sleep(10)

    def _modify_value(self,
                      key,
                      value,
                      conf_file="/etc/waagent.conf",
                      sepr='='):
        self.log.info("Setting {0}{1}{2} in {3}...".format(
            key, sepr, value, conf_file))
        self.session.cmd_output(
            "sed -i -e '$a{0}{1}{2}' -e '/^.*{0}.*$/d' {3}".format(
                key, sepr, value, conf_file))
        self.session.cmd_output("sync")
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

    def test_host_plugin_autoupdate(self):
        """
        :avocado: tags=tier3
        RHEL7-83664	WALA-TC: [General] host plugin - AutoUpdate
        1. Insert iptables rule to drop output 443 traffic
        2. Stop waagent service. Remove auto-update packages.
           Enable auto-update. Enable verbose log.
        3. Start waagent service. Check if can download auto-update packages.
        "host plugin" string should be in waagent.log
        """
        self.session.cmd_output("sudo su -")
        self.log.info("host plugin - AutoUpdate")
        self.log.info("1. Insert iptables rule to drop output 443 traffic")
        self._block_output_443()
        self.log.info("2. Stop waagent service. Remove auto-update packages. "
                      "Enable auto-update. Enable verbose log")
        self.session.cmd_output("systemctl stop waagent")
        self.session.cmd_output(
            "rm -rf /var/lib/waagent/WALinuxAgent-* /var/log/waagent.log")
        self._modify_value("AutoUpdate.Enabled", "y")
        self.log.info("3. Start waagent service. Check if can download \
auto-update packages. Special string should be in waagent.log")
        self.session.cmd_output("systemctl start waagent")
        time.sleep(50)
        for retry in range(0, 30):
            if self.session.cmd_status_output("ll -d /var/lib/waagent/WALinuxAgent-*")[0] == 0:
                break
            self.log.info("Waiting for auto-update package downloaded. \
Retry: {0}/30".format(retry+1))
            time.sleep(10)
        else:
            self.fail("Fail to download auto-update packages from host plugin")
        if self.wala_version < LooseVersion('2.3.0.2'):
            keywords = "Setting host plugin as default channel"
        else:
            keywords = "Default channel changed to HostGA.* channel"
        self.assertEqual(0, self.session.cmd_status_output(
            "grep -E '{}' /var/log/waagent.log".format(keywords))[0],
            "No '{}' notice in waagent.log".format(keywords))

    def test_host_plugin_extension(self):
        """
        :avocado: tags=tier3
        RHEL7-83665	WALA-TC: [General] host plugin - Extension
        1. Insert iptables rule to drop output 443 traffic
        2. Stop waagent service. Remove extension packages. Enable verbose log.
        3. Start waagent service. Run "reset remote access". Check if can
           download extension package.
        """
        self.session.cmd_output("sudo su -")
        self.log.info("RHEL7-83665 WALA-TC: [General] host plugin - Extension")
        self._block_output_443()
        self.session.cmd_output("systemctl stop waagent")
        self.session.cmd_output("rm -f /var/log/waagent.log")
        self._modify_value("AutoUpdate.Enabled", "n")
        # Remove old extension packages
        self.session.cmd_output("rm -rf /var/lib/waagent/Microsoft*")
        self.session.cmd_output("systemctl start waagent")
        self.vm.user_reset_ssh()
        time.sleep(20)
        for retry in range(0, 10):
            if "Microsoft" in self.session.cmd_output(
                    "ll /var/lib/waagent|grep -v xml"):
                break
            self.log.info("Waiting for extension package downloaded. \
Retry: {0}/10".format(retry+1))
            time.sleep(10)
        else:
            self.fail("Fail to download extension packages from host plugin")
        if self.wala_version < LooseVersion('2.3.0.2'):
            keywords = "Setting host plugin as default channel"
        else:
            keywords = "Default channel changed to HostGA.* channel"
        self.assertEqual(0, self.session.cmd_status_output(
            "grep -E '{}' /var/log/waagent.log".format(keywords))[0],
            "No '{}' notice in waagent.log".format(keywords))

    def test_host_plugin_blob_status_upload(self):
        """
        :avocado: tags=tier3
        RHEL7-90877	WALA-TC: [General] host plugin - Blob status upload
        1. Insert iptables rule to drop output 443 traffic
        2. Stop waagent service. Enable verbose log.
        3. Start waagent service. Check waagent.log if can upload blob status
           through host plugin.
        """
        self.session.cmd_output("sudo su -")
        self.log.info(
            "RHEL7-90877 WALA-TC: [General] host plugin - Blob status upload")
        self._block_output_443()
        self.session.cmd_output("systemctl stop waagent")
        self.session.cmd_output("rm -f /var/log/waagent.log")
        self._modify_value("AutoUpdate.Enabled", "n")
        self._modify_value("Logs.Verbose", "y")
        self.session.cmd_output("systemctl start waagent")
        time.sleep(180)
        for retry in range(0, 10):
            if self.session.cmd_status_output(
                    "grep 'HostGAPlugin: Put BlockBlob status succeeded' /var/log/waagent.log ")[0] == 0:
                break
            self.log.info(
                "Waiting for blob status uploading. Retry: {}/10".format(retry+1))
            time.sleep(10)
        else:
            self.fail("Fail to uploading blob status")

    def test_host_plugin_ignore_proxy(self):
        """
        :avocado: tags=tier3
        RHEL7-93870	WALA-TC: [General] host plugin - ignore proxy
        1. Stop waagent service. Enable wrong proxy. Enable auto-update.
           Remove /var/lib/waagent/WALinuxAgent-*.
        2. Start waagent service. Check if can download auto-update packages.
        """
        self.session.cmd_output("sudo su -")
        self.log.info("host plugin - AutoUpdate")
        self.log.info(
            "RHEL7-93870	WALA-TC: [General] host plugin - ignore proxy")
        self.session.cmd_output("systemctl stop waagent")
        self.session.cmd_output("rm -rf /var/lib/waagent/WALinuxAgent-*")
        self.session.cmd_output("rm -f /var/log/waagent.log")
        self._modify_value("AutoUpdate.Enabled", "y")
        self._modify_value("Logs.Verbose", "y")
        self._modify_value("HttpProxy.Host", "172.16.0.1")
        self._modify_value("HttpProxy.Port", "3128")
        self.session.cmd_output("systemctl start waagent")
        time.sleep(50)
        for retry in range(0, 10):
            if self.session.cmd_status_output("ll /var/lib/waagent/WALinuxAgent-*.zip")[0] == 0:
                break
            if self.session.cmd_status_output("grep 'Installed Agent .* is the most current agent' /var/log/waagent.log")[0] == 0:
                self.log.info("Current version is the latest. No need to download zip files.")
                break
            self.log.info(
                "Waiting for auto-update package downloaded. Retry: {0}/10".format(retry+1))
            time.sleep(10)
        else:
            self.fail("Fail to ignore proxy to download auto-update packages")

    def test_verify_nic_down_up_in_one_line(self):
        """
        :avocado: tags=tier1
        VIRT-294607 - WALA-TC: [General] Verify NIC down/up in the same line (code check)	
        Verify 'ip link set nic down' and 'ip link set nic up' in the same line in the wala code
        """
        self.log.info("VIRT-294607 - WALA-TC: [General] Verify NIC down/up in the same line (code check)")
        # Find the redhat.py full path
        file_path = self.session.cmd_output("rpm -ql WALinuxAgent|grep 'osutil/redhat.py'")
        # Check the content
        self.assertEqual(0, 
            self.session.cmd_status_output("grep -E 'ip link set .* down && ip link set .* up' {}".format(file_path))[0],
            "BZ#2098233: The 'ip link set down' and 'ip link set up' are not in the same line!")

    def test_verify_agent_cgroup_enabled(self):
        """
        :avocado: tags=tier2
        VIRT-294849 - WALA-TC: [General] Verify Agent CGroup enabled
        """
        if self.wala_version < LooseVersion('2.7.0.6'):
            self.cancel("This case is available in WALA v2.7.0.6+. Skip.")
        self.log.info("VIRT-294849 - WALA-TC: [General] Verify Agent CGroup enabled")
        # Print cgroup related logs
        self.session.cmd_output("grep -i cgroup /var/log/waagent.log")
        # Verify Agent CGroups is enabled
        self.assertIn('True', 
            self.session.cmd_output("grep 'Agent cgroups enabled' /var/log/waagent.log"),
            "#RHEL-7274(RHEL-9+):Agent cgroups is not enabled")

    def test_wala_version_not_lower_than_old_rhel(self):
        """
        :avocado: tags=tier3
        RHEL-198423 - WALA-TC: [General] Verify WALA version is not lower than it in the previous RHEL release
        """
        self.log.info("RHEL-198423 - WALA-TC: [General] Verify WALA version is not lower than it in the previous RHEL release")
        new_wala_pkg = self.session.cmd_output("rpm -q WALinuxAgent")
        new_wala_version = new_wala_pkg.split('-')[1]
        # Get the previous WALA version
        pre_x_version = int(self.project.split('.')[0]) - 1
        if pre_x_version == 7:
            pre_project = '7.9'
            brew_tag = "extras-rhel-7.9-candidate"
        else:
            compose_id = utils_azure.command("curl http://download.eng.bos.redhat.com/rhel-{0}/nightly/RHEL-{0}/latest-RHEL-{0}/COMPOSE_ID;echo".format(pre_x_version)).stdout
            pre_project = compose_id.split('-')[1]
            brew_tag = "rhel-{}-pending".format(pre_project)
        pre_wala_pkg = utils_azure.command("brew latest-build %s WALinuxAgent --quiet|awk '{print $1}'" % brew_tag).stdout.rstrip('\n')
        self.log.info("The latest WALA package in the RHEL-{} is {}".format(pre_x_version, pre_wala_pkg))
        pre_wala_version = pre_wala_pkg.split('-')[1]
        # Compare the WALA versions
        self.assertTrue(LooseVersion(new_wala_version) >= LooseVersion(pre_wala_version),
            "The {} in RHEL-{} is lower than {} in the RHEL-{}".format(new_wala_pkg, self.project, pre_wala_pkg, pre_project))
        self.log.info("The {} in RHEL-{} is newer than or equal to {} in the RHEL-{}".format(new_wala_pkg, self.project, pre_wala_pkg, pre_project))

    def test_check_waagent_network_setup_service(self):
        """
        :avocado: tags=tier3
        VIRT-294089	WALA-TC: [General] Check waagent-network-setup service
        """
        self.log.info("VIRT-294089 - WALA-TC: [General] Check waagent-network-setup service")
        self.session.cmd_output("sudo su -")
        self.session.cmd_output("systemctl status waagent-network-setup.service")
        self.session.cmd_output("rm -f /var/log/waagent.log /usr/lib/systemd/system/waagent-network-setup.service /var/lib/waagent/waagent-network-setup.py")
        self.session.cmd_output("systemctl restart waagent")
        time.sleep(5)
        self.assertEqual(0, self.session.cmd_status_output("grep 'Successfully added and enabled the waagent-network-setup.service' /var/log/waagent.log")[0],
            "waagent-network-setup fails to be added and enabled.")
        self.session.cmd_output("rm -f /var/log/waagent.log")
        self.session.cmd_output("systemctl restart waagent")
        time.sleep(5)
        self.assertEqual(0, self.session.cmd_status_output("grep 'waagent-network-setup.service already enabled' /var/log/waagent.log")[0],
            "waagent-network-setup is not enabled.")

    def test_change_python_version(self):
        """
        :avocado: tags=tier3
        VIRT-296991 WALA-TC: [General] Change python version
        """
        self.log.info("VIRT-296991 WALA-TC: [General] Change python version")
        self.session.cmd_output("sudo su -")
        # The new python must be different from the old one
        self.old_python = self.session.cmd_output("alternatives --display python3|grep 'link currently'|awk -F \'/\' \'{print $NF}\'")
        self.new_python = "python3.9"
        assert(self.session.cmd_status_output("yum install -y " + self.new_python, timeout=300)[0] == 0)
        self.session.cmd_output("alternatives --set python3 /usr/bin/{}".format(self.new_python))
        self.session.cmd_output("systemctl restart waagent")
        self.assertEqual(self.session.cmd_output("systemctl is-active waagent"), 'active',
            "Cannot start waagent service after changing python version")

    def test_check_10_azure_unmanaged_sriov_rules(self):
        """
        :avocado: tags=tier2
        VIRT-303915	WALA-TC: [Network] Verify 10-azure-unmanaged-sriov.rules exists
        """
        self.log.info("VIRT-303915	WALA-TC: [Network] Verify 10-azure-unmanaged-sriov.rules exists")
        ret = self.session.cmd_status_output("sudo cat /usr/lib/udev/rules.d/10-azure-unmanaged-sriov.rules")
        self.log.info(ret[1])
        self.assertEqual(ret[0], 0, "/usr/lib/udev/rules.d/10-azure-unmanaged-sriov.rules doesn't exist!")

    def tearDown(self):
        if self.case_short_name == "test_event_clean_up_when_above1000":
            self.session.cmd_output("rm -f /var/lib/waagent/events/test*")
        if self.case_short_name == "test_logrotate":
            self.session.cmd_output(
                "rm -rf /var/log/waagent.log* /var/log/azure/test;"
                "cp /tmp/waagent.log /var/log/waagent.log")
        if self.case_short_name.startswith("test_host_plugin"):
            self.session.cmd_output(
                "/usr/bin/mv /etc/waagent.conf-bak /etc/waagent.conf")
            self.session.cmd_output("rm -f /var/log/waagent.log")
            self.session.cmd_output(
                "iptables -D OUTPUT -p tcp --dport 443 -j DROP")
            time.sleep(10)
            self.session.cmd_output("systemctl restart waagent")
            if self.case_short_name == "test_host_plugin_extension":
                self.vm.extension_delete("enablevmaccess")
        if self.case_short_name == "test_change_python_version":
            self.session.cmd_output("alternatives --set python3 /usr/bin/" + self.old_python)
            self.session.cmd_output("yum remove -y " + self.new_python)
            self.session.cmd_output("systemctl restart waagent")
        if self.case_short_name in [
                "test_upgrade_downgrade_package",
                "test_install_uninstall_package",
                "test_provision_with_2_keys",
                "test_provision_gen2_vm",
            ]:
            self.vm.delete()


'''
    def test_check_release_version(self):
        """
        Check the /etc/redhat-release file contains a correct release version
        """
        self.log.info("Check the /etc/redhat-release file contains a correct \
release version")
        output_version = self.session.cmd_output("cat /etc/redhat-release")
        self.assertIn(str(self.project), output_version,
                      "Wrong version in /etc/redhat-release file. Real version\
: %s" % output_version)

    def test_check_boot_messages(self):
        """
        Check if there's error in the messages
        """
        self.log.info("Check the boot messages")
        error_log = self.vm.check_messages_log()
        self.assertEqual(error_log, "",
                         "Bug 1365727. "
                         "There's error in the messages: \n%s" % error_log)

    def test_verify_package_signed(self):
        """
        Check if the WALinuxAgent package is signed
        """
        self.log.info("Verify all packages are signed")
        self.session.cmd_output("rm -f /etc/yum.repos.d/redhat.repo")
        self.session.cmd_output("rpm -ivh /root/rhui*.rpm")
        self.assertIn("rh-cloud.repo",
                      self.session.cmd_output("ls /etc/yum.repos.d/"),
                      "RHUI is not installed. Cannot use yum.")
        self.session.cmd_output("rpm -e WALinuxAgent")
        self.session.cmd_output("yum install WALinuxAgent -y")
        cmd = "rpm -q WALinuxAgent --qf '%{name}-%{version}-%{release}.%{arch}\
 (%{SIGPGP:pgpsig})';echo"

        self.assertIn("Key ID", self.session.cmd_output(cmd),
                      "Fail to verify WALinuxAgent package signature")

    def test_check_hyperv_modules(self):
        """
        Check the hyper-V modules
        """
        self.log.info("Check the hyper-v modules")
        module_list = ["hv_utils", "hv_netvsc", "hid_hyperv",
                       "hyperv_keyboard", "hv_storvsc", "hyperv_fb",
                       "hv_vmbus", "hv_balloon"]
        output = self.session.cmd_output("lsmod|grep -E 'hv|hyperv'")
        for module in module_list:
            self.assertIn(module, output,
                          "%s module doesn't exist" % module)

    def test_verify_autoupdate_disabled(self):
        """
        Verify AutoUpdate is disabled(deprecated after WALA-2.2.4-2)
        """
        self.log.info("Verify AutoUpdate is disabled")
        # 1. Check AutoUpdate.enabled value
        self.assertTrue(self.vm.verify_value("AutoUpdate\.Enabled", 'n'),
                        "The AutoUpdate.enabled is not 'n' after installing \
WALA rpm package.")
'''

if __name__ == "__main__":
    main()
