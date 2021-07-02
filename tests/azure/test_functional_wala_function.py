import time
import re
import os
from distutils.version import LooseVersion
from avocado import Test
from avocado_cloud.app import Setup
from avocado_cloud.app.azure import AzureAccount
from avocado_cloud.utils.utils_azure import WalaConfig

BASEPATH = os.path.abspath(__file__ + "/../../../")

# WAAGENT_IGNORELIST = [
#     "INFO sfdisk with --part-type failed .1., retrying with -c",
#     "INFO Retry .1/1 - IO error: HTTP GET .Errno 101. Network is unreachable.",
#     "WARNING Failed to send DHCP request: .000006. timed out",
#     "ERROR Event: name=WALinuxAgent, op=AutoUpdate, message=, duration=0",
#     "WARNING ExtHandler failed to get IMDS info",
#     "INFO Daemon Error getting cloud-init enabled status from systemctl"
# ]


class WALAFuncTest(Test):
    """
    :avocado: tags=wala,func
    """

    def setUp(self):
        account = AzureAccount(self.params)
        account.login()
        self.case_short_name = re.findall(r"Test.(.*)", self.name.name)[0]
        cloud = Setup(self.params, self.name)
        self.vm = cloud.vm
        self.session = cloud.init_vm()
        if "interrupt_ctrl_c" in self.name.name:
            self.session1 = cloud.init_session()
            self.session1.connect()
        status, output = self.session.cmd_status_output('sudo su -')
        self.assertEqual(status, 0,
                         "User [root] login failed\n{}".format(str(output)))
        # Must stop NetworkManager or it will regenerate /etc/resolv.conf in RHEL-8.4
        if "test_waagent_depro" in self.case_short_name:
            self.session.cmd_output("systemctl stop NetworkManager")

    def test_waagent_verbose(self):
        """
        :avocado: tags=tier2
        WALA-TC: [WALA function] Check waagent -verbose
        """
        cmd_stop_waagent = "service waagent stop"
        status, output = self.session.cmd_status_output(cmd_stop_waagent)
        self.assertEqual(
            status, 0,
            "Fail to stop waagent service before test\n{}".format(str(output)))
        cmd_delete_log = "rm -f /var/log/waagent.log"
        self.session.cmd_output(cmd_delete_log)
        cmd_rerun_wala = "timeout 5 waagent -verbose -daemon"
        self.session.cmd_output(cmd_rerun_wala)
        time.sleep(5)
        cmd_verbose_check = "grep -RE 'HTTP\ Req|VERBOSE' /var/log/waagent.log"
        status, output = self.session.cmd_status_output(cmd_verbose_check)
        self.assertNotEqual(output, "", "Fail to enable verbose log")

    def test_waagent_version(self):
        """
        :avocado: tags=tier2
        WALA-TC: [WALA function] Check waagent -version
        """
        self.log.info("[WALA function] Check waagent -version")
        # Check the WALinuxAgent version
        # wala_version = self.params.get("wala_ver", "*/VM/*").split('-')[0]
        rpm_version = self.session.cmd_output("rpm -q WALinuxAgent")
        rpm_version_format = rpm_version.split('-')[1]
        show_version = self.session.cmd_output(
            "echo `waagent -version`").split(' ')[0].replace(
                "WALinuxAgent-", "")
        self.assertEqual(
            rpm_version_format, show_version, "WALinuxAgent version is wrong. "
            "Expect version: %s Show version: %s" %
            (rpm_version_format, show_version))

    def test_waagent_depro_nouser_noforce(self):
        """
        :avocado: tags=tier2
        WALA-TC: [WALA function] Check waagent -deprovision(not include user 
                 and no -force flag)
        """
        self.log.info("[WALA function] Check waagent -deprovision")
        # prepare environment
        if not self.vm.vm_password:
            # In fact,this password is not used for login,so put a plaintext
            # password here
            self.vm.vm_password = "RedHat@2019"
        passwd_status, passwd_output = self.session.cmd_status_output(
            "echo %s | passwd --stdin root" % self.vm.vm_password)
        self.assertEqual(passwd_status, 0,
                         "Fail to set password for user root")
        walaconfig = WalaConfig(self.session)
        status, output = walaconfig.modify_value(
            "Provisioning.DeleteRootPassword", "y")
        self.assertEqual(status, 0, output)
        del status, output
        status, output = walaconfig.verify_value(
            "Provisioning.DeleteRootPassword", "y")
        self.assertEqual(status, 0, output)
        del status, output
        status, output = walaconfig.modify_value(
            "Provisioning.RegenerateSshHostKeyPair", "y")
        self.assertEqual(status, 0, output)
        del status, output
        status, output = walaconfig.verify_value(
            "Provisioning.RegenerateSshHostKeyPair", "y")
        self.assertEqual(status, 0, output)
        del status, output
        wala_version = self.session.cmd_output("rpm -q WALinuxAgent")
        # In case there's no /root/.bash_history
        self.session.cmd_output("touch /var/lib/dhclient/walatest")
        self.session.cmd_output("touch /root/.bash_history")
        check_list = [
            "/etc/ssh/ssh_host_*", "/etc/resolv.conf", "/var/lib/dhclient/*",
            "/root/.bash_history", "/var/log/waagent.log"
        ]
        message_list = [
            "WARNING! The waagent service will be stopped",
            "WARNING! All SSH host key pairs will be deleted",
            "WARNING! Cached DHCP leases will be deleted",
            # For 2.0.16
            # "WARNING! Nameserver configuration in /etc/resolv.conf will be \
            # deleted",
            "WARNING! /etc/resolv.conf will be deleted",
            "WARNING! root password will be disabled. You will not be able to \
login as root"
        ]
        if r"2.0.16" in wala_version:
            message_list = [
                "WARNING! The waagent service will be stopped",
                "WARNING! All SSH host key pairs will be deleted",
                "WARNING! Cached DHCP leases will be deleted",
                "WARNING! Nameserver configuration in /etc/resolv.conf will be \
deleted", "WARNING! root password will be disabled. You will not be able \
to login as root"
            ]
        # 1.1. waagent -deprovision [n]
        deprovision_status, deprovision_output = \
            self.session.cmd_status_output(
                "echo `echo 'n' | waagent -deprovision`")
        self.assertEqual(deprovision_status, 0, deprovision_output)
        for msg in message_list:
            self.assertIn(msg, deprovision_output, "Bug 1364883. "
                          "%s message is not shown" % msg)
        self.assertIn("Do you want to proceed (y/n)", deprovision_output,
                      "Do you want to proceed (y/n) message is not shown")
        for not_delete_file in check_list:
            self.assertNotIn(
                "No such file",
                self.session.cmd_output("ls %s" % not_delete_file),
                "%s should not be deleted" % not_delete_file)
        self.assertNotIn("LOCK",
                         self.session.cmd_output("grep -R root /etc/shadow"),
                         "Should not delete root password")
        if LooseVersion(self.vm.rhel_version) < LooseVersion("7.0"):
            self.assertNotIn(
                "localhost.localdomain",
                self.session.cmd_output(
                    "grep -R HOSTNAME /etc/sysconfig/network"),
                "Should not reset hostname")
        else:
            self.assertNotEqual(
                "localhost.localdomain",
                self.session.cmd_output("grep -R localhost /etc/hostname"),
                "Should not reset hostname")
        # 1.2. waagent -deprovision [y]
        del deprovision_status, deprovision_output
        deprovision_status, deprovision_output = \
            self.session.cmd_status_output(
                "echo 'y' | waagent -deprovision")
        for delete_file in check_list:
            self.assertIn("No such file",
                          self.session.cmd_output("ls %s" % delete_file),
                          "%s is not deleted" % delete_file)
        self.assertIn("LOCK",
                      self.session.cmd_output("grep -R root /etc/shadow"),
                      "Root password is not deleted")
        if LooseVersion(self.vm.rhel_version) < LooseVersion("7.0"):
            self.assertIn(
                "localhost.localdomain",
                self.session.cmd_output(
                    "grep -R HOSTNAME /etc/sysconfig/network"),
                "Hostname is not reset")
        else:
            self.assertEqual(
                "localhost.localdomain",
                self.session.cmd_output("grep -R localhost /etc/hostname"),
                "Hostname is not reset")

    def test_waagent_depro_nouser_force(self):
        """
        :avocado: tags=tier2
        WALA-TC: [WALA function] Check waagent -deprovision -force(not include 
                 user, with -force flag)
        """
        self.log.info("[WALA function] Check waagent -deprovision -force")
        # prepare environment
        if not self.vm.vm_password:
            # In fact,this password is not used for login,so put a plaintext
            # password here
            self.vm.vm_password = "RedHat@2019"
        passwd_status, passwd_output = self.session.cmd_status_output(
            "echo %s | passwd --stdin root" % self.vm.vm_password)
        self.assertEqual(passwd_status, 0,
                         "Fail to set password for user root")
        wala_version = self.session.cmd_output("rpm -q WALinuxAgent")
        check_list = [
            "/etc/ssh/ssh_host_*", "/etc/resolv.conf", "/var/lib/dhclient/*",
            "/root/.bash_history", "/var/log/waagent.log"
        ]
        message_list = [
            "WARNING! The waagent service will be stopped",
            "WARNING! All SSH host key pairs will be deleted",
            "WARNING! Cached DHCP leases will be deleted",
            # For 2.0.16
            # "WARNING! Nameserver configuration in /etc/resolv.conf will be \
            # deleted",
            "WARNING! /etc/resolv.conf will be deleted",
            "WARNING! root password will be disabled. You will not be able \
to login as root"
        ]
        if r"2.0.16" in wala_version:
            message_list = [
                "WARNING! The waagent service will be stopped",
                "WARNING! All SSH host key pairs will be deleted",
                "WARNING! Cached DHCP leases will be deleted",
                "WARNING! Nameserver configuration in /etc/resolv.conf will \
be deleted", "WARNING! root password will be disabled. You will not be able \
to login as root"
            ]
        # waagent -deprovision -force
        deprovision_status, deprovision_output = \
            self.session.cmd_status_output(
                "waagent -deprovision -force")
        self.assertEqual(deprovision_status, 0, deprovision_output)
        for msg in message_list:
            self.assertIn(msg, deprovision_output,
                          "%s message is not shown" % msg)
        self.assertNotIn(
            "Do you want to proceed (y/n)", deprovision_output,
            "Do you want to proceed (y/n) message should not be shown")
        for delete_file in check_list:
            self.assertIn("No such file",
                          self.session.cmd_output("ls %s" % delete_file),
                          "%s is not deleted" % delete_file)
        self.assertIn("LOCK",
                      self.session.cmd_output("grep -R root /etc/shadow"),
                      "Root password is not deleted")
        if LooseVersion(self.vm.rhel_version) < LooseVersion("7.0"):
            self.assertIn(
                "localhost.localdomain",
                self.session.cmd_output(
                    "grep -R HOSTNAME /etc/sysconfig/network"),
                "Hostname is not reset")
        else:
            self.assertEqual(
                "localhost.localdomain",
                self.session.cmd_output("grep -R localhost /etc/hostname"),
                "Hostname is not reset")
        del deprovision_status, deprovision_output
        # 3.1. Warning log check when Provisioning.DeleteRootPassword=n
        walaconfig = WalaConfig(self.session)
        status, output = walaconfig.modify_value(
            "Provisioning.DeleteRootPassword", "n")
        self.assertEqual(status, 0, output)
        del status, output
        deprovision_status, deprovision_output = \
            self.session.cmd_status_output(
                "waagent -deprovision -force")
        self.assertEqual(deprovision_status, 0, deprovision_output)
        self.assertNotIn(
            "WARNING! root password will be disabled. You will not be able \
to login as root", deprovision_output,
            "Should not have the disable root password message. Messages:\n%s"
            % deprovision_output)
        del deprovision_status, deprovision_output
        # 3.2. Warning log check when Provisioning.RegenerateSshHostKeyPair=n
        status, output = walaconfig.modify_value(
            "Provisioning.RegenerateSshHostKeyPair", "n")
        self.assertEqual(status, 0, output)
        del status, output
        deprovision_status, deprovision_output = \
            self.session.cmd_status_output(
                "waagent -deprovision -force")
        self.assertEqual(deprovision_status, 0, deprovision_output)
        self.assertNotIn(
            "WARNING! All SSH host key pairs will be deleted",
            deprovision_output, "Bug 1314734. "
            "Should not have the delete ssh host key message. Messages:\n%s" %
            deprovision_output)

    def test_waagent_depro_user_noforce(self):
        """
        :avocado: tags=tier2
        WALA-TC: [WALA function] Check waagent -deprovision+user(include user 
                 and no -force flag)
        """
        self.log.info("[WALA function] Check waagent -deprovision+user\
                     | read 'y/n' from your input")
        # prepare environment
        if not self.vm.vm_password:
            # In fact,this password is not used for login,
            # so put a plaintext password here
            self.vm.vm_password = "RedHat@2019"
        passwd_status, passwd_output = self.session.cmd_status_output(
            "echo %s | passwd --stdin root" % self.vm.vm_password)
        self.assertEqual(passwd_status, 0,
                         "Fail to set password for user root")
        walaconfig = WalaConfig(self.session)
        status, output = walaconfig.modify_value(
            "Provisioning.DeleteRootPassword", "y")
        self.assertEqual(status, 0, output)
        del status, output
        status, output = walaconfig.verify_value(
            "Provisioning.DeleteRootPassword", "y")
        self.assertEqual(status, 0, output)
        del status, output
        status, output = walaconfig.modify_value(
            "Provisioning.RegenerateSshHostKeyPair", "y")
        self.assertEqual(status, 0, output)
        del status, output
        status, output = walaconfig.verify_value(
            "Provisioning.RegenerateSshHostKeyPair", "y")
        self.assertEqual(status, 0, output)
        del status, output
        wala_version = self.session.cmd_output("rpm -q WALinuxAgent")
        check_list = [
            "/etc/ssh/ssh_host_*", "/etc/resolv.conf", "/var/lib/dhclient/*",
            "/root/.bash_history", "/var/log/waagent.log"
        ]
        message_list = [
            "WARNING! The waagent service will be stopped",
            "WARNING! All SSH host key pairs will be deleted",
            "WARNING! Cached DHCP leases will be deleted",
            # For 2.0.16
            # "WARNING! Nameserver configuration in /etc/resolv.conf will be \
            # deleted",
            "WARNING! /etc/resolv.conf will be deleted",
            "WARNING! root password will be disabled. You will not be able to \
login as root",
            "WARNING! %s account and entire home directory will be deleted" %
            self.vm.vm_username
        ]
        if r"2.0.16" in wala_version:
            message_list = [
                "WARNING! The waagent service will be stopped",
                "WARNING! All SSH host key pairs will be deleted",
                "WARNING! Cached DHCP leases will be deleted",
                "WARNING! Nameserver configuration in /etc/resolv.conf will be \
deleted", "WARNING! root password will be disabled. You will not be able to \
login as root"
            ]
        # Make files for checking
        self.session.cmd_output("touch /var/lib/dhclient/walatest")
        self.session.cmd_output("touch /root/.bash_history")
        # 1.1. waagent -deprovision+user [n]
        deprovision_status, deprovision_output = \
            self.session.cmd_status_output(
                "echo `echo 'n' |sudo waagent -deprovision+user`")
        self.assertEqual(deprovision_status, 0, deprovision_output)
        for msg in message_list:
            self.assertIn(msg, deprovision_output, "Bug 1364883. "
                          "'%s' message is not shown" % msg)
        self.assertIn("Do you want to proceed (y/n)", deprovision_output,
                      "Do you want to proceed (y/n) message is not shown")
        for not_delete_file in check_list:
            self.assertNotIn(
                "No such file",
                self.session.cmd_output("ls %s" % not_delete_file),
                "%s should not be deleted" % not_delete_file)
        self.assertNotIn("LOCK",
                         self.session.cmd_output("grep -R root /etc/shadow"),
                         "Should not delete root password")
        self.assertIn(
            self.vm.vm_username,
            self.session.cmd_output("grep -r %s /etc/sudoers.d/waagent" %
                                    self.vm.vm_username),
            "Should not wipe /etc/sudoers.d/waagent")
        if LooseVersion(self.vm.rhel_version) < LooseVersion("7.0"):
            self.assertNotIn(
                "localhost.localdomain",
                self.session.cmd_output(
                    "grep -R HOSTNAME /etc/sysconfig/network"),
                "Should not reset hostname")
        else:
            self.assertNotEqual(
                "localhost.localdomain",
                self.session.cmd_output("grep -R localhost /etc/hostname"),
                "Should not reset hostname")
        self.assertNotEqual(
            "",
            self.session.cmd_output("grep -R %s /etc/shadow" %
                                    self.vm.vm_username),
            "%s should not be deleted" % self.vm.vm_username)
        del deprovision_status, deprovision_output
        # 1.2. waagent -deprovision+user [y]
        deprovision_status, deprovision_output = \
            self.session.cmd_status_output(
                "echo 'y' | waagent -deprovision+user")
        self.assertEqual(deprovision_status, 0, deprovision_output)
        for delete_file in check_list:
            self.assertIn("No such file",
                          self.session.cmd_output("ls %s" % delete_file),
                          "%s is not deleted" % delete_file)
        self.assertIn("LOCK",
                      self.session.cmd_output("grep -R root /etc/shadow"),
                      "Root password is not deleted")
        if LooseVersion(self.params.get("rhel_ver",
                                        "*/VM/*")) < LooseVersion("7.0"):
            self.assertIn(
                "localhost.localdomain",
                self.session.cmd_output(
                    "grep -R HOSTNAME /etc/sysconfig/network"),
                "hostname is not reset")
        else:
            self.assertEqual(
                "localhost.localdomain",
                self.session.cmd_output("grep -R localhost /etc/hostname"),
                "hostname is not reset")
        self.assertEqual(
            "",
            self.session.cmd_output("grep -R %s /etc/shadow" %
                                    self.vm.vm_username),
            "%s is not deleted" % self.vm.vm_username)
        if r"2.0.16" in wala_version:
            self.assertIn("No such file",
                          self.session.cmd_output("ls /etc/sudoers.d/waagent"),
                          "/etc/sudoers.d/waagent is not deleted")
        else:
            self.assertEqual(
                "",
                self.session.cmd_output("grep -R %s /etc/sudoers.d/waagent" %
                                        self.vm.vm_username),
                "/etc/sudoers.d/waagent is not wiped")

    def test_waagent_depro_user_force(self):
        """
        :avocado: tags=tier1
        WALA-TC: [WALA function] Check waagent -force -deprovision+user
        """
        self.log.info("[WALA function] Check waagent -force -deprovision+user")
        # prepare environment
        if not self.vm.vm_password:
            # In fact,this password is not used for login,so put a plaintext
            # password here
            self.vm.vm_password = "RedHat@2019"
        passwd_status, passwd_output = self.session.cmd_status_output(
            "echo %s | passwd --stdin root" % self.vm.vm_password)
        self.assertEqual(passwd_status, 0,
                         "Fail to set password for user root")
        wala_version = self.session.cmd_output("rpm -q WALinuxAgent")
        check_list = [
            "/etc/ssh/ssh_host_*", "/etc/resolv.conf", "/var/lib/dhclient/*",
            "/root/.bash_history", "/var/log/waagent.log"
        ]
        message_list = [
            "WARNING! The waagent service will be stopped",
            "WARNING! All SSH host key pairs will be deleted",
            "WARNING! Cached DHCP leases will be deleted",
            # For 2.0.16
            # "WARNING! Nameserver configuration in /etc/resolv.conf will be \
            # deleted",
            "WARNING! /etc/resolv.conf will be deleted",
            "WARNING! root password will be disabled. You will not be able to \
login as root",
            "WARNING! %s account and entire home directory will be deleted" %
            self.vm.vm_username
        ]
        if r"2.0.16" in wala_version:
            message_list = [
                "WARNING! The waagent service will be stopped",
                "WARNING! All SSH host key pairs will be deleted",
                "WARNING! Cached DHCP leases will be deleted",
                "WARNING! Nameserver configuration in /etc/resolv.conf will \
be deleted", "WARNING! root password will be disabled. You will not be able \
to login as root"
            ]
        # waagent -deprovision+user -force
        deprovision_status, deprovision_output = \
            self.session.cmd_status_output(
                "waagent -deprovision+user -force")
        self.assertEqual(deprovision_status, 0, deprovision_output)
        for msg in message_list:
            self.assertIn(msg, deprovision_output,
                          "%s message is not shown" % msg)
        for delete_file in check_list:
            self.assertIn("No such file",
                          self.session.cmd_output("ls %s" % delete_file),
                          "%s is not deleted" % delete_file)
        self.assertIn("LOCK",
                      self.session.cmd_output("grep -R root /etc/shadow"),
                      "Root password is not deleted")
        if LooseVersion(self.vm.rhel_version) < LooseVersion("7.0"):
            self.assertIn(
                "localhost.localdomain",
                self.session.cmd_output(
                    "grep -R HOSTNAME /etc/sysconfig/network"),
                "Hostname is not reset")
        else:
            self.assertEqual(
                "localhost.localdomain",
                self.session.cmd_output("grep -R localhost /etc/hostname"),
                "Hostname is not reset")
        self.assertEqual(
            "",
            self.session.cmd_output("grep -R %s /etc/shadow" %
                                    self.vm.vm_username),
            "%s is not deleted" % self.vm.vm_username)
        if r"2.0.16" in wala_version:
            self.assertIn("No such file",
                          self.session.cmd_output("ls /etc/sudoers.d/waagent"),
                          "/etc/sudoers.d/waagent is not deleted")
        else:
            self.assertEqual(
                "",
                self.session.cmd_output("grep -R %s /etc/sudoers.d/waagent" %
                                        self.vm.vm_username),
                "/etc/sudoers.d/waagent is not wiped")

    def test_waagent_help(self):
        """
        :avocado: tags=tier2
        WALA-TC: [WALA function] Check waagent -help
        """
        self.log.info("[WALA function] Check waagent -help")
        wala_version = LooseVersion(
            self.session.cmd_output("rpm -q WALinuxAgent").split("-")[1])
        if wala_version == LooseVersion("2.0.16"):
            help_msg = "[-verbose] [-force] [-help|" \
                       "-install|-uninstall|-deprovision[+user]|-version|"\
                       "-serialconsole|-daemon]"
        elif wala_version < LooseVersion("2.2.18"):
            help_msg = "[-verbose] [-force] [-help] " \
                       "-configuration-path:<path to configuration file>"\
                       "-deprovision[+user]|-register-service|-version|"\
                       "-daemon|-start|-run-exthandlers]"
        elif wala_version < LooseVersion("2.3.0"):
            help_msg = "[-verbose] [-force] [-help] " \
                       "-configuration-path:<path to configuration file>"\
                       "-deprovision[+user]|-register-service|-version|"\
                       "-daemon|-start|-run-exthandlers|"\
                       "-show-configuration]"
        else:
            help_msg = "[-verbose] [-force] [-help] " \
                       "-configuration-path:<path to configuration file>"\
                       "-deprovision[+user]|-register-service|-version|"\
                       "-daemon|-start|-run-exthandlers|-show-configuration|"\
                       "-collect-logs [-full]|-setup-firewall "\
                       "[-dst_ip=<IP> -uid=<UID> [-w/--wait]]"
        # self.log.info("help_msg: \n" + help_msg)
        cmd_output = self.session.cmd_output("waagent -help").strip(
            '\n').split("waagent")[-1].strip()
        self.assertEqual(help_msg, cmd_output, "waagent help message is wrong")

    def test_waagent_start(self):
        """
        :avocado: tags=tier2
        WALA-TC: [WALA function] waagent -start
        """
        self.log.info("[WALA function] waagent -start")
        # Stop waagent service
        cmd_stop_waagent = "service waagent stop"
        status, output = self.session.cmd_status_output(cmd_stop_waagent)
        self.assertEqual(
            status, 0,
            "Fail to stop waagent service before test\n{}".format(str(output)))
        # waagent start
        self.session.cmd_output("waagent -start")
        time.sleep(1)
        processes = self.session.cmd_output("ps aux|grep -E 'waagent|WAL'")
        self.assertIn("waagent -daemon", processes,
                      "Fail to start daemon process through waagent -start")
        self.assertIn("-run-exthandlers", processes,
                      "Fail to start exthandlers through waagent -start")

    def test_waagent_run_exthandlers(self):
        """
        :avocado: tags=tier2
        WALA-TC: [WALA function] waagent -run-exthandlers
        """
        self.log.info("[WALA function] waagent -run-exthandlers")
        # Stop service, remove waagent.log
        cmd_stop_waagent = "service waagent stop"
        status, output = self.session.cmd_status_output(cmd_stop_waagent)
        self.assertEqual(
            status, 0,
            "Fail to stop waagent service before test\n{}".format(str(output)))
        self.session.cmd_output("rm -f /var/log/waagent.log")
        walaconfig = WalaConfig(self.session)
        status, output = walaconfig.modify_value("AutoUpdate.Enabled", "n")
        self.assertEqual(status, 0, output)
        del status, output
        status, output = walaconfig.verify_value("AutoUpdate.Enabled", "n")
        self.assertEqual(status, 0, output)
        del status, output
        # waagent -run-exthandlers
        # It doesn't check the process, but only check the log.
        output = self.session.cmd_output("timeout 3 waagent -run-exthandlers")
        self.assertIn("is running as the goal state agent", output,
                      "Fail to run exthandlers")
        self.assertIn("is an orphan -- exiting", output,
                      "Fail to exit as orphan")
        output = self.session.cmd_output(
            "grep -iE 'error|fail' /var/log/waagent.log")
        self.assertEqual("", output, "There are error logs: \n%s" % output)
        # waagent -run-exthandlers -debug (v2.2.35)
        output = self.session.cmd_output(
            "timeout 3 waagent -run-exthandlers -debug")
        self.assertNotIn("is an orphan -- exiting", output,
                         "Should not exit as orphan")

    def test_run_waagent_command_under_events_folder(self):
        """
        :avocado: tags=tier2
        WALA-TC: [WALA function] Run waagent command under
                 /var/lib/waagent/events
        """
        self.log.info("[WALA function] Run waagent command \
                        under /var/lib/waagent/events")
        output = self.session.cmd_output(
            "cd /var/lib/waagent/events;waagent -version")
        self.assertIn(
            "Goal state agent", output,
            "Run waagent command under /var/lib/waagent/events is failed")

    def test_customize_waagent_conf_path(self):
        """
        :avocado: tags=tier2
        WALA-TC: [WALA function] the path of configuration file can be
                 customized
        1. Modify waagent.service; Move "/etc/waagent.conf" to
           "/root/waagent.conf"; Systemd daemon reload
        2. Deprovision this VM and use this as a template to create a new VM
        3. After the VM finishing provisioning,login and Check whether wala
           normally running
        """
        self.log.info(
            "WALA-TC: [func] the path of configuration file can be customized")
        self.log.info(
            "1. Modify waagent.service; Move /etc/waagent.conf to /root/\
waagent.conf; Systemd daemon reload")
        cmd_stop_waagent = "service waagent stop"
        status, output = self.session.cmd_status_output(cmd_stop_waagent)
        self.assertEqual(
            status, 0,
            "Fail to stop waagent service before test\n{}".format(str(output)))
        self.session.cmd_output("rm -f /var/log/waagent.log")
        self.session.cmd_output("mv /etc/waagent.conf /root/waagent.conf")
        if LooseVersion(self.vm.rhel_version) < LooseVersion("7.0"):
            waagent_service_file = "/etc/init.d/waagent"
            self.session.cmd_output(
                "sed -i '19s/-start/-configuration-path:\/root\/waagent.conf \
-start/' {0}".format(waagent_service_file))
            self.assertIn(
                "/root/waagent.conf",
                self.session.cmd_output(
                    "grep '$WAZD_BIN -configuration-path' {0}".format(
                        waagent_service_file)),
                "Fail to modify ConditionPathExists in waagent.service")
        else:
            waagent_service_file = "/usr/lib/systemd/system/waagent.service"
            self.session.cmd_output(
                "sed -i -e '/ExecStart/s/$/ -configuration-path:\/root\/\
waagent.conf&/g' -e 's/\/etc\/waagent.conf/\/root\/waagent.conf/g' {0}\
".format(waagent_service_file))
            self.assertIn(
                "-configuration-path:/root/waagent.conf",
                self.session.cmd_output(
                    "grep ExecStart {0}".format(waagent_service_file)),
                "Fail to modify ExecStart in waagent.service")
            self.assertIn(
                "/root/waagent.conf",
                self.session.cmd_output("grep ConditionPathExists {0}".format(
                    waagent_service_file)),
                "Fail to modify ConditionPathExists in waagent.service")
            self.session.cmd_output("systemctl daemon-reload")
        # Perform sync to let os write the file to disk right now.
        self.session.cmd_output("sync")
        self.log.info("2. Deprovision this VM and use this as a template to \
create a new VM")
        self.session.cmd_output("waagent -deprovision+user -configuration-path\
:/root/waagent.conf -force")
        # vm is running state is acceptable, ARM only.
        image_uri = self.vm.properties.get("storageProfile").get("osDisk").get(
            "vhd").get("uri")
        #
        self.old_vm = self.vm
        cloud = Setup(self.params, self.name)
        self.vm = cloud.vm
        self.vm.vm_name += "-recreate"
        self.vm.image = image_uri
        self.session = cloud.init_vm()
        del output, status
        status, output = self.session.cmd_status_output('sudo su -')
        self.assertEqual(status, 0,
                         "User [root] login failed\n{}".format(str(output)))
        self.log.info("3. After the VM finishing provisioning,login and Check \
whether wala normally running")
        del output
        output = self.session.cmd_output("ps aux|grep -E '(waagent|WAL)'")
        self.assertIn("waagent -daemon -configuration-path:/root/waagent.conf",
                      output,
                      "New waagent.conf file doesn't work for daemon process")
        self.assertIn(
            "-run-exthandlers -configuration-path:/root/waagent.conf", output,
            "New waagent.conf file doesn't work for run-exthandlers process")

    def test_waagent_daemon(self):
        """
        :avocado: tags=tier3
        RHEL7-41731	WALA-TC: [func] waagent -daemon
        1. Stop waagent service. Run "waagent -daemon &". Check process and log
        """
        self.session.cmd_output("service waagent stop")
        self.session.cmd_output("rm -f /var/log/waagent.log")
        ret = self.session.cmd_status_output(
            "timeout --preserve-status 10 waagent -daemon")
        self.assertEqual(0, ret[0],
                         "Fail to start waagent daemon process")
        error_logs = self._check_waagent_log()
        self.assertEqual("", error_logs,
                         "There are error logs in waagent.log")

    def test_waagent_show_configuration(self):
        """
        :avocado: tags=tier3
        RHEL7-98314	WALA-TC: [func] waagent -show-configuration
        """
        exit_status, output = self.session.cmd_status_output(
            "waagent -show-configuration")
        self.assertEqual(0, exit_status,
                         "Run waagent -show-configuration failed")
        new_conf = output.strip('\n').split('\n')
        file_conf = self.session.cmd_output(
            "cat /etc/waagent.conf|grep -Ev '(^ *$|^#)'|\
            sed -e 's/OS.OpensslPath=None/OS.OpensslPath=\/usr\/bin\/openssl/g'\
                -e 's/=y/=True/g'\
                -e 's/=n/=False/g'\
                -e 's/ *= */ = /g'").strip('\n').split('\n')
        with open("{}/data/azure/waagent_show_configuration".format(BASEPATH),
                  'r') as f:
            old_conf = f.read().split('\n')
        wrong_conf = []
        for line in file_conf:
            if line not in new_conf:
                wrong_conf.append(line)
        self.assertEqual(0, len(wrong_conf),
                         "There are mismatch configurations:\n{}".format('\n'.join(wrong_conf)))
        if set(new_conf) != set(old_conf):
            add = set(new_conf) - set(old_conf)
            rmv = set(old_conf) - set(new_conf)
            self.log.warn("Some configurations are changed:\n===Add:\n{}\n===Del:\n{}".format(
                '\n'.join(add), '\n'.join(rmv)))

    def test_interrupt_ctrl_c(self):
        """
        Interrupt "waagent -deprovision" by "ctrl -c"
        """
        self.log.info("Interrupt \"waagent -deprovision\" by \"ctrl -c\"")

        # Start 2 threads:
        # session1 is for running deprovision command and getting output
        # session2 is for getting pid and killing process,

        def session1(q):
            try:
                self.session1.cmd_output("waagent -deprovision", timeout=30)
            except Exception as e:
                self.log.error(
                    "'waagent -deprovision' is not killed. Exception: %s" %
                    str(e))
                q.put(str(e))
            q.put("0")

        def session2():
            time.sleep(5)
            pid = self.session.cmd_output(
                "ps aux|grep [d]eprovision|awk '{print $2}'")
            self.session.cmd_output("kill -2 {0}".format(pid)) if pid \
                else self.log.error("Cannot get 'waagent -deprovision' pid")

        import threading
        from Queue import Queue
        q = Queue()
        thread1 = threading.Thread(target=session1, args=(q, ))
        thread1.setDaemon(True)
        thread1.start()
        thread2 = threading.Thread(target=session2)
        thread2.setDaemon(True)
        thread2.start()
        thread1.join()
        output = q.get()
        q.task_done()
        self.log.info(output)
        self.assertEqual("0", output,
                         "Should not raise exception: %s" % output)

    def _check_waagent_log(self, ignore_list=None):
        with open("{}/data/azure/ignore_waagent_messages".format(BASEPATH),
                  'r') as f:
            ignore_message_list = f.read().split('\n')
        if ignore_list and type(ignore_list) is not list:
            raise RuntimeError("ignore_list should be a list,\
                                but you gave a {}".format(type(ignore_list)))
        elif ignore_list:
            ignore_list += ignore_message_list
        else:
            ignore_list = ignore_message_list
        return self._check_log("/var/log/waagent.log", ignore_list)

    def _check_log(self, log_file, ignore_list):
        if len(ignore_list) > 0:
            cmd = "cat {0} | grep -iE '(error|fail)' | grep -vE '({1})'\
".format(log_file, '|'.join(ignore_list))
        else:
            cmd = "cat {0} | grep -iE '(error|fail)'".format(log_file)
        return self.session.cmd_output(cmd)

    def tearDown(self):
        self.log.info("Do teardown")
        cmd_stop_waagent = "service waagent stop"
        cmd_start_waagent = "service waagent start"
        if "depro" in self.case_short_name:
            self.vm.delete()
        elif self.case_short_name == "test_customize_waagent_conf_path":
            self.old_vm.delete()
            self.vm.delete()
        elif self.case_short_name == "test_waagent_verbose" or \
                self.case_short_name == "test_waagent_run_exthandlers" or \
                self.case_short_name == "test_waagent_daemon":
            try:
                self.session.cmd_output(cmd_stop_waagent)
                self.session.cmd_output("rm -f /var/log/waagent*.log")
                self.session.cmd_output(cmd_start_waagent)
            except Exception as e:
                self.log.error("Teardown failed. {0}".format(e))
                self.vm.delete()
        elif self.case_short_name == "test_waagent_start":
            try:
                output = self.session.cmd_output('ps aux | grep [w]aagent')
                pid = output.split("root")[1].strip().split(" ")[0]
                self.session.cmd_output("kill -9 {}".format(pid))
                status, output = self.session.cmd_status_output(
                    cmd_start_waagent)
            except Exception as e:
                self.log.error("Teardown failed. {0}".format(e))
                self.vm.delete()
        # Clean ssh sessions
        # utils_misc.host_command("ps aux|grep '[s]sh -o UserKnownHostsFile'\
        # |awk '{print $2}'|xargs kill -9", ignore_status=True)
