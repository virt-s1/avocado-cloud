import os
import time
import re
from avocado import Test
from avocado import main
from avocado_cloud.app import Setup
from avocado_cloud.app.azure import AzureAccount
from distutils.version import LooseVersion


class SettingsTest(Test):
    """
    :avocado: tags=wala,settings
    """

    def setUp(self):
        account = AzureAccount(self.params)
        account.login()
        self.case_short_name = re.findall(r"Test.(.*)", self.name.name)[0]
        self.project = self.params.get("rhel_ver", "*/VM/*")
        if LooseVersion(self.project) == LooseVersion("8.0.0") or \
                LooseVersion(self.project) == LooseVersion("8.0"):
            self.cancel(
                "Azure Linux Extensions are not supported in RHEL-8.0. Skip.")
        cloud = Setup(self.params, self.name)
        self.vm = cloud.vm
        self.session = cloud.init_vm()
        self.session.cmd_output("sudo su -")
        self.username = self.vm.vm_username
        self.new_username = self.username + "new"

    def test_reset_existing_sshkey(self):
        """
        :avocado: tags=tier2
        Reset an existing user ssh key
        """
        self.log.info("Reset an existing user ssh key")
        # Create new user
        self.session.cmd_output("userdel -rf {}".format(self.new_username))
        self.session.cmd_output("useradd {}".format(self.new_username))
        # Reset ssh key
        homepath = os.path.expanduser("~")
        with open("{}/.ssh/id_rsa.pub".format(homepath), 'r') as f:
            sshkey_value = f.read().strip('\n')
        self.vm.user_update(username=self.new_username,
                            ssh_key_value=sshkey_value)
        self.session.close()
        self.vm.vm_username = self.new_username
        self.assertTrue(
            self.session.connect(timeout=60),
            "Fail to reset ssh key: cannot login with new ssh key")
        self.log.info("Reset ssh key successfully")

    def test_reset_existing_password(self):
        """
        :avocado: tags=tier2
        Reset an existing user's password
        """
        self.log.info("Reset an existing user's password")
        # Create a new user with password
        self.session.cmd_output("userdel -rf {}".format(self.new_username))
        self.session.cmd_output("useradd {}".format(self.new_username))
        self.session.cmd_output(
            "sed -i 's/^PasswordAuthentication.*"
            "/PasswordAuthentication=no/g' /etc/ssh/sshd_config")
        self.session.cmd_output("service sshd restart")
        # Reset password
        self.vm.user_update(username=self.new_username,
                            password=self.vm.vm_password)
        self.vm.vm_username = self.new_username
        self.assertTrue(
            self.session.connect(timeout=60, authentication="password"),
            "Fail to reset password: cannot login with new password")
        self.log.info("Reset password successfully")

    def test_reset_remote_access(self):
        """
        :avocado: tags=tier2
        Reset remote access
        """
        self.log.info("Reset remote access")
        # Prepare environment
        self.session.cmd_output("userdel -rf {}".format(self.new_username))
        self.session.cmd_output("useradd -p $(openssl passwd -1 {}) {}".format(
            self.vm.vm_password, self.new_username))
        self.session.cmd_output(
            "sed -i 's/^PasswordAuthentication.*"
            "/PasswordAuthentication=no/g' /etc/ssh/sshd_config")
        self.session.cmd_output("rm -f /etc/ssh/sshd_config_*")
        self.session.cmd_output("service sshd restart")
        # Reset remote access
        self.vm.user_reset_ssh()
        self.assertEqual(
            self.session.cmd_status_output("[ -f /etc/ssh/sshd_config_* ]")[0],
            0, "Did not make a backup of sshd_config file")
        self.vm.vm_username = self.new_username
        self.assertTrue(
            self.session.connect(timeout=50, authentication="password"),
            "Fail to login through password after reset ssh configuration")

    def test_add_new_user(self):
        """
        :avocado: tags=tier2
        Add a new user
        """
        self.log.info("Add a new user")
        # Remove new user
        self.session.cmd_output("userdel -rf {}".format(self.new_username))
        # Add new user with extension
        homepath = os.path.expanduser("~")
        with open("{}/.ssh/id_rsa.pub".format(homepath), 'r') as f:
            sshkey_value = f.read().strip('\n')
        self.vm.user_update(username=self.new_username,
                            ssh_key_value=sshkey_value)
        self.session.close()
        self.vm.vm_username = self.new_username
        self.assertTrue(self.session.connect(timeout=60),
                        "Fail to login with the new user")
        self.log.info("Create new user successfully")

    def test_run_command_shell_script(self):
        """
        :avocado: tags=tier2
        RHEL-170532 WALA-TC: [Settings] Run command (shell script)
        1. Run "run command RunShellScript"
        # az vm run-command invoke -g MyResourceGroup -n MyVm --command-id \
          RunShellScript --scripts 'echo $1 $2' --parameters hello world
        2. Check if can get command output "hello world"
        """
        self.log.info("RHEL-170532 WALA-TC: [Settings] Run command")
        scripts = "echo $1 $2"
        parameters = "hello world"
        self.assertRegexpMatches(
            self.vm.run_command(scripts=scripts, parameters=parameters),
            ".*hello world.*", "Fail to run shell script command")
        self.log.info("Run shell script command successfully")

    def test_run_command_ifconfig(self):
        """
        :avocado: tags=tier2
        RHEL-170533 WALA-TC: [Settings] Run command (ifconfig)
        1. Run "run command RunShellScript"
        # az vm run-command invoke -g MyResourceGroup -n MyVm --command-id \
          ifconfig
        2. Check if can get "ifconfig" output
        """
        self.log.info("RHEL-170533 WALA-TC: [Settings] Run command")
        self.assertRegexpMatches(self.vm.run_command(command_id="ifconfig"),
                                 ".*eth0.*", "Fail to run ifconfig command")
        self.log.info("Run ifconfig command successfully")

    def test_extension_uninstall(self):
        """
        :avocado: tags=tier2
        WALA-TC: [Settings] Extension uninstall
        1. Reset remote access to install the VMAccessForLinux extension
        2. Uninstall extension
        3. Login VM. Check extension
        """
        self.log.info("WALA-TC: [Settings] Extension uninstall")
        if self.session.cmd_output(
                "cat /var/lib/waagent/"
                "Microsoft.OSTCExtensions.VMAccessForLinux-*"
                "/config/HandlerState;echo") != "Enabled":
            self.log.info("No extension installed. Install extension.")
            self.vm.user_reset_ssh()
            max_retry = 10
            for retry in range(0, max_retry):
                if self.session.cmd_output(
                        "cat /var/lib/waagent/"
                        "Microsoft.OSTCExtensions.VMAccessForLinux-*"
                        "/config/HandlerState;echo") == "Enabled":
                    break
                time.sleep(10)
                self.log.info("Wait for Extension installed. "
                              "Retry ({0}/{1})".format(retry + 1, max_retry))
            else:
                self.error("Fail to install Extension. Exit.")
        self.log.info("2. Uninstall extension")
        self.vm.extension_delete(name="enablevmaccess")
        self.assertNotEqual(
            self.session.cmd_status_output(
                "ls -ld /var/lib/waagent/"
                "Microsoft.OSTCExtensions*|grep ^d")[0], 0,
            "Extension folder is not removed")

    def test_extension_cleanup_if_invalid(self):
        """
        :avocado: tags=tier2
        WALA-TC: [Settings] Extension clean up if status is not valid
        1. Prepare a VM on Azure with an extension installed
        2. Login VM. Remove status file:
           /var/lib/waagent/Microsoft.OSTCExtensions.\
               VMAccessForLinux-*/config/HandlerState
           check if /var/lib/waagent/Microsoft.OSTCExtensions.\
               VMAccessForLinux-* is removed.
        """
        self.log.info("Extension clean up if status is not valid")
        if self.session.cmd_output(
                "cat /var/lib/waagent/"
                "Microsoft.OSTCExtensions.VMAccessForLinux-*"
                "/config/HandlerState;echo") != "Enabled":
            self.log.info("No extension installed. Install extension.")
            self.vm.user_reset_ssh()
            max_retry = 10
            for retry in range(0, max_retry):
                if self.session.cmd_output(
                        "cat /var/lib/waagent/"
                        "Microsoft.OSTCExtensions.VMAccessForLinux-*"
                        "/config/HandlerState;echo") == "Enabled":
                    break
                time.sleep(10)
                self.log.info("Wait for Extension installed. "
                              "Retry ({0}/{1})".format(retry + 1, max_retry))
            else:
                self.error("Fail to install Extension. Exit.")
        self.log.info("2. Login VM. Remove status file and check")
        self.session.cmd_output(
            "rm -f /var/lib/waagent/"
            "Microsoft.OSTCExtensions.VMAccessForLinux-*/config/HandlerState")
        time.sleep(5)
        self.assertNotIn(
            "Microsoft.OSTCExtensions",
            self.session.cmd_output("ls -ld /var/lib/waagent/"
                                    "Microsoft.OSTCExtensions*|grep ^d"),
            "Extension folder is not removed")

    def tearDown(self):
        self.vm.vm_username = self.username
        if not self.session.connect(timeout=30):
            self.vm.delete()
            return
        self.session.cmd_output("sudo userdel -rf {}new".format(self.username))
        if self.case_short_name == "test_reset_existing_password":
            self.session.cmd_output(
                "sudo sed -i 's/^PasswordAuthentication.*"
                "/PasswordAuthentication=no/g' /etc/ssh/sshd_config")
            self.session.cmd_output("sudo service sshd restart")


'''
    def test_reset_access_successively(self):
        """
        Reset remote access successively
        """
        self.log.info("Reset remote access successively")
        # 1. First time
        self.log.info("The first time")
        # Prepare environment
        self.vm.modify_value("PasswordAuthentication", "no",
                             "/etc/ssh/sshd_config", ' ')
        self.vm.modify_value("ChallengeResponseAuthentication", "no",
                             "/etc/ssh/sshd_config", ' ')
        self.session.cmd_output("service sshd restart")
        self.assertFalse(self.vm.verify_alive(timeout=5),
                         "Prepare environment failed")
        self.session.cmd_output("rm -f /etc/ssh/sshd_config_*")
        # Reset remote access
        self.assertEqual(self.vm.reset_remote_access(version="1.4"), 0,
                         "Fail to reset remote access: azure cli fail")
        self.assertTrue(
            self.vm.verify_alive(timeout=50),
            "Fail to reset remote access: cannot login to the vm: First time")
        self.assertTrue(
            self.vm.verify_value("PasswordAuthentication", "yes",
                                 "/etc/ssh/sshd_config", ' '),
            "Fail to reset sshd_config file: PasswordAuthentication is not \
yes: First time")
        self.assertTrue(
            self.vm.verify_value("ChallengeResponseAuthentication", "no",
                                 "/etc/ssh/sshd_config", ' '),
            "Fail to reset sshd_config file: ChallengeResponseAuthentication \
is not no: First time")
        self.assertEqual(
            '1', self.session.cmd_output("ls -l /etc/ssh/sshd_config_*|wc -l"),
            "Did not make a backup of sshd_config file: First time")
        # 2. Second time
        self.log.info("The second time")
        # Prepare environment
        self.vm.modify_value("PasswordAuthentication", "no",
                             "/etc/ssh/sshd_config", ' ')
        self.vm.modify_value("ChallengeResponseAuthentication", "no",
                             "/etc/ssh/sshd_config", ' ')
        self.session.cmd_output("service sshd restart")
        self.assertFalse(self.vm.verify_alive(timeout=5),
                         "Prepare environment failed")
        # Reset remote access
        self.assertEqual(self.vm.reset_remote_access(version="1.4"), 0,
                         "Fail to reset remote access: azure cli fail")
        self.assertTrue(
            self.vm.verify_alive(timeout=50), "Bug 1324307. "
            "Fail to reset remote access: cannot login to the vm: Second time")
        self.assertTrue(
            self.vm.verify_value("PasswordAuthentication", "yes",
                                 "/etc/ssh/sshd_config", ' '),
            "Fail to reset sshd_config file: PasswordAuthentication is not \
yes: Second time")
        self.assertTrue(
            self.vm.verify_value("ChallengeResponseAuthentication", "no",
                                 "/etc/ssh/sshd_config", ' '),
            "Fail to reset sshd_config file: ChallengeResponseAuthentication \
is not no: Second time")
        self.assertEqual(
            '2', self.session.cmd_output("ls -l /etc/ssh/sshd_config_*|wc -l"),
            "Did not make a backup of sshd_config file: Second time")

    def test_reset_pw_after_capture(self):
        """
        Reset password after capture
        """
        self.log.info("Reset password after capture")
        # 1. Prepare environment
        old_username = self.vm_params["username"]
        old_password = self.vm_params["password"]
        new_username = self.vm_params["username"] + "new"
        new_password = self.vm_params["password"] + "new"
        # reset password
        self.assertEqual(
            self.vm.reset_password(username=old_username,
                                   password=old_password,
                                   method="password",
                                   version="1.4"), 0,
            "Fail to reset password before capture")
        # Sleep 10s to wait for the extension downloading and installing
        time.sleep(10)
        self.assertTrue(
            self.vm.verify_alive(username=old_username,
                                 password=old_password,
                                 timeout=50))
        # capture and create VM
        vm_image_name = self.vm.name + "-rstpwac" + self.vm.postfix()
        self.assertEqual(self.vm.shutdown(), 0, "Fail to shutdown VM")
        self.assertTrue(self.vm.wait_for_deallocated(), "VM is not shutdown")
        cmd_params = dict()
        cmd_params["os_state"] = "Specialized"
        self.assertEqual(self.vm.capture(vm_image_name, cmd_params), 0,
                         "Fail to capture the vm: azure cli fail")
        self.assertEqual(self.vm.delete(), 0,
                         "Fail to delete old vm: azure cli fail")
        self.assertTrue(self.vm.wait_for_delete(),
                        "Fail to delete old vm: cannot delete")
        self.vm_params["Image"] = vm_image_name
        self.assertEqual(self.vm.vm_create(self.vm_params), 0,
                         "Fail to create new VM base on capture image")
        self.assertTrue(self.vm.wait_for_running(),
                        "VM status cannot become running")
        self.assertTrue(
            self.vm.verify_alive(username=old_username, password=old_password))
        time.sleep(25)
        # 2. Reset password again
        self.assertEqual(
            self.vm.reset_password(username=new_username,
                                   password=new_password,
                                   method="password",
                                   version="1.4"), 0,
            "Fail to reset password after capture: azure cli fail")
        self.assertTrue(
            self.vm.verify_alive(username=new_username,
                                 password=new_password,
                                 timeout=50), "Bug 1323905. "
            "Fail to reset password after capture: cannot login")

    def test_resize_vm(self):
        """
        Resize the VM
        """
        self.log.info("Resize the VM")
        new_size = "A3"
        new_sizename = self.params.get("name", "*/vm_sizes/%s/*" % "A3")
        goal_cpu = str(self.params.get("cpu", "*/vm_sizes/%s/*" % new_size))
        goal_memory = int(
            self.params.get("memory", "*/vm_sizes/%s/*" % new_size)) * 1024
        goal_disk_size = self.params.get("disk_size", "*/%s/*" % new_size)
        self.assertEqual(self.vm.vm_resize(new_sizename), 0,
                         "Fail to resize the VM: azure cli fail")
        self.assertTrue(self.vm.wait_for_running(),
                        "Fail to resize the VM: cannot start")
        self.assertTrue(self.vm.verify_alive(),
                        "Fail to resize the VM: cannot login")
        real_cpu = self.session.cmd_output(
            "cat /proc/cpuinfo| grep processor| wc -l")
        self.assertEqual(
            goal_cpu, real_cpu,
            "Fail to resize the VM: cpu number is wrong. Goal: %s Real: %s" %
            (goal_cpu, real_cpu))
        real_memory = int(
            self.session.cmd_output(
                "free -m | grep Mem | awk '\"'{print $2}'\"'"))
        delta = int(goal_memory * 0.10)
        self.log.info(delta)
        self.assertAlmostEqual(
            goal_memory,
            real_memory,
            delta=delta,
            msg="Fail to resize the VM: memory is wrong. Goal: %sM Real: %sM" %
            (goal_memory * 1024, real_memory))
        real_disk_size = int(
            self.session.cmd_output("fdisk -l|grep sdb:|awk '\"'{print $5}'\"'"
                                    )) / 1024 / 1024 / 1024
        self.assertEqual(
            goal_disk_size, real_disk_size,
            "Fail to resize the VM: disk size is wrong. Goal: %sG Real: %sG" %
            (goal_disk_size, real_disk_size))
        self.log.info("Resize the VM successfully")
'''

if __name__ == "__main__":
    main()
