import time
import re
import os
from avocado import Test
from avocado import main
from avocado_cloud.app import Setup
from avocado_cloud.app.azure import AzureAccount
from distutils.version import LooseVersion
from avocado_cloud.utils import utils_azure


class LifeCycleTest(Test):
    """
    :avocado: tags=wala,lifecycle
    """
    def setUp(self):
        account = AzureAccount(self.params)
        account.login()
        cloud = Setup(self.params, self.name)
        self.vm = cloud.vm
        pre_delete = False
        pre_stop = False
        self.case_short_name = re.findall(r"Test.(.*)", self.name.name)[0]
        if self.case_short_name == "test_create_vm_all":
            cloud.vm.vm_name += "-all"
            cloud.vm.authentication_type = "all"
            self.vm.create()
            self.session = cloud.init_session()
            return
        if self.case_short_name == "test_create_vm_password":
            self.vm.vm_name += "-password"
            self.vm.authentication_type = "password"
            self.vm.generate_ssh_keys = False
            self.vm.ssh_key_value = None
            self.vm.create()
            self.session = cloud.init_session()
            return
        if self.case_short_name == "test_create_vm_sshkey":
            if self.vm.exists():
                # self.vm.delete(wait=True)
                pass
            self.vm.create(wait=True)
            self.session = cloud.init_session()
        if self.case_short_name == "test_start_vm":
            pre_stop = True
        self.session = cloud.init_vm(pre_delete=pre_delete, pre_stop=pre_stop)

    def test_create_vm_sshkey(self):
        """
        :avocado: tags=tier1
        RHEL7-41652 WALA-TC: [life cycle] Create a VM with sshkey
        """
        self.assertTrue(self.session.connect(authentication="publickey"),
                        "Fail to login through sshkey")
        output = self.session.cmd_output("sudo cat /etc/sudoers.d/waagent")
        expect = "{0} ALL=(ALL) NOPASSWD: ALL".format(self.vm.vm_username)
        self.assertEqual(
            output, expect, "Wrong sudoer permission.\nExpect: {0}\n"
            "Real: {1}".format(expect, output))
        # Collect /var/log/cloud-init.log and /var/log/messages
        try:
            self.session.cmd_output("mkdir -p /tmp/logs")
            self.session.cmd_output(
                "sudo cp /var/log/waagent.log /tmp/logs/")
            self.session.cmd_output("sudo cp /var/log/messages /tmp/logs/")
            self.session.cmd_output("sudo chmod 644 /tmp/logs/*")
            host_logpath = os.path.dirname(self.job.logfile) + "/logs"
            utils_azure.command("mkdir -p {}".format(host_logpath))
            self.session.copy_files_from("/tmp/logs/*", host_logpath)
        except:
            pass

    def test_create_vm_password(self):
        """
        :avocado: tags=tier1
        RHEL-169439 WALA-TC: [life cycle] Create a VM with password
        """
        self.assertTrue(self.session.connect(authentication="password"),
                        "Fail to login through password")
        output = self.session.cmd_output("echo {}|sudo -S \"cat\" "
                                         "/etc/sudoers.d/waagent".format(
                                             self.vm.vm_password))
        expect = "{0} ALL=(ALL) ALL".format(self.vm.vm_username)
        self.assertIn(
            expect, output, "Wrong sudoer permission.\nExpect: {0}\n"
            "Real: {1}".format(expect, output))

    def test_create_vm_all(self):
        """
        :avocado: tags=tier2
        RHEL-169634 WALA-TC: [life cycle] Create a VM with both password and
                             sshkey
        """
        self.assertTrue(self.session.connect(authentication="password"),
                        "Fail to login through password")
        self.session.close()
        self.assertTrue(self.session.connect(authentication="publickey"),
                        "Fail to login through password")
        output = self.session.cmd_output("echo {}|sudo -S \"cat\" "
                                         "/etc/sudoers.d/waagent".format(
                                             self.vm.vm_password))
        expect = "{0} ALL=(ALL) ALL".format(self.vm.vm_username)
        self.assertIn(
            expect, output, "Wrong sudoer permission.\nExpect: {0}\n"
            "Real: {1}".format(expect, output))

    def test_start_vm(self):
        """
        :avocado: tags=tier1
        RHEL7-41653	WALA-TC: [life cycle] Start a VM
        """
        self.vm.start()
        self.vm.show()
        self.session.connect()
        output = self.session.cmd_output('whoami')
        self.assertEqual(
            self.vm.vm_username, output,
            "Start VM error: output of cmd `who` unexpected -> %s" % output)

    def test_stop_vm(self):
        """
        :avocado: tags=tier1
        RHEL7-41654	WALA-TC: [life cycle] Stop a VM
        """
        self.vm.stop()
        self.vm.show()
        self.assertTrue(
            self.vm.is_stopped(),
            "Stop VM error: VM status is not Stopped(dea`llocated)")

    def test_delete_vm(self):
        """
        :avocado: tags=tier1
        RHEL7-41656	WALA-TC: [life cycle] Delete a VM
        """
        self.vm.delete()
        self.assertFalse(self.vm.exists(), "Delete VM error: VM still exists")

    def test_restart_vm(self):
        """
        :avocado: tags=tier1
        RHEL7-41655	WALA-TC: [life cycle] Restart a VM
        restart VM through Azure CLI
        """
        self.log.info("RHEL7-41655 WALA-TC: [life cycle] Restart a VM")
        # Get the swap size before reboot
        swapsize_before = self.session.cmd_output("free -m|grep Swap|awk '{print $2}'")
        before = self.session.cmd_output("last reboot")
        self.log.info("Restart the vm %s", self.vm.vm_name)
        self.vm.reboot()
        self.session.close()
        # wait for restart finished
        self.assertTrue(self.session.connect(),
                        "Cannot login after rebooting VM")
        after = self.session.cmd_output("last reboot")
        if after == before:
            self.fail("VM is not restarted.")
        self.log.info("VM restart successfully.")
        # Check the swap
        # Disable default swap
        project = self.session.cmd_output(
            "cat /etc/redhat-release |tr -cd '[0-9.\n]'")
        if LooseVersion(project) < LooseVersion("7.0"):
            self.session.cmd_output(
                "sudo swapoff /dev/mapper/VolGroup-lv_swap")
        else:
            self.session.cmd_output("sudo swapoff /dev/mapper/rhel-swap")
        # Retry 10 times (100s in total) to wait for the swap file created.
        max_retry = 10
        for count in range(1, max_retry + 1):
            swapsize_after = self.session.cmd_output(
                "free -m|grep Swap|awk '{print $2}'")
            if swapsize_after == swapsize_before:
                break
            else:
                self.log.info("Swap size is wrong. Retry %d times." % count)
                time.sleep(10)
        else:
            self.fail("Swap size is incorrect after VM restart. Before:{}, After:{}".format(swapsize_before, swapsize_after))

    def test_reboot_vm_inside_guest(self):
        """
        :avocado: tags=tier2
        RHEL7-61482	WALA-TC: [life cycle] Reboot a VM inside guest
        reboot inside guest
        """
        self.log.info(
            "RHEL7-61482	WALA-TC: [life cycle] Reboot a VM inside guest")
        before = self.session.cmd_output("last reboot")
        self.log.info("Reboot the vm %s", self.vm.vm_name)
        self.session.send_line("sudo reboot\n")
        self.session.close()
        # wait for reboot finished
        time.sleep(20)
        self.assertTrue(self.session.connect(),
                        "Cannot login after reboot inside VM")
        after = self.session.cmd_output("last reboot")
        if after == before:
            self.fail("VM is not rebooted.")
        self.log.info("VM reboot inside guest successfully.")

    def test_create_vm_without_deprovision(self):
        """
        :avocado: tags=tier3
        VIRT-47119	WALA-TC: [life cycle] Create a VM without deprovision
        1. Prepare a VM. Add a user with ssh_key. Set root password.
        2. Don't deprovision. Capture as specialized image.
        3. Use the new image to create a VM. Check the old user/ssh_key, root password and hostname.
        """
        self.log.info("VIRT-47119 - WALA-TC: [life cycle] Create a VM without deprovision")
        self.session.cmd_output('sudo su -')
        ### Test begin
        root_pw = "RedHatTest1@"
        self.session.cmd_output("echo '{}' | passwd root --stdin".format(root_pw))
        old_username = self.vm.vm_username
        new_username = old_username+'new'
        # self.vm.vm_username = new_username
        self.vm_1, session_1 = utils_azure.recreate_vm(self, "nodepro", vm_username=new_username, connect=False)
        self.vm_1.vm_username = old_username
        self.assertTrue(session_1.connect(timeout=60),
            "Failed to use the old username to login")
        self.assertNotIn("LOCK", self.session.cmd_output("getent shadow root"),
            "root password should not be locked.")
        self.assertNotEqual(0, self.session.cmd_status_output("id "+new_username)[0],
            "The new user should not be created.")


    def tearDown(self):
        if self.case_short_name in [
            "test_create_vm_password",
            "test_create_vm_all",
        ]:
            self.vm.delete(wait=False)
        if self.case_short_name == "test_create_vm_without_deprovision":
            self.session.cmd_output("sed -i -e '1i root:*LOCK*:14600::::::' -e '/root/d' /etc/shadow")
            self.vm_1.delete(wait=False)


if __name__ == "__main__":
    main()
