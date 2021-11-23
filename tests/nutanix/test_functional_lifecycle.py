from avocado import Test
from avocado_cloud.app import Setup
import time


class LifeCycleTest(Test):
    def setUp(self):
        self.cloud = Setup(self.params, self.name)
        self.vm = self.cloud.vm
        pre_delete = False
        pre_stop = False
        if self.name.name.endswith("test_create_vm_password"):
            if self.vm.exists():
                self.vm.delete(wait=True)
            self.session = self.cloud.init_session()
            return
        if self.name.name.endswith("test_create_vm_sshkey"):
            pre_delete = True
        if self.name.name.endswith("test_start_vm"):
            pre_stop = True
        self.session = self.cloud.init_vm(pre_delete=pre_delete,
                                          pre_stop=pre_stop)

    def test_create_vm_password(self):
        self.vm.ssh_pubkey = None
        self.vm.create(wait=True)
        if self.vm.is_stopped():
            self.vm.start(wait=True)
        self.session.connect(authentication="password")
        output = self.session.cmd_output('whoami')
        self.assertEqual(
            self.vm.vm_username, output, "Create VM with password error: \
output of cmd `who` unexpected -> %s" % output)

    def test_create_vm_sshkey(self):
        output = self.session.cmd_output('whoami')
        self.assertEqual(
            self.vm.vm_username, output,
            "Create VM with sshkey error: output of cmd `who` unexpected -> %s"
            % output)

    def test_start_vm(self):
        self.vm.start(wait=True)
        self.session.connect(timeout=300)
        output = self.session.cmd_output('whoami')
        self.assertEqual(
            self.vm.vm_username, output,
            "Start VM error: output of cmd `who` unexpected -> %s" % output)

    def test_reboot_vm(self):
        before = self.session.cmd_output('last reboot')
        self.vm.reboot(wait=True)
        self.session.connect(timeout=300)
        output = self.session.cmd_output('whoami')
        self.assertEqual(
            self.vm.vm_username, output,
            "Reboot VM error: output of cmd `who` unexpected -> %s" % output)
        after = self.session.cmd_output('last reboot')
        self.assertNotEqual(
            before, after,
            "Reboot VM error: before -> %s; after -> %s" % (before, after))

    def test_reboot_inside_vm(self):
        before = self.session.cmd_output('last reboot')
        self.session.send_line('sudo reboot')
        time.sleep(10)
        self.session.connect(timeout=300)
        output = self.session.cmd_output('whoami')
        self.assertEqual(
            self.vm.vm_username, output,
            "Reboot VM error: output of cmd `who` unexpected -> %s" % output)
        after = self.session.cmd_output('last reboot')
        self.assertNotEqual(
            before, after,
            "Reboot VM error: before -> %s; after -> %s" % (before, after))

    def test_stop_vm(self):
        self.vm.stop(wait=True)
        self.assertTrue(self.vm.is_stopped(),
                        "Stop VM error: VM status is not SHUTOFF")

    def test_delete_vm(self):
        self.vm.delete(wait=True)
        self.assertFalse(self.vm.exists(), "Delete VM error: VM still exists")

    def tearDown(self):
        if self.name.name.endswith("create_vm_password"):
            self.vm.delete(wait=True)
        self.session.close()
