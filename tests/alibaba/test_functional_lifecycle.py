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

    # TODO Add test_modify_instance_type for Alibaba cloud
    def test_create_vm_password(self):
        import base64
        user_data = """\
#cloud-config

user: {0}
password: {1}
chpasswd: {{ expire: False }}

ssh_pwauth: 1
""".format(self.vm.vm_username, self.vm.vm_password)
        # Set timeout for Alibaba baremetal
        if 'ecs.ebm' in self.vm.flavor:
            connect_timeout = 600
        else:
            connect_timeout = 120

        self.vm.user_data = base64.b64encode(user_data.encode())
        self.vm.keypair = None
        self.vm.create(wait=True)
        if self.vm.is_stopped():
            self.vm.start(wait=True)
        self.session.connect(authentication="password",
                             timeout=connect_timeout)
        output = self.session.cmd_output('whoami')
        self.assertEqual(
            self.vm.vm_username, output, "Create VM with password error: \
output of cmd `who` unexpected -> %s" % output)

        # Test change password
        self.vm.vm_password = "Redhat123$"
        self.vm.reset_password(new_password=self.vm.vm_password)
        self.vm.reboot(wait=True)
        self.session = self.cloud.init_session()
        self.session.connect(authentication="password",
                             timeout=connect_timeout)
        output = self.session.cmd_output('whoami')
        self.assertEqual(
            self.vm.vm_username, output, "Start VM error after change \
password: output of cmd `who` unexpected -> %s" % output)

    def test_create_vm_sshkey(self):
        output = self.session.cmd_output('whoami')
        self.assertEqual(
            self.vm.vm_username, output,
            "Create VM with sshkey error: output of cmd `who` unexpected -> %s"
            % output)

    def test_start_vm(self):
        # Set timeout for Alibaba baremetal
        if 'ecs.ebm' in self.vm.flavor:
            connect_timeout = 600
        else:
            connect_timeout = 120

        self.vm.start(wait=True)
        self.session.connect(timeout=connect_timeout)
        output = self.session.cmd_output('whoami')
        self.assertEqual(
            self.vm.vm_username, output,
            "Start VM error: output of cmd `who` unexpected -> %s" % output)

    def test_pause_unpause_vm(self):
        self.vm.pause(wait=True)
        self.vm.unpause(wait=True)
        output = self.session.cmd_output('whoami')
        self.assertEqual(
            self.vm.vm_username, output,
            "Pause/Unpause VM error: output of cmd `who` unexpected -> %s" %
            output)

    def test_reboot_vm(self):
        # Set timeout for Alibaba baremetal
        if 'ecs.ebm' in self.vm.flavor:
            connect_timeout = 600
        else:
            connect_timeout = 120

        before = self.session.cmd_output('last reboot')
        self.vm.reboot(wait=True)
        self.session.connect(timeout=connect_timeout)
        output = self.session.cmd_output('whoami')
        self.assertEqual(
            self.vm.vm_username, output,
            "Reboot VM error: output of cmd `who` unexpected -> %s" % output)
        after = self.session.cmd_output('last reboot')
        self.assertNotEqual(
            before, after,
            "Reboot VM error: before -> %s; after -> %s" % (before, after))

    def test_reboot_inside_vm(self):
        # Set timeout for Alibaba baremetal
        if 'ecs.ebm' in self.vm.flavor:
            connect_timeout = 600
        else:
            connect_timeout = 120

        before = self.session.cmd_output('last reboot')
        self.session.send_line('sudo reboot')
        time.sleep(10)
        self.session.connect(timeout=connect_timeout)
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
