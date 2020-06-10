from avocado import Test
from avocado_cloud.app import Setup
from avocado_cloud.app.azure import AzureAccount


class AzureVmbus(Test):
    def setUp(self):
        account = AzureAccount(self.params)
        account.login()
        vm_size = "D3"
        cloud = Setup(self.params, self.name, size=vm_size)
        self.vm = cloud.vm
        self.session = cloud.init_vm()
        status, output = self.session.cmd_status_output('sudo su -')
        self.assertEqual(status, 0,
                         "User [root] login failed\n{}".format(str(output)))

    def test_version(self):
        cmd_version = "dmesg | grep 'Vmbus version' | awk -F 'Vmbus version:' \
'{print $2}'"

        output_version = self.session.cmd_output(cmd_version)
        self.assertIn(
            output_version, ["3.0", "4.0"],
            "vmbus version doesn't match\nActual vmbus version is [{}]".format(
                output_version))
        cmd_log = 'dmesg| grep -i vmbus | egrep -i "error|fail"'
        output_log = self.session.cmd_output(cmd_log)
        self.assertEqual(
            len(output_log), 0,
            "There are error log about vmbus\n{}".format(output_log))

    def test_interrupt(self):
        cmd = 'cat /proc/interrupts | grep "HYP" | sed "s/HYP://g" | \
sed "s/Hyper.*$//g"'

        output = self.session.cmd_output(cmd)
        # convert string to int
        output = [int(x) for x in output.strip().split()]
        self.assertNotIn(0, output,
                         "Interrupt distribution doesn't among all cpus")
