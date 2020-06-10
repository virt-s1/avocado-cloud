import time
from avocado import Test
from avocado_cloud.app import Setup
from avocado_cloud.app.azure import AzureAccount


class AzureMemory(Test):
    '''
    This case need to run 1h
    '''
    def setUp(self):
        self.casestatus = False
        account = AzureAccount(self.params)
        account.login()
        cloud = Setup(self.params, self.name)
        self.vm = cloud.vm
        self.session = cloud.init_vm()
        status, output = self.session.cmd_status_output('sudo su -')
        self.assertEqual(status, 0,
                         "User [root] login failed\n{}".format(str(output)))
        status, output = self.session.cmd_status_output(
            'rpm -qa | grep rhui-azure')
        if status != 0:
            status, output = self.session.cmd_status_output(
                'rpm -ivh `ls /root/rhui-azure*`')
            self.assertEqual(status, 0, "Failed to install rhui-azure")
        status, output = self.session.cmd_status_output(
            'yum -y install git gcc make expect', timeout=400)
        self.assertEqual(status, 0, "Failed to install gcc,git,make,expect")
        status, output = self.session.cmd_status_output(
            'git clone https://github.com/julman99/eatmemory.git \
&& cd eatmemory && make install',
            timeout=300)
        self.assertEqual(status, 0, "Failed to install eatmemory")
        status, output = self.session.cmd_status_output("free")
        self.assertEqual(status, 0, "Failed to get VM's memory")
        self.log.info("[PRE-TEST] OS memory is:\n\n{}".format(output))
        status, output = self.session.cmd_status_output("free -g | \
grep 'Mem' | awk -F 'Mem:' '{print $2}' | awk -F ' ' '{print $1}'")
        self.assertEqual(status, 0, "Failed to get VM's memory")
        target_memory = str(int(output.strip()) / 3)
        script_content = [
            'spawn eatmemory {}G'.format(target_memory), 'expect "Done"',
            'send "a\\r"'
        ]
        script_path = "/tmp/testmemory.expect"
        with open(script_path, "w+") as f:
            for content in script_content:
                f.write(content + "\n")
        self.session.copy_files_to(local_path=script_path,
                                   remote_path=script_path)
        script_content = "while true; do expect /tmp/testmemory.expect; done"
        script_path = "/tmp/run.sh"
        with open(script_path, "w+") as f:
            f.write(script_content + "\n")
        self.session.copy_files_to(local_path=script_path,
                                   remote_path=script_path)
        status, output = self.session.cmd_status_output(
            "chmod +x {}".format(script_path))
        self.assertEqual(
            status, 0,
            "Failed to assign execute permission for file {}".format(
                script_path))
        status, output = self.session.cmd_status_output(
            'echo "/tmp/run.sh" >> /etc/rc.d/rc.local')
        self.assertEqual(status, 0, "Failed to write command to rc.local")
        self.session.cmd_output("chmod +x /etc/rc.local")
        self.session.send_line("reboot")
        time.sleep(30)
        self.session.connect()
        status, output = self.session.cmd_status_output('sudo su -')
        self.assertEqual(status, 0,
                         "User [root] login failed\n{}".format(str(output)))
        status, output = self.session.cmd_status_output(
            'ps aux | grep eatmemory | grep -v "grep"')
        self.assertEqual(status, 0, "Failed to start eatmemory")

    def test_memory(self):
        time.sleep(3600)
        self.session.connect()
        status, output = self.session.cmd_status_output('sudo su -')
        self.assertEqual(status, 0,
                         "User [root] login failed\n\n{}".format(str(output)))
        status, output = self.session.cmd_status_output("free")
        self.assertEqual(status, 0, "Failed to get VM's memory")
        self.log.info("[POST-TEST] OS memory is:\n{}".format(output))
        self.casestatus = True

    def tearDown(self):
        if self.casestatus is True:
            cmd = "sed -i 's/\/tmp\/run.sh//g' /etc/rc.d/rc.local"
            self.session.cmd_output(cmd)
            cmd = "rm /root/eatmemory -rf"
            self.session.cmd_output(cmd)
            self.session.cmd_output('chmod -x /etc/rc.local')
            self.session.send_line("reboot")
        else:
            self.vm.delete()
