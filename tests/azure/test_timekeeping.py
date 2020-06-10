import time
from avocado import Test
from avocado_cloud.app import Setup
from avocado_cloud.app.azure import AzureAccount


class AzureTimeKeeping(Test):
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
        if self.name.name.endswith("test_chrony"):
            status, output = self.session.cmd_status_output(
                'systemctl is-enabled chronyd')
            self.assertEqual(status, 0, "There isn't chrony installed")
            self.assertEqual(output.strip(), "enabled", "Chrony isn't enabled")
        elif self.name.name.endswith("test_clocksource_performance"):
            status, output = self.session.cmd_status_output('which gcc')
            if status != 0:
                status, output = self.session.cmd_status_output(
                    'rpm -qa | grep rhui-azure')
                if status != 0:
                    status, output = self.session.cmd_status_output(
                        'rpm -ivh `ls /root/rhui-azure*`')
                    self.assertEqual(status, 0, "Failed to install rhui-azure")
                status, output = self.session.cmd_status_output(
                    'yum -y install gcc', timeout=400)
                self.assertEqual(status, 0, "Failed to install gcc")

    def test_chrony(self):
        status, output = self.session.cmd_status_output(
            "sed -i 's/^makestep.*$/makestep 10 6/g' /etc/chrony.conf")
        self.assertEqual(status, 0, "Failed to modify chrony conf file")
        self.session.cmd_output('echo "" > /var/log/messages')
        status, output = self.session.cmd_status_output(
            'systemctl restart chronyd')
        self.assertEqual(status, 0, "Failed to restart chrony")
        time.sleep(30)
        current_time = self.session.cmd_output('date +"%s"')
        # Modify time to 10 mins later
        target_time = str(int(current_time) + 630)
        format_time = self.session.cmd_output(
            'date -d @{} +"%Y%m%d %H:%M:%S"'.format(target_time))
        status, output = self.session.cmd_status_output(
            "date -s '{}'".format(format_time))
        self.assertEqual(status, 0, "Failed to modify system time")
        cmd = "cat /var/log/messages| grep 'System clock was stepped by'| awk \
-F ']:' '{print $2}' | awk -F 'by -' '{print $2}' | awk -F ' ' '{print $1}'"

        for interval in [300, 180, 120]:
            time.sleep(interval)
            status, output = self.session.cmd_status_output(cmd)
            self.assertEqual(status, 0, "Failed to execute command")
            if len(output):
                stepby_time = output.strip().split()
                for item in stepby_time:
                    ret = 400 < int(float(item)) < 800
                    if ret is True:
                        self.casestatus = True
                        break
            if self.casestatus is True:
                break
        self.assertEqual(self.casestatus, True, "Failed to sync time")

    def test_clocksource_performance(self):
        script_content = [
            "#include <time.h>", "main()", "{ int rc;", "long i;",
            "struct timespec ts;", "for(i=0; i<100000000; i++)",
            "{ rc = clock_gettime(CLOCK_MONOTONIC, &ts); }  }"
        ]
        script_path = "/tmp/clock_gettime.c"
        with open(script_path, "w+") as f:
            for content in script_content:
                f.write(content + "\n")
        self.session.copy_files_to(local_path=script_path,
                                   remote_path=script_path)
        status, output = self.session.cmd_status_output(
            "gcc {} -o /tmp/clock".format(script_path))
        self.assertEqual(status, 0, "Failed to compile")
        status, output = self.session.cmd_status_output("cat \
/sys/devices/system/clocksource/clocksource0/current_clocksource")
        self.assertEqual(status, 0, "Failed to get current clocksource")
        self.assertEqual(
            output.strip(), "hyperv_clocksource_tsc_page",
            "Current clocksource isn't hyperv_clocksource_tsc_page\n{}".format(
                output.strip()))
        status, output = self.session.cmd_status_output("time /tmp/clock")
        self.assertEqual(status, 0, "Failed to execute program")

    def test_unbind_clocksource(self):
        cmd = "cat /sys/devices/system/clocksource/clocksource0/\
current_clocksource"

        status, output = self.session.cmd_status_output(cmd)
        self.assertEqual(status, 0, "Failed to get current clocksource")
        self.assertEqual(
            output.strip(), u"hyperv_clocksource_tsc_page",
            "Current clocksource isn't hyperv_clocksource_tsc_page\n{}".format(
                output.strip()))
        cmd = "cat /sys/devices/system/clocksource/clocksource0/\
available_clocksource"

        status, output = self.session.cmd_status_output(cmd)
        self.assertEqual(status, 0, "Failed to get available clocksource")
        cmd = "echo hyperv_clocksource_tsc_page > /sys/devices/system/\
clocksource/clocksource0/unbind_clocksource"

        status, output = self.session.cmd_status_output(cmd)
        self.assertEqual(status, 0, "Failed to unbind clocksource")
        cmd = "cat /sys/devices/system/clocksource/clocksource0/\
current_clocksource"

        status, output = self.session.cmd_status_output(cmd)
        self.assertEqual(status, 0, "Failed to get current clocksource")
        self.assertNotEqual(output.strip(), u'hyperv_clocksource_tsc_page',
                            "Failed to change to another clocksource")
        cmd = "dmesg | grep clock | egrep -i 'fail|error'"
        output = self.session.cmd_output(cmd)
        self.assertEqual(
            len(output), 0,
            "There are errors in dmesg about clocksource\n{}".format(
                output.strip()))

    def test_check_clocksource(self):
        # Check CPU vendor,not can only support Intel CPU
        cmd = "lscpu | grep 'Vendor ID:' | awk -F ' ' '{print $3}'"
        status, output = self.session.cmd_status_output(cmd)
        self.assertEqual(status, 0, "Failed to get vendor id")
        self.assertEqual(output.strip(), u'GenuineIntel',
                         "CPU is not Intel,now this case only support Intel")
        cmd = "cat /sys/devices/system/clocksource/clocksource0/\
current_clocksource"

        status, output = self.session.cmd_status_output(cmd)
        self.assertEqual(status, 0, "Failed to get current clocksource")
        self.assertEqual(
            output.strip(), u"hyperv_clocksource_tsc_page",
            "Current clocksource isn't hyperv_clocksource_tsc_page\n{}".format(
                output.strip()))
        cmd = "grep tsc /proc/cpuinfo"
        status, output = self.session.cmd_status_output(cmd)
        self.assertEqual(0, status, "CPU doesn't contain 'tsc' flag")
        cmd = "dmesg | egrep -i 'tsc|clock'"
        status, output = self.session.cmd_status_output(cmd)
        self.assertEqual(0, status, "Failed to get dmesg log")
        self.log.info("\n{}".format(output))

    def test_check_clockevent(self):
        # =====This is test case of RHEL-82815=====
        cmd = "cat /sys/devices/system/clockevents/clockevent0/current_device"
        status, output = self.session.cmd_status_output(cmd)
        self.assertEqual(status, 0, "Failed to get cloudevent")
        self.assertEqual(output.strip(), u'Hyper-V clockevent',
                         "Current clockevent isn't Hyper-V clockevent")
        # =====End of test case RHEL-82815=====

    def tearDown(self):
        if self.name.name.endswith("test_unbind_clocksource"):
            self.session.send_line("reboot")
