from avocado import Test
from avocado_cloud.app.aws import aws
from avocado_cloud.utils import utils_lib
import time


class KdumpTest(Test):
    '''
    :avocado: tags=kdump,fulltest
    '''
    def _get_kdump_status(self):
        self.log.info("Checking kdump status: %s " % self.vm.instance_id)
        check_cmd = "systemctl status kdump.service"
        for i in range(10):
            status, output = self.session.cmd_status_output(check_cmd)
            if status == 0:
                self.log.info("Kdump service is running!")
                self.kdump_status = True
                break
            else:
                self.log.info(
                    "Kdump service is not in running state, wait for max 200s")
                self.log.debug("%s" % output)
                self.kdump_status = False
                # systemctl cmd is not available in RHEL6
                if "systemctl: command not found" in output:
                    check_cmd = "sudo service kdump status"
                if 'Active: failed' in output:
                    break
                elif 'Kdump is unsupported' in output:
                    break
                time.sleep(20)
                if i == 9:
                    self.log.error(
                        "kdump service is not in running state at last!")

    def _delete_core_file(self):
        self.log.info("Clean up core files for space concern!")
        utils_lib.run_cmd(self, "find /var/crash", msg="Before cleanup")
        utils_lib.run_cmd(self, "sudo rm -rf /var/crash/*")
        utils_lib.run_cmd(self, "sudo rm -rf /var/spool/abrt/*")
        utils_lib.run_cmd(self, "sudo sync")
        utils_lib.run_cmd(self, "find /var/crash", msg="After cleanup")

    def _trigger_kdump_on_cpu(self, cpu=None):
        cmd = 'sudo su'
        aws.run_cmd(self, cmd, msg="Switch to root")
        cmd = 'echo 1 > /proc/sys/kernel/sysrq'
        aws.run_cmd(self,
                    cmd,
                    msg="Make sure it allows trigger panic via sysrq")
        cpuN = cpu
        if cpuN is None:
            trigger_cmd = "bash -c 'echo c > /proc/sysrq-trigger'"
        else:
            trigger_cmd = "bash -c 'taskset -c " + \
                str(cpuN) + " echo c > /proc/sysrq-trigger'"

        self.log.debug("Send command '%s' " % trigger_cmd)
        # session.cmd_ouput failes to get ret status as reboot close connection
        # considering add a function to guest.py to handle this. For now, use
        # sendline directly.
        self.session.session.sendline("'%s'" % trigger_cmd)
        try:
            status, output = self.session.cmd_status_output(trigger_cmd)
            self.log.info("trigger ret: %s, output: %s" % (status, output))
        except Exception as err:
            self.log.info("Error to read output as expected! %s" % err)

    def setUp(self):
        self.session = None
        self.vm = None
        self.ssh_wait_timeout = None
        aws.init_test(self)
        time.sleep(30)
        self._get_kdump_status()
        status, output = self.session.cmd_status_output(
            "grep processor /proc/cpuinfo |wc -l")
        if status == 0:
            self.cpu_count = output
        self.log.info("CPU(s): %s" % self.cpu_count)
        self.log.debug("output: %s" % output)
        cmd = "lscpu"
        self.log.info("CMD: %s" % cmd)
        aws.run_cmd(self,
                    cmd,
                    expect_ret=0,
                    cancel_not_kw='Xen',
                    msg="Not run in xen instance")

    def test_kdump_no_specify_cpu(self):
        '''
        :avocado: tags=test_kdump_no_specify_cpu,acceptance,fast_check
        polarion_id: RHEL7-58669
        bz#: 1654962
        '''
        if not self.kdump_status:
            self.cancel("Cancle test as kdump not running!")
        self.session.connect(timeout=self.ssh_wait_timeout)
        time.sleep(10)
        output = utils_lib.run_cmd(self, 'lscpu', expect_ret=0)
        if 'aarch64' in output and 'metal' not in self.vm.instance_type:
            self.log.info("arm instance")
            self.cancel("Cancel it as bug 1654962 in arm instances which \
no plan to fix it in the near future!")

        aws.run_cmd(self,
                    r'sudo rm -rf /var/crash/*',
                    expect_ret=0,
                    msg='clean /var/crash firstly')
        aws.run_cmd(self, r'sudo sync', expect_ret=0)
        self.log.info("Before system crash %s" % self.vm.instance_id)
        aws.run_cmd(self,
                    r'find /var/crash',
                    expect_ret=0,
                    msg='list /var/crash')
        self.log.info("Crashing %s via ssh" % self.vm.instance_id)
        self._trigger_kdump_on_cpu()

        if 'metal' in self.vm.instance_type:
            self.log.info("Wait %s" % self.ssh_wait_timeout)
            time.sleep(self.ssh_wait_timeout)
        else:
            self.log.info("Wait 30s")
            time.sleep(30)
        self.session.connect(timeout=640)
        self.log.info("After system crash %s" % self.vm.instance_id)
        aws.run_cmd(self,
                    r'find /var/crash',
                    expect_ret=0,
                    msg='list /var/crash after crash')
        cmd = r'sudo cat /var/crash/1*/vmcore-dmesg.txt|tail -50'
        aws.run_cmd(self, cmd, expect_ret=0, expect_kw='write_sysrq_trigger')

    def test_kdump_unknown_nmi_panic_disabled(self):
        '''
        :avocado: tags=test_kdump_unknown_nmi_panic_disabled,acceptance,
                       fast_check
        polarion_id: 
        trigger kdump via nmi
        https://aws.amazon.com/blogs/aws/new-trigger-a-kernel-panic-to-\
            diagnose-unresponsive-ec2-instances/
        '''
        if not self.kdump_status:
            self.cancel("Cancle test as kdump not running!")
        self.session.connect(timeout=self.ssh_wait_timeout)
        aws.run_cmd(self,
                    'lscpu',
                    cancel_not_kw='aarch64',
                    msg='Not support in arm instance')
        time.sleep(10)

        aws.run_cmd(self,
                    r'sudo rm -rf /var/crash/*',
                    expect_ret=0,
                    msg='clean /var/crash firstly')
        aws.run_cmd(self,
                    r'sudo sysctl kernel.unknown_nmi_panic=0',
                    expect_ret=0,
                    msg='enable unknown_nmi_panic')
        aws.run_cmd(self,
                    r'sudo sysctl -a|grep -i nmi',
                    expect_ret=0,
                    expect_kw='kernel.unknown_nmi_panic = 0')
        if not self.vm.send_nmi():
            self.fail("Cannot trigger panic via nmi!")

        time.sleep(10)
        if not self.session.session.is_responsive():
            self.fail("SSH connection should live!")
        aws.run_cmd(self,
                    r'sudo ls /var/crash/',
                    expect_ret=0,
                    msg='list /var/crash after crash')
        cmd = r'sudo dmesg|tail -10'
        aws.run_cmd(self, cmd, expect_ret=0, expect_kw='NMI received')

    def test_kdump_unknown_nmi_panic_enabled(self):
        '''
        :avocado: tags=test_kdump_unknown_nmi_panic_enabled,acceptance,
                       fast_check
        polarion_id: 
        trigger kdump via nmi
        https://aws.amazon.com/blogs/aws/new-trigger-a-kernel-panic-to-\
            diagnose-unresponsive-ec2-instances/
        '''
        if not self.kdump_status:
            self.cancel("Cancle test as kdump not running!")
        self.session.connect(timeout=self.ssh_wait_timeout)
        aws.run_cmd(self,
                    'lscpu',
                    cancel_not_kw='aarch64',
                    msg='Not support in arm instance')
        time.sleep(10)

        aws.run_cmd(self,
                    r'sudo rm -rf /var/crash/*',
                    expect_ret=0,
                    msg='clean /var/crash firstly')
        aws.run_cmd(self,
                    r'sudo sysctl kernel.unknown_nmi_panic=1',
                    expect_ret=0,
                    msg='enable unknown_nmi_panic')
        aws.run_cmd(self,
                    r'sudo sysctl -a|grep -i nmi',
                    expect_ret=0,
                    expect_kw='kernel.unknown_nmi_panic = 1')
        if not self.vm.send_nmi():
            self.fail("Cannot trigger panic via nmi!")

        time.sleep(10)
        if self.session.session.is_responsive():
            self.fail("SSH connection keeps live! Should be closed \
if crashed successfully!")
        if 'metal' in self.vm.instance_type:
            self.log.info("Wait %s" % self.ssh_wait_timeout)
            time.sleep(self.ssh_wait_timeout)
        else:
            self.log.info("Wait 30s")
            time.sleep(30)
        self.session.connect(timeout=self.ssh_wait_timeout)
        aws.run_cmd(self,
                    r'sudo ls /var/crash/',
                    expect_ret=0,
                    msg='list /var/crash after crash')
        cmd = r'sudo cat /var/crash/1*/vmcore-dmesg.txt|tail -50'
        aws.run_cmd(self, cmd, expect_ret=0, expect_kw='nmi_panic')

    def test_kdump_unknown_nmi_panic_enabled_sysrq_trigger(self):
        '''
        :avocado: tags=test_kdump_unknown_nmi_panic_enabled_sysrq_trigger,
                       acceptance,fast_check
        polarion_id:
        Test kdump works while triggerring panic inside guest via 
        sysrq-trigger when unknown_nmi_panic_enabled=1
        '''
        if not self.kdump_status:
            self.cancel("Cancle test as kdump not running!")
        self.session.connect(timeout=self.ssh_wait_timeout)
        aws.run_cmd(self,
                    'lscpu',
                    cancel_not_kw='aarch64',
                    msg='Not support in arm instance')
        time.sleep(10)
        aws.run_cmd(self,
                    r'sudo rm -rf /var/crash/*',
                    expect_ret=0,
                    msg='clean /var/crash firstly')
        aws.run_cmd(self, r'sudo sync', expect_ret=0)
        aws.run_cmd(self,
                    r'sudo sysctl kernel.unknown_nmi_panic=1',
                    expect_ret=0,
                    msg='enable unknown_nmi_panic')
        aws.run_cmd(self,
                    r'sudo sysctl -a|grep -i nmi',
                    expect_ret=0,
                    expect_kw='kernel.unknown_nmi_panic = 1')
        self.log.info("Before system crash %s" % self.vm.instance_id)
        aws.run_cmd(self,
                    r'find /var/crash',
                    expect_ret=0,
                    msg='list /var/crash')
        self.log.info("Crashing %s via ssh" % self.vm.instance_id)
        self._trigger_kdump_on_cpu()

        if 'metal' in self.vm.instance_type:
            self.log.info("Wait %s" % self.ssh_wait_timeout)
            time.sleep(self.ssh_wait_timeout)
        else:
            self.log.info("Wait 30s")
            time.sleep(30)
        self.session.connect(timeout=640)
        self.log.info("After system crash %s" % self.vm.instance_id)
        aws.run_cmd(self,
                    r'find /var/crash',
                    expect_ret=0,
                    msg='list /var/crash after crash')
        cmd = r'sudo cat /var/crash/1*/vmcore-dmesg.txt|tail -50'
        aws.run_cmd(self, cmd, expect_ret=0, expect_kw='write_sysrq_trigger')

    def test_kdump_each_cpu(self):
        '''
        :avocado: tags=test_kdump_each_cpu
        polarion_id: RHEL7-88711
        '''
        for i in range(int(self.cpu_count)):
            self.session.connect(timeout=self.ssh_wait_timeout)
            time.sleep(10)
            self._get_kdump_status()
            if not self.kdump_status:
                self.cancel("Cancle test as kdump not running!")
            self.log.info("Before system crash %s" % self.vm.instance_id)
            output1 = self.session.cmd_output('find /var/crash')
            self.log.info("/var/crash dir:\n %s" % output1)
            self.log.info("Crashing %s via ssh" % self.vm.instance_id)
            self._trigger_kdump_on_cpu(i)
            time.sleep(5)
            # if self.session.session.is_responsive():
            #    self.fail(
            #        "SSH connection keeps live! Should be closed if crashed \
            # successfully!")
            self.session.connect(timeout=self.ssh_wait_timeout)
            self.log.info("After system crash %s" % self.vm.instance_id)
            output2 = self.session.cmd_output('find /var/crash')
            self.log.info("/var/crash dir:\n %s" % output2)
            if output1 == output2:
                self.fail("CPU- %s No new core file found! Test FAIL" % i)
            else:
                self.log.info("CPU- %s New core file found! Test PASS" % i)
            self._delete_core_file()

    def test_kdump_fastboot(self):
        '''
        :avocado: tags=test_kdump_fastboot,acceptance,
                       fast_check
        polarion_id:
        bz#: 1758323
        '''
        if not self.kdump_status:
            self.cancel("Cancle test as kdump not running!")
        self.session.connect(timeout=self.ssh_wait_timeout)
        cmd = 'sudo rpm -qa|grep -e "kernel-[0-9]"'
        output = utils_lib.run_cmd(self, cmd, msg='Get kernel version')
        kernels_list = output.split('\n')
        for kernel in kernels_list:
            kernel_vmlinuz = "/boot/" + kernel.replace('kernel','vmlinuz')
            kernel_initramfs = "/boot/" + kernel.replace('kernel','initramfs') + ".img"
            cmd = "sudo kexec -l %s --initrd=%s --reuse-cmdline" % (kernel_vmlinuz, kernel_initramfs)
            utils_lib.run_cmd(self, cmd, msg='Switch kernel', expect_ret=0)
            cmd = "sudo systemctl kexec"
            self.log.info("CMD: %s", cmd)
            self.session.session.sendline("%s" % cmd)
            time.sleep(10)
            self.session.connect(timeout=self.ssh_wait_timeout)
            utils_lib.run_cmd(self, 'uname -r', msg='check kernel', expect_ret=0, expect_kw=kernel[7:])

    def tearDown(self):
        if self.session.session.is_responsive(
        ) is not None and self.vm.is_started():
            aws.gcov_get(self)
            aws.get_memleaks(self)
            self.session.close()
