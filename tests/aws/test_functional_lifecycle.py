from avocado import Test
from avocado_cloud.app.aws import EC2Snapshot
from avocado_cloud.app.aws import aws
import time
import random
from avocado_cloud.utils import utils_lib


class LifeCycleTest(Test):
    '''
    :avocado: tags=lifecycle,acceptance,fulltest
    '''

    def setUp(self):
        self.session = None
        self.vm = None
        self.ssh_wait_timeout = None
        aws.init_test(self)

    def test_create_vm(self):
        '''
        :avocado: tags=test_create_vm
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        aws.check_session(self)

        aws.run_cmd(self,
                    'whoami',
                    expect_ret=0,
                    expect_output=self.vm.vm_username,
                    msg="New VM is created: %s" % self.vm.instance_id)
        aws.run_cmd(self, 'uname -r', msg='Get instance kernel version')

    def test_start_vm(self):
        '''
        :avocado: tags=test_start_vm
        polarion_id: RHEL7-103633
        '''

        if not self.vm.is_stopped():
            self.vm.stop(loops=4)
        if not self.vm.is_stopped():
            self.fail("Instance is not in stopped state!")

        self.log.info("Start instance %s" % self.vm.instance_id)
        if self.vm.start(wait=True):
            self.log.info("Instance is started: %s" % self.vm.instance_id)
            self.session.connect(timeout=self.ssh_wait_timeout)
            aws.check_session(self)
            aws.run_cmd(self, 'uname -r', msg='Get instance kernel version')
        else:
            self.fail("Failed to start instance!")

    def test_start_vm_iommu(self):
        '''
        :avocado: tags=test_start_vm_iommu
        polarion_id:
        This test bare metal instance can boot up with iommu
        '''
        if 'metal' in self.vm.instance_type:
            self.log.info("Instance is bare metal")
        else:
            self.log.info("Instance is xen/kvm")
            self.cancel("Only run in bare metal instances!")
        self.session.connect(timeout=self.ssh_wait_timeout)
        aws.check_session(self)
        aws.run_cmd(self, 'uname -r', msg='Get instance kernel version')

        aws.run_cmd(self,
                    'lscpu',
                    expect_ret=0,
                    cancel_not_kw="Xen,aarch64,AuthenticAMD")

        cmd = 'sudo grubby --update-kernel=ALL --args="intel_iommu=on"'
        aws.run_cmd(self, cmd, expect_ret=0)
        if not self.vm.is_stopped():
            self.vm.stop(loops=4)
        if not self.vm.is_stopped():
            self.fail("Instance is not in stopped state!")

        self.log.info("Start instance %s" % self.vm.instance_id)
        if self.vm.start(wait=True):
            self.session.connect(timeout=self.ssh_wait_timeout)
            aws.check_session(self)
            aws.run_cmd(self,
                        'cat /proc/cmdline',
                        msg='Get instance boot cmdline')
            cmd = 'sudo grubby --update-kernel=ALL \
--remove-args="intel_iommu=on"'

            aws.run_cmd(self, cmd, expect_ret=0)

        else:
            self.fail("Failed to start instance!")

    def test_reboot_vm_from_control(self):
        '''
        :avocado: tags=test_reboot_vm_from_control,kernel_tier1
        polarion_id: RHEL7-103636
        '''

        self.session.connect(timeout=self.ssh_wait_timeout)
        time.sleep(10)
        aws.check_session(self)

        cmd = 'last|grep reboot'
        aws.run_cmd(self,
                    cmd,
                    expect_ret=0,
                    msg="Before rebooting %s" % self.vm.instance_id)
        self.log.info("Rebooting %s" % self.vm.instance_id)
        if self.vm.reboot():
            if 'metal' in self.vm.instance_type:
                self.log.info("Wait %s" % self.ssh_wait_timeout)
                time.sleep(self.ssh_wait_timeout)
            else:
                self.log.info("Wait 30s")
                time.sleep(30)
            if self.session.session.is_responsive():
                self.fail("SSH connection keeps live!")
            self.session.connect(timeout=self.ssh_wait_timeout)
            aws.run_cmd(self,
                        cmd,
                        expect_ret=0,
                        msg="After reboot %s" % self.vm.instance_id)
            self.log.info("Reboot %s successfully" % self.vm.instance_id)

        else:
            self.fail("Reboot %s operation failed!" % self.vm.instance_id)

    def test_reboot_vm_inside_guest(self):
        '''
        :avocado: tags=test_reboot_vm_inside_guest
        polarion_id: RHEL7-103635
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        time.sleep(10)
        aws.check_session(self)

        self.log.info("Before rebooting %s" % self.vm.instance_id)
        output1 = self.session.cmd_output('last|grep reboot')
        self.log.info("VM last reboot log:\n %s" % output1)
        # session.cmd_ouput failes to get ret status as reboot close connection
        # considering add a function to guest.py to handle this. For now, use
        # sendline directly.
        self.session.session.sendline('sudo reboot')
        self.log.info("Rebooting %s via ssh" % self.vm.instance_id)
        if 'metal' in self.vm.instance_type:
            self.log.info("Wait %s" % self.ssh_wait_timeout)
            time.sleep(self.ssh_wait_timeout)
        else:
            self.log.info("Wait 60s")
            time.sleep(60)
        if self.session.session.is_responsive():
            self.fail("SSH connection keeps live!")

        self.session.connect(timeout=self.ssh_wait_timeout)
        output2 = self.session.cmd_output('last|grep reboot')
        self.log.info("VM last reboot log:\n %s" % output2)
        # self.assertEqual(output1, output2, "Reboot %s operation failed!" % \
        #     self.vm.instance_id)
        self.log.info("Reboot %s successfully" % self.vm.instance_id)

    def test_stop_vm(self):
        '''
        :avocado: tags=test_stop_vm,fast_check,kernel_tier1
        polarion_id: RHEL7-103634
        '''
        if not self.vm.stop(wait=True, loops=1):
            self.fail("Stop VM error: VM status is not stopped")

    def test_stop_vm_inside_guest(self):
        '''
        :avocado: tags=test_stop_vm_inside_guest,fast_check
        polarion_id: RHEL7-103846
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        aws.check_session(self)
        aws.run_cmd(self, 'uname -r', msg='Get instance kernel version')

        self.log.info("Before shuting down %s" % self.vm.instance_id)
        output = self.session.cmd_output('last|grep reboot')
        self.log.info("VM last reboot log:\n %s" % output)
        self.log.info("Stopping vm from inside itself %s" %
                      self.vm.instance_id)
        self.session.session.sendline('sudo init 0')

        time.sleep(30)
        if self.session.session.is_responsive():
            self.fail("SSH connection keeps live!")
        start_time = int(time.time())
        while True:
            time.sleep(20)
            if self.vm.is_stopped():
                self.log.info("VM is stopped!")
                break
            else:
                self.log.info(
                    "VM is not in stopped state, check again after 20s!")
            end_time = int(time.time())
            if end_time - start_time > 3 * self.ssh_wait_timeout:
                self.fail("VM is not in stopped state after %s seconds!" %
                          self.ssh_wait_timeout)
                break

    def test_delete_vm(self):
        '''
        :avocado: tags=test_delete_vm
        polarion_id: RHEL7-103637
        '''
        if not self.vm.delete(wait=True, loops=1):
            self.fail("Delete VM error: VM still exists")
        else:
            self.log.info("Cleanup previous saved vm info!")
            aws.cleanup_stored(self.teststmpdir,
                               self.params,
                               resource_id=self.vm.instance_id)

    def test_create_snapshot_vmrunning(self):
        '''
        :avocado: tags=test_create_snapshot_vmrunning
        polarion_id:RHEL7-103638
        '''
        if not self.vm.is_started():
            self.vm.start()
        if self.vm.is_started():
            self.snap = EC2Snapshot(self.params, self.vm.boot_volume_id)
            self.log.info("Create snapshot of %s when vm is running" %
                          self.vm.boot_volume_id)
            if not self.snap.create():
                self.log.info("Create snapshot failed!")
            else:
                self.log.info("Create snapshot successfully %s" %
                              self.snap.snap_id)
        else:
            self.fail("Instance is not in running state!")

    def test_create_snapshot_vmstopped(self):
        '''
        :avocado: tags=test_create_snapshot_vmstopped
        polarion_id: RHEL7-103639
        '''
        if not self.vm.is_stopped():
            self.vm.stop(loops=4)
        if not self.vm.is_stopped():
            self.fail("Instance is not in stopped state!")

        self.snap = EC2Snapshot(self.params, self.vm.boot_volume_id)
        self.log.info("Create snapshot of %s when vm is stopped" %
                      self.vm.boot_volume_id)
        if not self.snap.create():
            self.log.info("Create snapshot failed!")
        else:
            self.log.info("Create snapshot successfully %s" %
                          self.snap.snap_id)

    def test_change_instance_type(self):
        '''
        :avocado: tags=test_change_instance_type
        polarion_id: RHEL7-103853
        '''
        cmd = 'lscpu'
        output = aws.run_cmd(self, cmd, expect_ret=0)
        if 'aarch64' in output:
            self.log.info("arm instance")
            instance_list = [
                "a1.medium", "a1.large", "a1.xlarge", "a1.2xlarge",
                "a1.4xlarge"
            ]
        else:
            self.log.info("x86 instance")
            instance_list = [
                "t2.small", "t3.medium", "m5.2xlarge", "m4.2xlarge",
                "c4.xlarge", "c5.xlarge", "c5d.xlarge", "g3.4xlarge",
                "i3.xlarge", "r5d.xlarge"
            ]

        if not self.vm.is_stopped():
            self.vm.stop(loops=4)
        if not self.vm.is_stopped():
            self.fail("Instance is not in stopped state!")
        old_type = self.vm.instance_type
        new_type = random.choice(instance_list)
        self.log.info("Try to change %s to %s" % (old_type, new_type))
        ret = self.vm.modify_instance_type(new_type)
        self.assertTrue(ret, msg="Failed to change instance type!")
        self.vm.start()

        self.session.connect(timeout=self.ssh_wait_timeout)
        aws.check_session(self)
        self.log.info(
            "Changed instance type done! Restore it back to previous.")
        self.vm.stop(wait=True)
        ret = self.vm.modify_instance_type(old_type)
        self.assertTrue(ret, msg="Failed to restore instance type!")

    def test_boot_nr_cpus(self):
        '''
        :avocado: tags=test_boot_nr_cpus
        polarion_id:
        bz#: 1844522
        '''
        self.log.info("Check system can boot with nr_cpu=1 and 2")
        self.session.connect(timeout=self.ssh_wait_timeout)
        for cpu in range(1,3):
            cmd = 'sudo grubby --update-kernel=ALL --args="nr_cpus={}"'.format(cpu)
            utils_lib.run_cmd(self, cmd, expect_ret=0, msg='boot with nr_cpus={}'.format(cpu))
            self.log.info('Reboot system!')
            self.vm.reboot(wait=True)
            if 'metal' in self.vm.instance_type:
                self.log.info("Wait {}".format(self.ssh_wait_timeout))
                time.sleep(self.ssh_wait_timeout)
            else:
                self.log.info("Wait 60s")
                time.sleep(60)
            self.session.connect(timeout=self.ssh_wait_timeout)
            utils_lib.run_cmd(self, 'lscpu', msg='list cpus')
            cmd = "sudo cat /proc/cpuinfo |grep processor|wc -l"
            utils_lib.run_cmd(self, cmd, expect_kw=str(cpu), msg='check cpus')
            utils_lib.run_cmd(self, 'lscpu', msg='list cpus')

    def test_boot_fipsenabled(self):
        '''
        :avocado: tags=test_boot_fipsenabled
        polarion_id:
        bz#: 1787270
        '''
        self.log.info("Check system can boot with fips=1")
        self.session.connect(timeout=self.ssh_wait_timeout)
        cmd = 'uname -r'
        output = aws.run_cmd(self, cmd, expect_ret=0)
        if 'el7' in output:
            cmd = 'sudo dracut -v -f'
            aws.run_cmd(self,
                        cmd,
                        msg='regenerate the initramfs!',
                        timeout=600)
            cmd = 'sudo grubby --update-kernel=ALL --args="fips=1"'
            aws.run_cmd(self, cmd, msg='Enable fips!', timeout=600)
            self.log.info('Reboot system!')
            self.vm.reboot(wait=True)
            if 'metal' in self.vm.instance_type:
                self.log.info("Wait %s" % self.ssh_wait_timeout)
                time.sleep(2 * self.ssh_wait_timeout)
            else:
                self.log.info("Wait 300s")
                time.sleep(300)
            self.session.connect(timeout=self.ssh_wait_timeout)
            aws.run_cmd(self, 'cat /proc/cmdline', expect_kw='fips=1')
            aws.run_cmd(self, 'dmesg', msg='save dmesg')
            cmd = 'sudo grubby --update-kernel=ALL  --remove-args="fips=1"'
            aws.run_cmd(self, cmd, msg='Disable fips!')
        else:
            cmd = 'sudo fips-mode-setup --enable'
            aws.run_cmd(self, cmd, msg='Enable fips!', timeout=600)
            self.log.info('Reboot system!')
            self.vm.reboot(wait=True)
            if 'metal' in self.vm.instance_type:
                self.log.info("Wait %s" % self.ssh_wait_timeout)
                time.sleep(2 * self.ssh_wait_timeout)
            else:
                self.log.info("Wait 300s")
                time.sleep(300)
            self.session.connect(timeout=self.ssh_wait_timeout)
            aws.run_cmd(self,
                        'sudo fips-mode-setup --check',
                        expect_kw='enabled')
            aws.run_cmd(self, 'cat /proc/cmdline', expect_kw='fips=1')
            aws.run_cmd(self, 'dmesg', msg='save dmesg')
            cmd = 'sudo fips-mode-setup --disable'
            aws.run_cmd(self, cmd, msg='Disable fips!')
        self.log.info('Reboot system!')
        self.vm.reboot(wait=True)
        if 'metal' in self.vm.instance_type:
            self.log.info("Wait %s" % self.ssh_wait_timeout)
            time.sleep(2 * self.ssh_wait_timeout)
        else:
            self.log.info("Wait 300s")
            time.sleep(300)
        self.session.connect(timeout=self.ssh_wait_timeout)

    def test_boot_debugkernel(self):
        '''
        :avocado: tags=test_boot_debugkernel
        polarion_id:
        bz#: 1703366
        '''
        self.log.info("Check kernel-debug can boot up!")
        self.session.connect(timeout=self.ssh_wait_timeout)
        mini_mem = self.params.get('memory', '*/instance_types/*')
        if int(mini_mem) < 2:
            self.cancel('Cancel case as low memory')
        cmd = 'sudo lscpu'
        output = aws.run_cmd(self, cmd, expect_ret=0)
        if 'aarch64' in output and int(mini_mem) < 4:
            self.cancel('Cancel case as low memory')

        cmd = 'sudo uname -r'
        kernel_ver = aws.run_cmd(self, cmd, expect_ret=0)
        if 'el7' in kernel_ver:
            debug_kernel = "/boot/vmlinuz-" + kernel_ver.strip('\n') + ".debug"
        else:
            debug_kernel = "/boot/vmlinuz-" + kernel_ver.strip('\n') + "+debug"

        cmd = "sudo grubby --info=%s" % debug_kernel
        aws.run_cmd(self,
                    cmd,
                    expect_ret=0,
                    msg="check kernel-debug installed")
        cmd = "sudo grubby --info=%s|grep index|cut -d'=' -f2" % debug_kernel
        debug_kernel_index = aws.run_cmd(self,
                                         cmd,
                                         expect_ret=0,
                                         msg="check kernel-debug index")
        cmd = "sudo grubby --set-default-index=%s" % debug_kernel_index
        aws.run_cmd(self, cmd, expect_ret=0, msg="change default boot index")
        cmd = 'sudo grubby --update-kernel=ALL --args="kmemleak=on"'
        aws.run_cmd(self, cmd, expect_ret=0, msg="enable kmemleak")
        self.vm.reboot(wait=True)
        if 'metal' in self.vm.instance_type:
            self.log.info("Wait %s" % self.ssh_wait_timeout)
            time.sleep(self.ssh_wait_timeout)
        else:
            self.log.info("Wait 120s")
            time.sleep(120)
        self.session.connect(timeout=self.ssh_wait_timeout)
        aws.run_cmd(self,
                    'uname -r',
                    expect_ret=0,
                    expect_kw='debug',
                    msg="checking debug kernel booted")
        aws.run_cmd(self, 'dmesg', expect_ret=0, msg="saving dmesg output")
        cmd = 'sudo su'
        aws.run_cmd(self, cmd, expect_ret=0)
        cmd = 'journalctl > /tmp/journalctl.log'
        aws.run_cmd(self, cmd, expect_ret=0, msg="saving journalctl output")
        cmd = 'cat /tmp/journalctl.log'
        aws.run_cmd(self, cmd, expect_ret=0)
        cmd = "sudo systemd-analyze blame > /tmp/blame.log"
        aws.run_cmd(self, cmd)
        cmd = "cat /tmp/blame.log"
        aws.run_cmd(self, cmd)
        cmd = "sudo systemd-analyze "
        time_start = int(time.time())
        while True:
            output = aws.run_cmd(self, cmd)
            if 'Bootup is not yet finished' not in output:
                break
            time_end = int(time.time())
            aws.run_cmd(self, 'sudo systemctl list-jobs')
            if time_end - time_start > 120:
                self.fail("Bootup is not yet finished after 120s")
            self.log.info("Wait for bootup finish......")
            time.sleep(1)
        if int(mini_mem) < 17:
            cmd = 'sudo echo scan > /sys/kernel/debug/kmemleak'
            aws.run_cmd(self, cmd, expect_ret=0, timeout=1800)

            cmd = 'sudo cat /sys/kernel/debug/kmemleak'
            output = aws.run_cmd(self, cmd, expect_ret=0)
            if len(output) > 0:
                self.fail('Memory leak found!')

    def tearDown(self):
        if "create_snapshot" in self.name.name:
            if self.snap.delete():
                self.log.info("Delete snaphot after test!")
            else:
                self.log.info("Delete snapshot failed after test!")
        if "test_boot_debugkernel" in self.name.name:
            aws.cleanup_stored(self.teststmpdir,
                               self.params,
                               resource_id=self.vm.res_id)
        if "test_boot_nr_cpus" in self.name.name:
            for cpu in range(1,3):
                cmd = 'sudo grubby --update-kernel=ALL --remove-args="nr_cpus={}"'.format(cpu)
                utils_lib.run_cmd(self, cmd, msg='remove nr_cpus={}'.format(cpu))

            self.log.info('Reboot system!')
            self.vm.reboot(wait=True)
            if 'metal' in self.vm.instance_type:
                self.log.info("Wait {}".format(self.ssh_wait_timeout))
                time.sleep(self.ssh_wait_timeout)
            else:
                self.log.info("Wait 60s")
                time.sleep(60)
        if self.session.session.is_responsive(
        ) is not None and self.vm.is_started():
            aws.gcov_get(self)
            aws.get_memleaks(self)
            self.session.close()
