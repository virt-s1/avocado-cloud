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

    def test_start_vm(self):
        '''
        :avocado: tags=test_start_vm
        description:
            Test start an RHEL instance on AWS. Linked case RHEL7-103633
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]LifeCycleTest.test_start_vm"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            LifeCycle
        key_steps:
            1. Launch an instance on AWS EC2.
            2. Connect the instance via ssh with user:ec2-user.
        pass_criteria: 
            Instance is in running state without error, and can be connected via ssh.
        '''

        if not self.vm.is_stopped():
            self.vm.stop(loops=4)
        if not self.vm.is_stopped():
            self.fail("Instance is not in stopped state!")

        self.log.info("Start instance %s" % self.vm.instance_id)
        if self.vm.start(wait=True):
            self.log.info("Instance is started: %s" % self.vm.instance_id)
            self.session.connect(timeout=self.ssh_wait_timeout)
            utils_lib.run_cmd(self, 'uname -r', msg='Get instance kernel version')
        else:
            self.fail("Failed to start instance!")

    def test_start_vm_iommu(self):
        '''
        :avocado: tags=test_start_vm_iommu
        description:
            Test boot up an RHEL bare metal instance on AWS with iommu. Note this case is only for Bare metal instance since iommu is for configuring a host for PCI passthrough.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]LifeCycleTest.test_start_vm_iommu"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            LifeCycle
        key_steps:
            1. Launch a bare metal instance on AWS EC2.
            2. Connect the instance via ssh with user:ec2-user, add iommu parameter to kernel command line with command "sudo grubby --update-kernel=ALL --args="intel_iommu=on"".
            3. Reboot instance, check if instance can boot up, and check the kernel command line with command "cat /proc/cmdline".
        pass_criteria: 
            Instance boots up as normal and there are "intel_iommu=on" in kernel command line.
        '''
        if 'metal' in self.vm.instance_type:
            self.log.info("Instance is bare metal")
        else:
            self.log.info("Instance is xen/kvm")
            self.cancel("Only run in bare metal instances!")
        self.session.connect(timeout=self.ssh_wait_timeout)
        utils_lib.run_cmd(self, 'uname -r', msg='Get instance kernel version')

        utils_lib.run_cmd(self,
                    'lscpu',
                    expect_ret=0,
                    cancel_not_kw="Xen,aarch64,AuthenticAMD")

        cmd = 'sudo grubby --update-kernel=ALL --args="intel_iommu=on"'
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        if not self.vm.is_stopped():
            self.vm.stop(loops=4)
        if not self.vm.is_stopped():
            self.fail("Instance is not in stopped state!")

        self.log.info("Start instance %s" % self.vm.instance_id)
        if self.vm.start(wait=True):
            self.session.connect(timeout=self.ssh_wait_timeout)
            aws.check_session(self)
            utils_lib.run_cmd(self,
                        'cat /proc/cmdline',
                        msg='Get instance boot cmdline')
            cmd = 'sudo grubby --update-kernel=ALL \
--remove-args="intel_iommu=on"'

            utils_lib.run_cmd(self, cmd, expect_ret=0)

        else:
            self.fail("Failed to start instance!")

    def test_reboot_vm_from_control(self):
        '''
        :avocado: tags=test_reboot_vm_from_control,kernel
        description:
        Test reboot RHEL instance from AWS platform. Linked case RHEL7-103636.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]LifeCycleTest.test_reboot_vm_from_control"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            LifeCycle
        key_steps:
            1. Launch an instance on AWS EC2.
            2. From AWS console, AWS cli or API, reboot the instance.
        pass_criteria: 
            Instance reboot as normal, and there is new record about the lastest reboot in output of "last" command.
            Note: It will take longer time for Bare Metal instance to reboot.
        '''

        self.session.connect(timeout=self.ssh_wait_timeout)
        time.sleep(10)
        aws.check_session(self)

        utils_lib.run_cmd(self,
                    'last|grep reboot',
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
            utils_lib.run_cmd(self,
                        'last|grep reboot',
                        expect_ret=0,
                        msg="After reboot %s" % self.vm.instance_id)
            self.log.info("Reboot %s successfully" % self.vm.instance_id)

        else:
            self.fail("Reboot %s operation failed!" % self.vm.instance_id)

    def test_reboot_vm_inside_guest(self):
        '''
        :avocado: tags=test_reboot_vm_inside_guest
        description:
        Test reboot RHEL instance on AWS inside instance. Linked case RHEL7-103635.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]LifeCycleTest.test_reboot_vm_inside_guest"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            LifeCycle
        key_steps:
            1. Launch an instance on AWS EC2.
            2. Connect instace via ssh, run command "sudo Reboot" inside the instance to reboot the instance.
        pass_criteria: 
            Instance reboot as normal, and there is new record about the lastest reboot in output of "last" command.
            Note: It will take longer time for Bare Metal instance to reboot.
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        time.sleep(10)
        aws.check_session(self)

        self.log.info("Before rebooting %s" % self.vm.instance_id)
        output1 = utils_lib.run_cmd(self, 'last|grep reboot')
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
        output2 = utils_lib.run_cmd(self, 'last|grep reboot')
        self.log.info("VM last reboot log:\n %s" % output2)
        # self.assertEqual(output1, output2, "Reboot %s operation failed!" % \
        #     self.vm.instance_id)
        self.log.info("Reboot %s successfully" % self.vm.instance_id)

    def test_stop_vm(self):
        '''
        :avocado: tags=test_stop_vm,kernel
        description:
        Test stop RHEL instance from AWS platform. Linked case RHEL7-103634.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]LifeCycleTest.test_stop_vm"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            LifeCycle
        key_steps:
            1. Launch an instance on AWS EC2.
            2. From AWS console, AWS cli or API, stop the instance.
        pass_criteria: 
            Instance status is stopped.
        '''
        if not self.vm.stop(wait=True, loops=1):
            self.fail("Stop VM error: VM status is not stopped")

    def test_stop_vm_inside_guest(self):
        '''
        :avocado: tags=test_stop_vm_inside_guest
        description:
        Test stop RHEL instance on AWS inside instance. Linked case RHEL7-103846.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]LifeCycleTest.test_stop_vm_inside_guest"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            LifeCycle
        key_steps:
            1. Launch an instance on AWS EC2.
            2. Connect instace via ssh, run command "sudo init 0" inside the instance to stop the instance.
        pass_criteria: 
            Instance status is stopped.
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        aws.check_session(self)
        utils_lib.run_cmd(self, 'uname -r', msg='Get instance kernel version')

        self.log.info("Before shuting down %s" % self.vm.instance_id)
        output = utils_lib.run_cmd(self, 'last|grep reboot')
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
        description:
        Test terminal RHEL instance on AWS. Linked case RHEL7-103637.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]LifeCycleTest.test_delete_vm"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            LifeCycle
        key_steps:
            1. Launch an instance on AWS EC2.
            2. From AWS console, AWS cli or API, terminal the instance.
        pass_criteria: 
            Instance is in stopping and then terminated state, ssh connect to the instance losts.
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
        description:
        Test create snapshot for running instance on AWS. Linked case RHEL7-103638.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]LifeCycleTest.test_create_snapshot_vmrunning"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            LifeCycle
        key_steps:
            1. Launch an instance on AWS EC2.
            2. When the instance is in running state, from AWS console, AWS cli or API, create snapshot for this instance.
        pass_criteria: 
            Snapshot is created successfully.
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
        description:
        Test create snapshot for stopped instance on AWS. Linked case RHEL7-103639.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]LifeCycleTest.test_create_snapshot_vmstopped"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            LifeCycle
        key_steps:
            1. Launch an instance on AWS EC2.
            2. Stop the instance.
            3. When the instance is in stopped status, from AWS console, AWS cli or API, create snapshot for it.
        pass_criteria: 
            Snapshot is created successfully.
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
        description:
        Test reboot RHEL instance on AWS platform. Linked case RHEL7-103853.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]LifeCycleTest.test_change_instance_type"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            LifeCycle
        key_steps:
            1. Launch an instance on AWS EC2.
            2. Stop the instance.
            3. When the instance is in stopped status, from AWS console, AWS cli or API, change the instance type.
            4. Start the instance.
        pass_criteria: 
            Instance is started successfully with the new instance type.
            Note: Only change instance types between the same arch.
        '''
        cmd = 'lscpu'
        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        if 'aarch64' in output:
            self.log.info("arm instance")
            instance_list = [
                "t4g.small", "c6g.medium", "a1.xlarge", "c6gd.medium",
                "m6gd.medium", "r6g.medium","r6g.medium","c6gn.medium"
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

    def test_boot_mitigations(self):
        '''
        :avocado: tags=test_boot_mitigations
        description:
        Test boot xen-based RHEL instance with kernel commandline argument 'mitigations=auto,nosmt' on AWS platform.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]LifeCycleTest.test_boot_mitigations"
        bugzilla_id: 
            1896786
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            LifeCycle
        key_steps:
            1. Launch a xen-based instance on AWS.
            2. Connect the instance via ssh, add kernel command line argument 'mitigations=auto,nosmt' to current kernel with command "sudo grubby --update-kernel=ALL --args="mitigations=auto,nosmt"".
            3. Reboot the instance.
            4. Connect the instance again after reboot, check dmesg.
        pass_criteria: 
            There isn't unbind_from_irqhandler warning or any other call trace in dmesg.
        '''
        cmd = 'sudo grubby --update-kernel=ALL --args="mitigations=auto,nosmt"'
        utils_lib.run_cmd(self, cmd, msg='Append mitigations=auto,nosmt to command line!', timeout=600)
        self.vm.reboot(wait=True)
        if 'metal' in self.vm.instance_type:
            self.log.info("Wait {}".format(self.ssh_wait_timeout))
            time.sleep(self.ssh_wait_timeout)
        else:
            self.log.info("Wait 60s")
            time.sleep(60)
        self.session.connect(timeout=self.ssh_wait_timeout)
        utils_lib.run_cmd(self, 'cat /proc/cmdline', expect_kw='mitigations=auto,nosmt')
        utils_lib.run_cmd(self, "dmesg", expect_not_kw="Call trace,Call Trace")

    def test_boot_usbcore_quirks(self):
        '''
        :avocado: tags=test_boot_usbcore_quirks
        description:
            Test boot RHEL instance with kernel commandline parameter "usbcore.quirks" on AWS platform.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]LifeCycleTest.test_boot_usbcore_quirks"
        bugzilla_id: 
            1809429
        customer_case_id: 
            BZ1809429
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            LifeCycle
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh, add kernel command line parameter "usbcore.quirks" to current kernel with command "sudo grubby --update-kernel=ALL --args=usbcore.quirks=quirks=0781:5580:bk,0a5c:5834:gij"".
            3. Reboot the instance.
            4. Connect the instance again after reboot.
        pass_criteria: 
            The instance can boot as normal with "usbcore.quirks" parameter in kernel command line. No kernel panic and crash, and no Call Track in dmesg.
        '''
        utils_lib.run_cmd(self, r'sudo rm -rf /var/crash/*',
                    expect_ret=0, msg='clean /var/crash firstly')
        option = 'usbcore.quirks=quirks=0781:5580:bk,0a5c:5834:gij'
        cmd = 'sudo grubby --update-kernel=ALL --args="{}"'.format(option)
        utils_lib.run_cmd(self, cmd, msg='Append {} to command line!'.format(option), timeout=600)
        self.vm.reboot(wait=True)
        if 'metal' in self.vm.instance_type:
            self.log.info("Wait {}".format(self.ssh_wait_timeout))
            time.sleep(self.ssh_wait_timeout)
        else:
            self.log.info("Wait 60s")
            time.sleep(60)
        self.session.connect(timeout=self.ssh_wait_timeout)

        utils_lib.run_cmd(self, 'cat /proc/cmdline', expect_kw=option)
        cmd = r'sudo cat /var/crash/*/vmcore-dmesg.txt|tail -50'
        utils_lib.run_cmd(self, cmd, expect_kw='No such file or directory', msg='make sure there is no core generated')
        utils_lib.run_cmd(self, "dmesg", expect_not_kw="Call trace,Call Trace")

    def test_boot_hpet_mmap_enabled(self):
        '''
        :avocado: tags=test_boot_hpet_mmap_enabled
        description:
            Test boot RHEL instance with HPET MMAP enabled on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]LifeCycleTest.test_boot_hpet_mmap_enabled"
        bugzilla_id: 
            1660796,1764790
        customer_case_id: 
            BZ1660796,BZ1764790
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            LifeCycle
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh, enable HPET MMAP with command "sudo grubby --update-kernel=ALL --args="hpet_mmap=1".
            3. Reboot the instance.
            4. Connect the instance again after reboot, check kernel command line, dmesg.
        pass_criteria: 
            The instance can boot as normal with HPET MMAP enabled.
            There is 'hpet_mmap=1' in /proc/cmdline, HPET mmap is enabled in dmesg, and no typo like "6HPET" in message. No Call Trace or other error in dmesg.
        '''
        utils_lib.is_arm(self, action='cancel')
        utils_lib.run_cmd(self,
                    r'sudo rm -rf /var/crash/*',
                    expect_ret=0,
                    msg='clean /var/crash firstly')
        cmd = 'sudo grubby --update-kernel=ALL --args="hpet_mmap=1"'
        utils_lib.run_cmd(self, cmd, msg='Append hpet_mmap=1 to command line!', timeout=600)
        self.vm.reboot(wait=True)
        if 'metal' in self.vm.instance_type:
            self.log.info("Wait {}".format(self.ssh_wait_timeout))
            time.sleep(self.ssh_wait_timeout)
        else:
            self.log.info("Wait 60s")
            time.sleep(60)
        self.session.connect(timeout=self.ssh_wait_timeout)
        utils_lib.run_cmd(self, 'cat /proc/cmdline', expect_kw='hpet_mmap=1')
        utils_lib.run_cmd(self, 'dmesg | grep -i hpet', expect_kw='enabled', expect_not_kw='6HPET')
        cmd = 'sudo cat /sys/devices/system/clocksource/clocksource0/available_clocksource'
        out = utils_lib.run_cmd(self, cmd)
        if 'hpet' in out:
            utils_lib.run_cmd(self, 'sudo cat /proc/iomem|grep -i hpet', expect_kw='HPET 0')
        utils_lib.run_cmd(self, "dmesg", expect_not_kw="Call trace,Call Trace")

    def test_boot_nr_cpus(self):
        '''
        :avocado: tags=test_boot_nr_cpus
        description:
            Test boot RHEL instance with kernel commandline parameter nr_cpus on AWS.
            This case tests the workaround of BZ1844522.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]LifeCycleTest.test_boot_nr_cpus"
        bugzilla_id: 
            1844522
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            LifeCycle
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh, add kernel commandline parameter nr_cpus to current kernel with command "sudo grubby --update-kernel=ALL --args="nr_cpus=1".
            3. Reboot the instance.
            4. Connect the instance again after reboot, check kernel command line "cat /proc/cmdline" and loaded cpus "cat /proc/cpuinfo".
            5. Change kernel commandline parameter nr_cpus with command "sudo grubby --update-kernel=ALL --args="nr_cpus=2"".
            6. Connect the instance again after reboot, check kernel command line "cat /proc/cmdline" and loaded cpus "cat /proc/cpuinfo".
        pass_criteria: 
            The instance can boot as normal with kernel commandline parameter nr_cpus.
            There is nr_cpus in kernel commanline, and the online cpu numbers are the same as the vaule of nr_cpus.
        '''
        expect_cpus = self.params.get('cpu', '*/instance_types/*')
        self.session.connect(timeout=self.ssh_wait_timeout)
        for cpu in range(1,3):
            if cpu > int(expect_cpus):
                break
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
            utils_lib.run_cmd(self, 'cat /proc/cmdline', expect_kw='nr_cpus={}'.format(cpu))
            utils_lib.run_cmd(self, 'lscpu', msg='list cpus')
            cmd = "sudo cat /proc/cpuinfo |grep processor|wc -l"
            utils_lib.run_cmd(self, cmd, expect_kw=str(cpu), msg='check cpus')
            utils_lib.run_cmd(self, 'lscpu', msg='list cpus')

    def test_boot_fipsenabled(self):
        '''
        :avocado: tags=test_boot_fipsenabled
        description:
            Test boot RHEL instance with fips enabled on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]LifeCycleTest.test_boot_fipsenabled"
        bugzilla_id: 
            1787270
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            LifeCycle
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh, enable fips to current kernel:
                For RHEL7, regernerate initramfs image with command "sudo dracut -v -f", and enable fips with command "sudo grubby --update-kernel=ALL --args="fips=1"".
                For RHEL8 with command "sudo fips-mode-setup --enable".
            3. Reboot the instance.
            4. Connect the instance again after reboot, check kernel command line "cat /proc/cmdline" and loaded cpus "cat /proc/cpuinfo".
        pass_criteria: 
            The instance can boot as normal with fips enabled, and there isn't error or Call Trace in dmesg.
            For RHEL7, There is fips=1 in kernel commanline.
            For RHEL8, fips-mode-setup is enabled with command "sudo fips-mode-setup --check".
        '''
        self.log.info("Check system can boot with fips=1")
        self.session.connect(timeout=self.ssh_wait_timeout)
        cmd = 'uname -r'
        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        if 'el7' in output:
            utils_lib.run_cmd(self,
                       'sudo dracut -v -f',
                        msg='regenerate the initramfs!',
                        timeout=600)
            cmd = 'sudo grubby --update-kernel=ALL --args="fips=1"'
            utils_lib.run_cmd(self, cmd, msg='Enable fips!', timeout=600)
            self.log.info('Reboot system!')
            self.vm.reboot(wait=True)
            if 'metal' in self.vm.instance_type:
                self.log.info("Wait %s" % self.ssh_wait_timeout)
                time.sleep(2 * self.ssh_wait_timeout)
            else:
                self.log.info("Wait 300s")
                time.sleep(300)
            self.session.connect(timeout=self.ssh_wait_timeout)
            utils_lib.run_cmd(self, 'cat /proc/cmdline', expect_kw='fips=1')
            utils_lib.run_cmd(self, 'dmesg', msg='save dmesg')
            cmd = 'sudo grubby --update-kernel=ALL  --remove-args="fips=1"'
            utils_lib.run_cmd(self, cmd, msg='Disable fips!')
        else:
            cmd = 'sudo fips-mode-setup --enable'
            utils_lib.run_cmd(self, cmd, msg='Enable fips!', timeout=600)
            self.log.info('Reboot system!')
            self.vm.reboot(wait=True)
            if 'metal' in self.vm.instance_type:
                self.log.info("Wait %s" % self.ssh_wait_timeout)
                time.sleep(2 * self.ssh_wait_timeout)
            else:
                self.log.info("Wait 300s")
                time.sleep(300)
            self.session.connect(timeout=self.ssh_wait_timeout)
            utils_lib.run_cmd(self, 'cat /proc/cmdline', expect_kw='fips=1')
            utils_lib.run_cmd(self,
                        'sudo fips-mode-setup --check',
                        expect_kw='enabled')
            utils_lib.run_cmd(self, 'dmesg', msg='save dmesg')
            cmd = 'sudo fips-mode-setup --disable'
            utils_lib.run_cmd(self, cmd, msg='Disable fips!')
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
        description:
            Test boot debug kernel on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]LifeCycleTest.test_boot_debugkernel"
        bugzilla_id: 
            1703366
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            LifeCycle
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance via ssh, check if debug kernel is installed.
            3. Install debug kernel packages if debug kernel isn't installed in system.
            4. Configure grubby to set debug kernel as the defualt boot kernel.
            5. Enable kmemleak with command "sudo grubby --update-kernel=ALL --args="kmemleak=on"".
            6. Reboot system.
            7. Connect the instance again after reboot, check loaded kernel, dmesg, journalctl log and memeory leak.
            8. Check memory leak with command "sudo echo scan > /sys/kernel/debug/kmemleak".
        pass_criteria: 
            The instance can boot with debug kernel, and there isn't error or Call Trace in dmesg.
            There isn't fail in journalctl log and no memory leak in /sys/kernel/debug/kmemleak.
        '''
        self.log.info("Check kernel-debug can boot up!")
        self.session.connect(timeout=self.ssh_wait_timeout)
        mini_mem = self.params.get('memory', '*/instance_types/*')
        if int(mini_mem) < 2:
            self.cancel('Cancel case as low memory')
        output = utils_lib.run_cmd(self, 'sudo lscpu', expect_ret=0)
        if 'aarch64' in output and int(mini_mem) < 4:
            self.cancel('Cancel case as low memory')

        kernel_ver = utils_lib.run_cmd(self, 'uname -r', expect_ret=0)
        if 'el7' in kernel_ver:
            debug_kernel = "/boot/vmlinuz-" + kernel_ver.strip('\n') + ".debug"
            debug_kernel_2 = kernel_ver.strip('\n') + ".debug"
        else:
            debug_kernel = "/boot/vmlinuz-" + kernel_ver.strip('\n') + "+debug"
            debug_kernel_2 = kernel_ver.strip('\n') + "+debug"

        utils_lib.run_cmd(self,
                    "sudo grubby --info=%s" % debug_kernel,
                    expect_ret=0,
                    msg="check kernel-debug installed")
        cmd = "sudo grubby --info=%s|grep index|cut -d'=' -f2" % debug_kernel
        debug_kernel_index = utils_lib.run_cmd(self,
                                         cmd,
                                         expect_ret=0,
                                         msg="check kernel-debug index")
        cmd = "sudo grubby --set-default-index=%s" % debug_kernel_index
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg="change default boot index")
        cmd = 'sudo grubby --update-kernel=ALL --args="kmemleak=on"'
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg="enable kmemleak")
        self.vm.reboot(wait=True)
        if 'metal' in self.vm.instance_type:
            self.log.info("Wait %s" % self.ssh_wait_timeout)
            time.sleep(self.ssh_wait_timeout)
        else:
            self.log.info("Wait 120s")
            time.sleep(120)
        self.session.connect(timeout=self.ssh_wait_timeout)
        utils_lib.run_cmd(self,
                    'cat /proc/cmdline',
                    expect_ret=0,
                    expect_kw=debug_kernel_2,
                    msg="checking debug kernel booted")
        utils_lib.run_cmd(self, 'dmesg', expect_ret=0, msg="saving dmesg output")
        utils_lib.run_cmd(self, 'sudo su', expect_ret=0)
        cmd = 'journalctl > /tmp/journalctl.log'
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg="saving journalctl output")
        utils_lib.run_cmd(self, 'cat /tmp/journalctl.log', expect_ret=0)
        utils_lib.run_cmd(self, "sudo systemd-analyze blame > /tmp/blame.log")
        utils_lib.run_cmd(self, "cat /tmp/blame.log")
        cmd = "sudo systemd-analyze "
        time_start = int(time.time())
        while True:
            output = utils_lib.run_cmd(self, cmd)
            if 'Bootup is not yet finished' not in output:
                break
            time_end = int(time.time())
            utils_lib.run_cmd(self, 'sudo systemctl list-jobs')
            if time_end - time_start > 180:
                self.fail("Bootup is not yet finished after 180s")
            self.log.info("Wait for bootup finish......")
            time.sleep(1)
        utils_lib.run_cmd(self, "dmesg", expect_not_kw="Call trace")
        if int(mini_mem) < 17:
            cmd = 'sudo echo scan > /sys/kernel/debug/kmemleak'
            utils_lib.run_cmd(self, cmd, expect_ret=0, timeout=1800)

            cmd = 'sudo cat /sys/kernel/debug/kmemleak'
            output = utils_lib.run_cmd(self, cmd, expect_ret=0)
            if len(output) > 0:
                self.fail('Memory leak found!')

    def tearDown(self):
        aws.done_test(self)
        if self.vm.is_created:
            if "test_boot_mitigations" in self.name.name:
                cmd = 'sudo grubby --update-kernel=ALL  --remove-args="mitigations=auto,nosmt"'
                utils_lib.run_cmd(self, cmd, msg='Remove "mitigations=auto,nosmt"')
                self.log.info('Reboot system!')
                self.vm.reboot(wait=True)
                if 'metal' in self.vm.instance_type:
                    self.log.info("Wait {}".format(self.ssh_wait_timeout))
                    time.sleep(self.ssh_wait_timeout)
                else:
                    self.log.info("Wait 60s")
                    time.sleep(60)
    
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
            if "test_boot_usbcore_quirks" in self.name.name:
                option = 'usbcore.quirks=quirks=0781:5580:bk,0a5c:5834:gij'
                cmd = 'sudo grubby --update-kernel=ALL --args="{}"'.format(option)
                utils_lib.run_cmd(self, cmd, msg='Remove "{}"'.format(option))
                self.log.info('Reboot system!')
                self.vm.reboot(wait=True)
                if 'metal' in self.vm.instance_type:
                    self.log.info("Wait {}".format(self.ssh_wait_timeout))
                    time.sleep(self.ssh_wait_timeout)
                else:
                    self.log.info("Wait 60s")
                    time.sleep(60)
            if "test_boot_hpet_mmap_enabled" in self.name.name:
                cmd = 'sudo grubby --update-kernel=ALL  --remove-args="hpet_mmap=1"'
                utils_lib.run_cmd(self, cmd, msg='Remove "hpet_mmap=1"')
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
