from avocado import Test
from avocado_cloud.app.aws import aws
from avocado_cloud.app.aws import EC2Volume
from avocado_cloud.utils import utils_lib
import time
import re
import json


class StorageTest(Test):
    '''
    :avocado: tags=storage,fulltest
    '''
    def _check_disk_count(self):
        '''
        check disk count via lsblk.
        For now, no exactly check result as output format may different on
        RHEL6/7/8.
        Only comparing disk count from fdisk and lsblk to vm assigned.
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        lsblk_cmd = 'sudo lsblk -d'
        vm_volumes = self.vm.get_volumes_id()
        vm_local_disks = int(self.params.get('disks',
                                             '*/instance_types/*')) - 1
        start_time = time.time()
        while True:
            output = utils_lib.run_cmd(self,
                                 lsblk_cmd,
                                 expect_ret=0,
                                 msg='Get online disk count.')
            self.log.info("lsblk result: %s" % output)
            if output.count('disk') - output.count(
                    'SWAP') - vm_local_disks != len(vm_volumes):
                self.log.info("volume cound not match assinged, try again \
later! expected: %s lsblk: %s assigned: %s" %
                              (self.params.get('disks', '*/instance_types/*'),
                               output.count('disk'), vm_volumes))
            else:
                self.log.info(
                    "volumes matches assinged! lsblk: %s assigned: %s" %
                    (output.count('disk'), vm_volumes))
                break
            end_time = time.time()
            if int(end_time) - int(start_time) > 60:
                utils_lib.run_cmd(self, 'dmesg', expect_ret=0)
                self.fail(
                    "volume cound not match assinged after attached 60s!")
            time.sleep(5)

    def _get_disk_online(self):
        '''
        Get online disks in system.
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        cmd = 'sudo lsblk -d'
        output = utils_lib.run_cmd(self,
                             cmd,
                             expect_ret=0,
                             msg='Get online disk count.')
        count = output.count('disk') - output.count('SWAP')
        self.log.info('Online disks: %s' % count)
        return count

    def _get_test_disk(self):
        '''
        If there 2+ disks found inside system, return its name for block
        testing
        '''
        cmd = 'lsblk -l -o NAME -d|grep -v NAME'
        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        disk_list = output.split('\n')
        if 'xvda' in disk_list:
            disk_list.remove('xvda')
        else:
            cmd = " sudo lsblk -o NAME,MOUNTPOINT|grep -w '/'"
            out = utils_lib.run_cmd(self, cmd)
            bootdisk = re.findall('nvme[0-9]+', out)[0]
            self.log.info("Boot disk is %s" % bootdisk)
            disk_list.remove('%sn1' % bootdisk)
        if len(disk_list) > 0:
            self.log.info("%s selected for testing." % disk_list[0])
            return disk_list[0]
        else:
            self.cancel("No addtional disk for testing. Skip test")

    def _get_blktest(self):
        '''
        Clone blktests from github
        '''
        test_disk = self._get_test_disk()
        cmd = 'sudo yum install -y blktrace fio nvme-cli git sysstat'
        utils_lib.run_cmd(self, cmd)
        cmd = 'which git'
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        utils_lib.run_cmd(self, 'sudo rm -rf blktests', expect_ret=0)
        cmd = 'git clone https://github.com/osandov/blktests.git'
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = "echo 'TEST_DEVS=(/dev/%s)' > blktests/config" % test_disk
        utils_lib.run_cmd(self, cmd, expect_ret=0)

    def setUp(self):
        self.session = None
        self.vm = None
        self.ssh_wait_timeout = None
        aws.init_test(self)

        if 'test_multi' in self.name.name or 'blktests' in self.name.name:
            self.log.info('Prepare disks for multi disk test.')
            if self.params.get('outpostarn') is not None:
                self.log.info("outpostarn specified, only gp2 disk supported for now.")
                self.disk1 = EC2Volume(self.params)
                res_id = aws.get_exists_resource_id(self.teststmpdir, 'gp2')
                if not self.disk1.reuse_init(res_id):
                    self.disk1.create(disksize=10, disktype='gp2')
                    aws.save_exists_resource_id(self.teststmpdir, self.disk1)
            else:
                self.disk1 = EC2Volume(self.params)
                res_id = aws.get_exists_resource_id(self.teststmpdir, 'standard')
                if not self.disk1.reuse_init(res_id):
                    self.disk1.create(disksize=10, disktype='standard')
                    aws.save_exists_resource_id(self.teststmpdir, self.disk1)
                self.disk2 = EC2Volume(self.params)
                res_id = aws.get_exists_resource_id(self.teststmpdir, 'gp2')
                if not self.disk2.reuse_init(res_id):
                    self.disk2.create(disksize=10, disktype='gp2')
                    aws.save_exists_resource_id(self.teststmpdir, self.disk2)
                self.disk3 = EC2Volume(self.params)
                res_id = aws.get_exists_resource_id(self.teststmpdir, 'io1')
                if not self.disk3.reuse_init(res_id):
                    self.disk3.create(disksize=100, disktype='io1')
                    aws.save_exists_resource_id(self.teststmpdir, self.disk3)
                self.disk4 = EC2Volume(self.params)
                res_id = aws.get_exists_resource_id(self.teststmpdir, 'sc1')
                if not self.disk4.reuse_init(res_id):
                    self.disk4.create(disksize=500, disktype='sc1', loops=60)
                    aws.save_exists_resource_id(self.teststmpdir, self.disk4)

    def test_ssd_trim(self):
        '''
        :avocado: tags=test_ssd_trim,acceptance,fast_check,outposts
        description:
            Test ssd trim in RHEL on AWS. Linked case RHEL7-87311.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]StorageTest.test_ssd_trim"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            Storage
        key_steps:
            1. Launch an instance which supports SSD volumes with TRIM on AWS.
            2. Check block devices information via command "$ sudo lsblk -d -O -J".
            3. If the disc-max value isn't 0B, the disk supports discard.
            4. Check the disk partition information via command "$ sudo lsblk |grep -i part".
            5. Create file system on this device via command "$ sudo mkfs.xfs /dev/nvme0n1".
            6. Mount it and make sure trim successfully via below commands.
               "$ sudo mount /dev/nvme0n1 /mnt"
               "$ sudo fstrim -v /mnt"
        pass_criteria: 
            Block devices can be mount and trimmed infomation displays, no error message or any exception.
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        self.session = self.session
        aws.check_session(self)

        cmd = 'sudo lsblk -d -O -J'
        disk_discard = None
        try:
            output = utils_lib.run_cmd(self, cmd)
            disks_dict = json.loads(output)
            disk_discard = None
            for disk in disks_dict["blockdevices"]:
                if disk["disc-max"] is not None and '0B' not in disk[
                        "disc-max"]:
                    disk_discard = disk["name"]
                    self.log.info("%s supports discard %s" %
                                  (disk_discard, disk["disc-max"]))
        except ValueError as err:
            self.log.info("lsblk no json support")
            cmd = 'sudo lsblk -o NAME,DISC-MAX -d|grep -v NAME'
            output = utils_lib.run_cmd(self, cmd)
            for disk in output.split('\n'):
                if '0B' not in disk:
                    disk_discard = disk.split(' ')[0]
                    self.log.info("%s supports discard" % disk)

        if disk_discard is None:
            self.cancel("No disk supports discard found.")
        cmd = 'sudo lsblk |grep -i part'
        output = utils_lib.run_cmd(self, cmd)
        if disk_discard not in output:
            cmd = "sudo mkfs.xfs /dev/%s" % disk_discard
            utils_lib.run_cmd(self, cmd, expect_ret=0)
            cmd = "sudo mount /dev/%s /mnt" % disk_discard
            utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = "sudo fstrim -v /mnt"
        utils_lib.run_cmd(self, cmd, expect_ret=0)

    def test_nvme_basic(self):
        '''
        :avocado: tags=test_nvme_basic,acceptance,fast_check,outposts
        description:
            Test basic nvme functions in RHEL on AWS. Linked case RHEL7-87122.
            Instances with nvme drivers include,
            X2gd, I3, I3en, 
            T3, T3a, T4g,
            C5, C5a, C5ad, C5d, C5n, 
            M5, M5a, M5ad, M5d, M5dn, M5n, M5zn,
            R5, R5a, R5ad, R5b, R5d, R5dn, R5n,
            A1, C6g, C6gd, C6gn, M6g, M6gd, R6g, R6gd, 
            F1, Inf1,
            D3, D3en,
            G4ad, G4dn, 
            P3dn, P4d,
            Mac1, z1d and so on.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]StorageTest.test_nvme_basic"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            Storage
        key_steps:
            1. Launch an instance with nvme drivers on AWS.
            2. Check block devices information via command "$ sudo lsblk".
            3. Check nvme module is loaded via command "pciutils".
            4. Install package pciutils, and check nvme pci via command "$ sudo lspci|grep Non-Volatile"
            5. Install package nvme-cli, and check nvme devices via command "sudo nvme list".
            6. Do read and write tests with non boot nvme devices via below commands.
               "sudo nvme read /dev/nvme0n1 --data-size=10000"
               "echo "write test"|sudo nvme write /dev/nvme0n1 --data-size=10000"
        pass_criteria: 
            Basic function tests pass for nmve blockers with nvme cli.
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        self.session = self.session
        aws.check_session(self)
        cmd = 'lsblk'
        out = utils_lib.run_cmd(self, cmd)
        if 'nvme' not in out:
            self.cancel('No nvme disk found!')
        aws.install_pkgs(self.session, 'pciutils')
        find_nvme_pci = 'sudo lspci|grep Non-Volatile'
        find_nvme_module = 'sudo lsmod|grep nvme'
        utils_lib.run_cmd(self,
                    find_nvme_pci,
                    expect_ret=0,
                    msg='Try to find nvme pci!')
        utils_lib.run_cmd(self,
                    find_nvme_module,
                    expect_ret=0,
                    msg='Try to find nvme module in loading drivers!')

        aws.install_pkgs(self.session, 'nvme-cli')
        nvme_list = 'sudo nvme list'
        self.log.info("CMD: %s" % nvme_list)
        output = utils_lib.run_cmd(self, nvme_list, expect_ret=0)
        search_for = re.compile(r'/dev/nvme\dn\d')
        nvme_blks = search_for.findall(output)
        if len(nvme_blks) > 0:
            self.log.info("Found nvme devices %s" % nvme_blks)
        else:
            self.fail("No nvme blks found %s" % output)
        output = utils_lib.run_cmd(self, 'lsblk', expect_ret=0)
        if 'xvda' in output:
            bootdisk = 'xvda'
        else:
            cmd = " sudo lsblk -o NAME,MOUNTPOINT|grep -w '/'"
            out = utils_lib.run_cmd(self, cmd)
            bootdisk = re.findall('nvme[0-9]+', out)[0]
        self.log.info("Boot disk is %s" % bootdisk)
        for nvme_blk in nvme_blks:
            nvme_read = 'sudo nvme read %s --data-size=10000' % nvme_blk
            utils_lib.run_cmd(self,
                        nvme_read,
                        expect_ret=0,
                        expect_kw=r'read: Success',
                        msg="%s read test" % nvme_blk)
            if bootdisk not in nvme_blk:
                nvme_write = 'echo "write test"|sudo nvme write %s \
--data-size=10000' % nvme_blk
                utils_lib.run_cmd(self,
                            nvme_write,
                            expect_ret=0,
                            expect_kw=r'write: Success',
                            msg="%s write test" % nvme_blk)

    def test_disk_info(self):
        '''
        :avocado: tags=test_disk_info,acceptance,fast_check,outposts
        description:
            Check disk information via fdisk and lsblk in RHEL on AWS. Linked case RHEL7-103855.
            For now, no exactly check result as output format may different on RHEL6/7/8.
            Only comparing disk count from fdisk and lsblk to vm assigned.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]StorageTest.test_disk_info"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            Storage
        key_steps:
            1. Launch an instance on AWS.
            2. Check disk information via command "$ sudo fdisk -l".
        pass_criteria: 
            Disk information lists as the same with instance specs, and no error, hang or crash in system.
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        self.session = self.session
        aws.check_session(self)
        fdisk_cmd = 'sudo fdisk -l'
        utils_lib.run_cmd(self, fdisk_cmd, expect_ret=0)

    def test_check_disk_count(self):
        '''
        :avocado: tags=test_check_disk_count,acceptance,fast_check,tire1,outposts
        description:
            Check disk count in RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]StorageTest.test_check_disk_count"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            Storage
        key_steps:
            1. Launch an instance on AWS.
            2. Check online disks count via command "$ sudo lsblk -d".
        pass_criteria: 
            The online disks count is the same with attached disks, and no error, hang or crash in system.
        '''
        self._check_disk_count()

    def test_multi_disk(self):
        '''
        :avocado: tags=test_multi_disk,acceptance,outposts
        description:
            Check system can boot up with multiple disks assigned on AWS. Linked case RHEL7-103954.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]StorageTest.test_multi_disk"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            Storage
        key_steps:
            1. Launch an instance on AWS.
            2. Check online disks count via command "$ sudo lsblk -d".
            3. Stop the instance. 
            4. Attach 4 disks to this instance.
            5. Start the instance.
            6. When instance is in running state, connect instance via ssh.
            7. Check online disks count again.
            8. Create partition and filesystem for the attached disks, format and mount the disk, check read and write in the attached disks.
            9. Stop the instance and detach the disks.
        pass_criteria: 
            Instance can boot up with multiple disks attached.
            The online disks count is the same with the orignial disks in spec plus attached disks.
            Read and write in attached disks work well.
            And no error, hang or crash in system.
            Disks can be detached successfully in step 8.
        '''
        vm_local_disks = int(self.params.get('disks',
                                             '*/instance_types/*')) - 1
        if self.params.get('outpostarn') is not None or vm_local_disks >= 23:
            disk_dict = {
                self.disk1: 'sdz',
            }
        else:
            disk_dict = {
                self.disk1: 'sdw',
                self.disk2: 'sdx',
                self.disk3: 'sdy',
                self.disk4: 'sdz'
            }
        # Make sure instance is in stopped state before attaching disk
        count1 = self._get_disk_online()
        self.vm.stop(loops=20)
        for i in disk_dict.keys():
            if i.is_attached():
                i.detach_from_instance(force=True)
            if not i.attach_to_instance(self.vm.instance_id, disk_dict.get(i), timeout=180):
                self.fail("Attached failed!")
        if not self.vm.start():
            self.fail("Cannot start instance")
        count2 = self._get_disk_online()
        self.vm.stop(loops=20)
        for i in disk_dict.keys():
            if not i.detach_from_instance():
                self.fail("Dettached failed!")
        if self.params.get('outpostarn') is not None:
            expected_count = 1
        else:
            expected_count = 4
        if count2 - count1 != expected_count:
            self.fail("count2(%s) - count1(%s) not equal new addded %s!" %
                      (count2, count1, expected_count))

    def test_multi_disk_hotplug(self):
        '''
        :avocado: tags=test_multi_disk_hotplug,acceptance,fast_check,outposts
        description:
            Check hotplug disks when instance is running on AWS. Linked case RHEL7-93570.
            Will add disk read&write in auto test later.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]StorageTest.test_multi_disk_hotplug"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            Storage
        key_steps:
            1. Launch an instance on AWS.
            2. Check online disks count via command "$ sudo lsblk -d".
            3. When instance is in running state, attach 4 disks to this instance.
            4. Connect instance via ssh, check online disks count again.
            5. Create partition and filesystem for the attached disks, format and mount the disks, check read and write in the attached disks.
            6. Detach the disks.
        pass_criteria: 
            Disks can be attached to the running instance successfully.
            The online disks count is the same with the orignial disks in spec plus attached disks.
            Read and write in attached disks work well.
            And no error, hang or crash in system.
            Disks can be detached successfully in step 6.
        '''
        vm_local_disks = int(self.params.get('disks',
                                             '*/instance_types/*')) - 1
        if self.params.get('outpostarn') is not None or vm_local_disks >= 23:
            disk_dict = {
                self.disk1: 'sdz',
            }
        else:
            disk_dict = {
                self.disk1: 'sdw',
                self.disk2: 'sdx',
                self.disk3: 'sdy',
                self.disk4: 'sdz'
            }
        if self.vm.is_stopped():
            self.vm.start()
        self.session.connect(timeout=self.ssh_wait_timeout)
        self.session = self.session
        aws.check_session(self)
        count1 = self._get_disk_online()
        dmesg1 = self.session.cmd_output('dmesg')
        for i in disk_dict.keys():
            if i.is_attached():
                i.detach_from_instance(force=True)
            if not i.attach_to_instance(self.vm.instance_id, disk_dict.get(i)):
                aws.get_debug_log(self)
                self.fail("Attached failed!")
        utils_lib.run_cmd(self, 'dmesg|tail -20', msg='save dmesg after attached!')
        time.sleep(30)
        count2 = self._get_disk_online()
        if self.params.get('outpostarn') is not None:
            expected_count = 1
        else:
            expected_count = 4
        if count2 - count1 != expected_count:
            self.fail("count2(%s) - count1(%s) not equal new addded %s!" %
                      (count2, count1, expected_count))
        for i in disk_dict.keys():
            if not i.detach_from_instance():
                aws.get_debug_log(self)
                self.fail("Dettached failed!")

        dmesg2 = self.session.cmd_output('dmesg')
        if not aws.compare_dmesg(dmesg1, dmesg2):
            self.fail("dmesg log check fail!")
        # test system can reboot with multidisks
        for i in disk_dict.keys():
            if i.attach_to_instance(self.vm.instance_id, disk_dict.get(i)):
                self.log.info('Attached successfully!')
            else:
                aws.get_debug_log(self)
                self.fail("Attached failed!")

        self.vm.reboot()
        self.session.connect(timeout=self.ssh_wait_timeout)
        count2 = self._get_disk_online()
        if count2 - count1 != expected_count:
            self.fail("count2(%s) - count1(%s) not equal new addded %s!" %
                      (count2, count1, expected_count))
        for i in disk_dict.keys():
            if i.detach_from_instance():
                self.log.info('Dettached successfully!')
            else:
                aws.get_debug_log(self)
                self.fail("Dettached failed!")

    def test_virsh_pci_reattach(self):
        '''
        :avocado: tags=test_virsh_pci_reattach,acceptance,outposts
        description:
            Test nodedev-detach and nodedev-reattach pci devices with virsh on AWS.
            The case is only for bare metal instances with local disks include c5d.metal, c6gd.metal, m5d.metal, m6gd.metal, r5d.metal, r6gd.metal, x2gd.metal, z1d.metal.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]StorageTest.test_virsh_pci_reattach"
        bugzilla_id: 
            1700254
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            Storage
        key_steps:
            1. Launch a bare metal instance with local disks on AWS.
            2. Configure intel_iommu=on in the grubby file to enable SR-IOV in the kernel via command "sudo grubby --update-kernel=ALL --args="intel_iommu=on""
            3. Reboot the instance.
            4. Install package libvirt via command "$ sudo yum install -y libvirt".
            5. Start libvirt service via command "$ sudo systemctl restart libvirtd".
            6. Get pci list via command "$ sudo lspci".
            7. Check the nvme pci devices via command "$ sudo find /sys/devices -name *nvme*".
            8. Use virsh to nodedev-detach non boot nvme pci device via command "$ sudo virsh nodedev-detach pci_0000_2b_00_0".
            9. Use virsh to nodedev-reattach non boot nvme pci device via command "$ sudo virsh nodedev-detach pci_0000_2b_00_0".
            10. Disable SR-IOV in kernel via command "$ sudo grubby --update-kernel=ALL --remove-args="intel_iommu=on"".
        pass_criteria: 
            nodedev-detach and nodedev-reattach pci devices with virsh on AWS success, and no panic or hang in system.
        '''
        if 'metal' in self.vm.instance_type:
            self.log.info("Instance is bare metal")
        else:
            self.log.info("Instance is xen/kvm")
            self.cancel("Only run in bare metal instances!")
        if 'd.metal' not in self.vm.instance_type:
            self.cancel("No local disk have, cancel case!")
        self.session.connect(timeout=self.ssh_wait_timeout)
        aws.check_session(self)
        utils_lib.run_cmd(self, 'which virsh', cancel_not_kw="no virsh")

        # utils_lib.run_cmd(self, 'lscpu', expect_ret=0,cancel_not_kw="Xen,aarch64,
        #     AuthenticAMD")

        cmd = 'sudo grubby --update-kernel=ALL --args="intel_iommu=on"'
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        if not self.vm.is_stopped():
            self.vm.stop(loops=4)
        if not self.vm.is_stopped():
            self.fail("Instance is not in stopped state!")

        self.log.info("Start instance %s" % self.vm.instance_id)
        if not self.vm.start(wait=True):
            self.fail("Failed to start instance!")
        self.session.connect(timeout=self.ssh_wait_timeout)
        aws.check_session(self)
        case_name = "os_tests.tests.test_general_test.TestGeneralTest.test_virsh_pci_reattach"
        utils_lib.run_os_tests(self, case_name=case_name)

        cmd = 'sudo grubby --update-kernel=ALL \
--remove-args="intel_iommu=on"'
        utils_lib.run_cmd(self, cmd, expect_ret=0, msg='clean up "intel_iommu=on"')

    def test_iostat_x(self):
        '''
        :avocado: tags=test_iostat_x,fast_check,acceptance,outposts
        description:
            os-tests check iostat output in RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]StorageTest.test_iostat_x"
        bugzilla_id: 
            1661977,1669684
        customer_case_id: 
            BZ1661977, BZ1669684
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            Storage
        key_steps:
            1. Launch an instance on AWS.
            2. Check the iostat via command "$ iostat -x".
        pass_criteria: 
            No high utils reported when no obviously read/write operations.
            eg. # iostat -x
                Linux 4.18.0-236.el8.aarch64 (ip-xx-xxx-x-xxx.us-west-2.compute.internal) 	09/28/2020 	_aarch64_	(2 CPU)
                avg-cpu:  %user   %nice %system %iowait  %steal   %idle
                           7.77    0.00    1.48    0.69    0.00   90.06
                Device            r/s     w/s     rkB/s     wkB/s   rrqm/s   wrqm/s  %rrqm  %wrqm r_await w_await aqu-sz rareq-sz wareq-sz  svctm  %util
                nvme0n1         46.06    2.82   1587.81    274.62     0.00     0.23   0.00   7.52    0.50    1.32   0.00    34.47    97.31   0.86   4.19
                nvme1n1          0.15    0.00     10.43      0.00     0.00     0.00   0.00   0.00    1.00    0.00   0.00    70.40     0.00   1.50   0.02

        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        self.session = self.session
        case_name = "os_tests.tests.test_general_check.TestGeneralCheck.test_iostat_x"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_blktests_block(self):
        '''
        :avocado: tags=test_blktests_block
        description:
            Run blktests block test in RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]StorageTest.test_blktests_block"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            1
        case_component: 
            Storage
        key_steps:
            1. Launch an instance on AWS.
            2. If there are not local disks by default in the instance, attach 4 disks for blktest.
            3. Install blktest required packages blktrace fio nvme-cli git sysstat.
            4. Download blktest "git clone https://github.com/osandov/blktests.git".
            5. Add test disks to configure file in blktest, e.g., echo 'TEST_DEVS=(/dev/nvme5n1)' > blktests/config".
            6. Run blktest block test via command "$ sudo cd blktests;sudo ./check block".
        pass_criteria: 
            There are not unknown failures in test results.
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        self.session = self.session
        aws.check_session(self)
        if int(self.params.get('disks', '*/instance_types/*')) == 1:
            self.log.info("Only 1 disk available, attached more for blktest.")
            if self.params.get('outpostarn') is not None:
                disk_dict = {
                    self.disk1: 'sds',
                }
            else:
                disk_dict = {
                    self.disk1: 'sds',
                    self.disk2: 'sdt',
                    self.disk3: 'sdu',
                    self.disk4: 'sdv'
                }
            self.session.connect(timeout=self.ssh_wait_timeout)
            self.session = self.session
            for i in disk_dict.keys():
                if i.is_attached():
                    i.detach_from_instance(force=True)
                self.log.info("Try to attach %s to %s" %
                              (i.res_id, self.vm.instance_id))
                if not i.attach_to_instance(self.vm.instance_id,
                                            disk_dict.get(i)):
                    self.fail("Attached failed!")

        self._get_blktest()
        cmd = ''
        cmd = 'cd blktests;sudo ./check block'
        # Not all cases are pass due to test tool issue
        output = utils_lib.run_cmd(self, cmd, timeout=1200)
        if output is None:
            self.fail("Cannot get output!")
        if output.count('[failed]') > 1:
            self.fail("%s failed found" % output.count('[failed]'))

        cmd = 'dmesg'
        utils_lib.run_cmd(self, cmd, msg="dmesg after test")

    def test_blktests_nvme(self):
        '''
        :avocado: tags=test_blktests_nvme
        description:
            Run blktests nvme test in RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]StorageTest.test_blktests_nvme"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            1
        case_component: 
            Storage
        key_steps:
            1. Launch an instance on AWS.
            2. If there are not local disks by default in the instance, attach 4 disks for blktest.
            3. Install blktest required packages blktrace fio nvme-cli git sysstat.
            4. Download blktest "git clone https://github.com/osandov/blktests.git".
            5. Add test disks to configure file in blktest, e.g., echo 'TEST_DEVS=(/dev/nvme5n1)' > blktests/config".
            6. Run blktest nvme test via command "$ sudo cd blktests;sudo ./check nvme".
        pass_criteria: 
            There are not unknown failures in test results.
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        self.session = self.session
        aws.check_session(self)
        if int(self.params.get('disks', '*/instance_types/*')) == 1:
            self.log.info("Only 1 disk available, attached more for blktest.")
            if self.params.get('outpostarn') is not None:
                disk_dict = {
                    self.disk1: 'sds',
                }
            else:
                disk_dict = {
                    self.disk1: 'sds',
                    self.disk2: 'sdt',
                    self.disk3: 'sdu',
                    self.disk4: 'sdv'
                }
            self.session.connect(timeout=self.ssh_wait_timeout)
            self.session = self.session
            for i in disk_dict.keys():
                if i.is_attached():
                    i.detach_from_instance(force=True)
                self.log.info("Try to attach %s to %s" %
                              (i.res_id, self.vm.instance_id))
                if not i.attach_to_instance(self.vm.instance_id,
                                            disk_dict.get(i)):
                    self.fail("Attached failed!")
        self._get_blktest()
        cmd = 'cd blktests;sudo ./check nvme'
        output = utils_lib.run_cmd(self, cmd, timeout=1200)
        # Not all cases are pass due to test tool issue
        output = utils_lib.run_cmd(self, cmd, timeout=1200)
        if output.count('[failed]') > 1:
            self.fail("%s failed found" % output.count('[failed]'))
        cmd = 'dmesg'
        utils_lib.run_cmd(self, cmd, msg="dmesg after test")

    def test_fsadm_resize(self):
        '''
        :avocado: tags=test_fsadm_resize
        description:
            os-tests check fsadm resize doesn't crash when using it without size argument in RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]StorageTest.test_fsadm_resize"
        bugzilla_id: 
            1905705
        customer_case_id: 
            BZ1905705
        maintainer: 
            xiliang
        case_priority:
            1
        case_component: 
            Storage
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance, Use "$ sudo df -h" to check the filesystem.
            3. Use "$ sudo fsadm resize $device_path" to resize the filesystem without size argument.
            4. Or use this command to instead step 2 and 3, "$ sudo fsadm resize $(findmnt -n -o source /)".
        pass_criteria: 
            fsadm does nothing since the filesystem is already at maximum size, no crash like this "/sbin/fsadm: line 818: $3: unbound variable".
        '''
        case_name = "os_tests.tests.test_general_test.TestGeneralTest.test_fsadm_resize"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_fio_cpuclock(self):
        '''
        :avocado: tags=test_fio_cpuclock,acceptance,fast_check,outposts
        description:
            os-tests use fio to test internal CPU clock in RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]StorageTest.test_fio_cpuclock"
        bugzilla_id: 
            1943474
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            Storage
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance, Use "$ sudo fio --cpuclock-test" to test internal CPU clock.
        pass_criteria: 
            cpuclock test pass.
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        case_name = "os_tests.tests.test_general_test.TestGeneralTest.test_fio_cpuclock"
        utils_lib.run_os_tests(self, case_name=case_name,timeout=1200)

    def test_fio_crctest(self):
        '''
        :avocado: tags=test_fio_crctest,acceptance,fast_check,outposts
        polarion_id:
        description:
            Use fio to test the speed of the built-in checksumming functions in RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]StorageTest.test_fio_crctest"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            Storage
        key_steps:
            1. Launch an instance on AWS.
            2. Connect the instance, Use "$ sudo fio --crctest" to test the speed of the built-in checksumming functions.
        pass_criteria: 
            crc test pass.
        '''
        self.session.connect(timeout=self.ssh_wait_timeout)
        self.session = self.session
        aws.check_session(self)
        cmd = 'sudo fio --crctest'
        utils_lib.run_cmd(
            self,
            cmd,
            expect_ret=0,
            msg='Test  the  speed  of  the built-in checksumming functions.', timeout=1200)

    def tearDown(self):
        aws.done_test(self)
        if self.vm.is_created:
            if 'test_multi' in self.name.name or 'blktests' in self.name.name:
                self.log.info('Release disk if it is not available')
                try:
                    if self.params.get('outpostarn') is not None:
                        if self.disk1.is_attached():
                            self.disk1.detach_from_instance()
                    else:
                        [disk.detach_from_instance(force=True) for disk in [self.disk1, self.disk2, self.disk3, self.disk4] if disk.is_attached()]
                except AttributeError as err:
                    self.log.info('No disk release required!')
            self.session = self.session
            try:
                if self.session is not None and self.session.session.is_responsive() is not None and self.vm.is_started():
                    aws.gcov_get(self)
                    aws.get_memleaks(self)
                    self.session.close()
                if self.name.name.endswith("test_blktests_nvme"):
                    self.vm.reboot()
                self.log.info("Try to close session")
                self.session.close()
            except Exception as err:
                self.log.info("Exception hit when try to close session: {}".format(err))
