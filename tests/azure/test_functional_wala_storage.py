import time
import re
from avocado import Test
from avocado import main
from avocado_cloud.app import Setup
from avocado_cloud.app.azure import AzureAccount
from avocado_cloud.app.azure import AzureImage


class StorageTest(Test):
    """
    :avocado: tags=wala,storage
    """
    def setUp(self):
        account = AzureAccount(self.params)
        account.login()
        self.case_short_name = re.findall(r"Test.(.*)", self.name.name)[0]
        self.project = self.params.get("rhel_ver", "*/VM/*")
        # Multiple disk test need DS2_v2 size
        cloud = Setup(self.params, self.name, size="DS2_v2")
        if self.case_short_name == "test_verify_storage_rule_gen2":
            cloud.vm.vm_name += "-gen2"
            self.image = AzureImage(self.params, generation="V2")
            if not self.image.exists():
                self.image.create()
            cloud.vm.image = self.image.name
            cloud.vm.use_unmanaged_disk = False
        self.vm = cloud.vm
        self.session = cloud.init_vm()
        self.session.cmd_output("sudo su -")
        self.username = self.vm.vm_username

    def _disk_part(self,
                   disk,
                   partition=1,
                   del_part=True,
                   label="msdos",
                   start=None,
                   end=None,
                   size=None):
        self.log.info("DISK: %s", disk)
        if del_part:
            self.session.cmd_output("parted -s %s rm %d" % (disk, partition))
        current_label = self.session.cmd_output(
            "parted {0} print|grep Partition".format(disk))
        if ("unknown" in current_label) or (label not in current_label):
            self.session.cmd_output("parted -s {0} mklabel {1}".format(
                disk, label))
        min, max = self.session.cmd_output(
            "parted %s unit GB p free|grep Free|tail -1" % disk).replace(
                "GB", "").split()[0:2]
        if not start:
            start = min
        if not end:
            end = max
        # If size is set, the "end" config will be ignored
        if size:
            end = float(start) + size
        start = start if "GB" in str(start).upper() else str(start) + "GB"
        end = end if "GB" in str(end).upper() else str(end) + "GB"
        self.session.cmd_output("parted %s mkpart primary %s %s" %
                                (disk, start, end))
        output = self.session.cmd_output(
            "parted -s {0} print".format(disk + str(partition)))
        if "Could not stat device" in output:
            self.session.send_line("sudo reboot\n")
            time.sleep(10)
            self.session.connect()
            output = self.session.cmd_output(
                "parted -s {0} print".format(disk + str(partition)))
            if "Could not stat device" in output:
                self.error("Fail to part disk " + disk)

    def _disk_mount(self,
                    disk,
                    mount_point,
                    fstype="ext4",
                    partition=1,
                    del_part=True,
                    start=None,
                    end=None,
                    size=None):
        self._disk_part(disk,
                        partition=partition,
                        del_part=del_part,
                        start=start,
                        end=end,
                        size=size)
        self.session.cmd_output("mkfs.{0} %s".format(fstype) % disk +
                                str(partition),
                                timeout=300)
        self.session.cmd_output("mkdir -p %s" % mount_point)
        self.session.cmd_output("mount %s %s" %
                                (disk + str(partition), mount_point))
        if self.session.cmd_output("mount | grep %s" % mount_point) == "":
            self.error("Fail to mount %s to %s" %
                       (disk + str(partition), mount_point))

    def _disk_check(self, mount_point):
        self.session.cmd_output("touch %s" % mount_point + "/file1")
        self.session.cmd_output("echo \"test\" > %s" % mount_point + "/file1")
        self.session.cmd_output("mkdir %s" % mount_point + "/folder1")
        if self.session.cmd_output("cat %s" % mount_point +
                                   "/file1").strip('\n') != "test":
            self.error("Fail to write in %s" % mount_point + "/file1")
        self.session.cmd_output(
            "cp %s %s" % (mount_point + "/file1", mount_point + "/file2"))
        self.session.cmd_output("rm -f %s" % mount_point + "/file1")
        if "No such file or directory" not in self.session.cmd_output(
                "ls %s" % mount_point + "/file1"):
            self.error("Fail to remove file from %s" % mount_point + "/file1")

    @property
    def postfix(self):
        return time.strftime("%m%d%H%M%S", time.localtime())

    def _check_in_link(self, device, links):
        self.assertIn(device, links,
                      "No {0} link in disk links".format(device))
        self.log.info("{0} is in disk links. Pass.".format(device))

    def _check_not_in_link(self, device, links):
        self.assertNotIn(device, links,
                         "Link {0} should not in disk links".format(device))
        self.log.info("{0} is not in disk links. Pass.".format(device))

    def _get_links(self, disk_path):
        return self.session.cmd_output("ls -l " + disk_path)

    def _attach_disk(self, disk_name, disk_size, generation):
        """
        If gen1, attach unmanaged disk; if gen2, attach managed disk
        """
        if generation == 'gen1':
            self.vm.unmanaged_disk_attach(disk_name, disk_size)
        else:
            self.vm.disk_attach(disk_name, disk_size)
        time.sleep(5)

    def _detach_disk(self, disk_name, generation):
        """
        If gen1, detach unmanaged disk; if gen2, detach managed disk
        """
        if generation == 'gen1':
            self.vm.unmanaged_disk_detach(disk_name)
        else:
            self.vm.disk_detach(disk_name)
        time.sleep(5)

    def _verify_storage_rule(self, generation):
        """
        1. Check /dev/disk/azure/, there should be soft links to sda and sdb
        2. Attach a new disk, then check /dev/disk/azure again. There should
           be a new folder scsi1, and a soft link to sdc.
        3. Create a partition of the /dev/sdc, then check /dev/disk/azure/\
           scsi1 again. There should be a soft link to sdc1
        4. Remove the partition /dev/sdc1, then check /dev/disk/azure/scsi1.
        5. Add another new disk(disk2). Create a partition and check /dev/\
           disk/azure/scsi1.
        6. Restart the VM. Then check /dev/disk/azure/scsi1.
           * The soft links might be changed. But the device_id and lun are
           matched. Can use udevadm info -a -p /sys/class/block/sdc|grep 
           ATTRS{device_id} to check the device_id
        7. Detach the disk2, then check /dev/disk/azure/scsi1 again.
        """
        azure_disk_path = "/dev/disk/azure"
        scsi1_path = azure_disk_path + "/scsi1"
        # 1. Check /sda and /sdb soft links
        self.log.info("1. Check /sda and /sdb soft links")
        links = self._get_links(azure_disk_path)
        devices_list = re.findall(r"\w+",
                                  self.session.cmd_output("cd /dev;ls sd*"))
        for device in devices_list:
            self._check_in_link(device, links)
        # There should be root and resource links
        self._check_in_link('root', links)
        self._check_in_link('resource', links)
        # 2. Attach a new disk, check /dev/disk/azure/scsi1
        self.log.info("2. Attach a new disk, check /dev/disk/azure/scsi1")
        disk1_name = "{}-disk1-{}".format(self.vm.vm_name, self.postfix)
        # if generation == 'gen1':
        #     self.vm.unmanaged_disk_attach(disk1_name, 10)
        # else:
        #     self.vm.disk_attach(disk1_name, 10)
        # time.sleep(5)
        self._attach_disk(disk1_name, 10, generation)
        links = self._get_links(scsi1_path)
        self._check_in_link("sdc", links)
        # 3. Create partition /dev/sdc1, then check /dev/disk/azure/scsi1
        self.log.info(
            "3. Create partition /dev/sdc1, then check /dev/disk/azure/scsi1")
        self._disk_part(disk="/dev/sdc", size=1)
        time.sleep(5)
        links = self._get_links(scsi1_path)
        self._check_in_link("sdc1", links)
        # 4. Remove the partition /dev/sdc1, then check /dev/disk/azure/scsi1
        self.log.info("4. Remove the partition /dev/sdc1, then check \
/dev/disk/azure/scsi1")
        self.session.cmd_output("parted /dev/sdc rm 1")
        time.sleep(5)
        links = self._get_links(scsi1_path)
        self._check_in_link("sdc", links)
        self._check_not_in_link("sdc1", links)
        # 5. Add another new disk(disk2). Create a partition and check
        # /dev/disk/azure/scsi1
        self.log.info("5. Add another new disk(disk2). Create a partition \
and check /dev/disk/azure/scsi1")
        disk2_name = "{}-disk2-{}".format(self.vm.vm_name, self.postfix)
        self._attach_disk(disk2_name, 10, generation)
        # self.vm.unmanaged_disk_attach(disk2_name, 10)
        # time.sleep(5)
        links = self._get_links(scsi1_path)
        self._disk_part(disk="/dev/sdd", size=1)
        time.sleep(5)
        links = self._get_links(scsi1_path)
        self._check_in_link("sdd", links)
        self._check_in_link("sdd1", links)
        disk1_identifier = self.session.cmd_output("fdisk -l /dev/sdc | grep 'Disk identifier'")
        disk2_identifier = self.session.cmd_output("fdisk -l /dev/sdd | grep 'Disk identifier'")
        # 6. Restart the VM. Then check /dev/disk/azure/scsi1
        self.log.info("6. Restart the VM. Then check /dev/disk/azure/scsi1")
        self.vm.reboot()
        self.session.connect()
        self.session.cmd_output("sudo su -")
        for device in ['sda', 'sdb', 'sdc', 'sdd']:
            tmp_identifier = self.session.cmd_output("fdisk -l /dev/{} | grep 'Disk identifier'".format(device))
            if disk1_identifier == tmp_identifier:
                disk1 = device
            if disk2_identifier == tmp_identifier:
                disk2 = device
        links = self._get_links(scsi1_path)
        for device in [disk1, disk2, disk2+"1"]:
            self._check_in_link(device, links)
        # 7. Detach the disk2, then check /dev/disk/azure/scsi1 again
        self.log.info(
            "7. Detach the disk2, then check /dev/disk/azure/scsi1 again")
        # self.vm.unmanaged_disk_detach(disk2_name)
        # time.sleep(5)
        self._detach_disk(disk2_name, generation)
        links = self._get_links(scsi1_path)
        self._check_in_link(disk1, links)
        self._check_not_in_link(disk2, links)
        self._check_not_in_link(disk2+"1", links)

    def test_verify_storage_rule_gen1(self):
        """
        :avocado: tags=tier2
        RHEL7-90706	WALA-TC: [Storage] Verify storage rule - Gen1
        """
        self.log.info("RHEL7-90706	WALA-TC: [Storage] Verify storage rule - Gen1")
        self._verify_storage_rule('gen1')

    def test_verify_storage_rule_gen2(self):
        """
        :avocado: tags=tier2
        RHEL-188921	WALA-TC: [Storage] Verify storage rule - Gen2
        BZ#1859037
        """
        self.log.info("RHEL-188921	WALA-TC: [Storage] Verify storage rule - Gen2")
        self._verify_storage_rule('gen2')

    def tearDown(self):
        self.vm.delete(wait=False)


'''
    def test_disk_attach_new(self):
        """
        Attach a new disk to the VM

        :return:
        """
        self.log.info("Attach a new disk to the vm %s",
                      self.vm_params["VMName"])
        # Attach 3 new disks with different host-caching
        self.assertTrue(self.vm.verify_alive())
        for bn in range(1, 4):
            self.assertEqual(
                self.vm.disk_attach_new(self.blob_list[bn].params.get("size"),
                                        self.blob_list[bn].params), 0,
                "Fail to attach new disk %s host-caching: azure cli fail" %
                self.blob_params.get("host_caching"))
            time.sleep(5)
            self.vm.wait_for_running()
            # parted, mkfs, mount, test
            self.assertTrue(self.vm.verify_alive(), "Cannot login")
            disk = self.vm.get_device_name()
            self.assertIsNotNone(
                disk,
                "Fail to attach new disk %s host-caching: no device name" %
                self.blob_params.get("host_caching"))
            mount_point = "/mnt/newdisk%d" % bn
            self.assertTrue(
                self.vm.vm_disk_mount(disk=disk,
                                      mount_point=mount_point,
                                      size=1), "Fail to mount disk")
            self.assertTrue(self.vm.vm_disk_check(mount_point),
                            "Fail to check disk")

    def test_disk_detach(self):
        """
        Detach a disk from VM
        :return:
        """
        self.log.info("Detach a disk from VM")
        # Attach a disk first
        mount_point = "/mnt/newdisk1"
        self.assertEqual(
            self.vm.disk_attach_new(self.blob_list[1].params.get("size"),
                                    self.blob_list[1].params), 0,
            "Fail to attach new disk before detach: azure cli fail")
        time.sleep(5)
        self.vm.wait_for_running()
        self.assertTrue(self.vm.verify_alive(), "Cannot login")
        disk = self.vm.get_device_name()
        self.assertIsNotNone(
            disk, "Fail to attach new disk before detach: no device name")
        self.assertTrue(
            self.vm.vm_disk_mount(disk=disk, mount_point=mount_point, size=1))
        self.assertEqual(self.vm.disk_detach(disk_lun=0), 0,
                         "Fail to detach disk: azure cli fail")
        time.sleep(5)
        self.vm.wait_for_running()
        self.assertTrue(self.vm.verify_alive(), "Cannot login")
        self.assertIn("No such file", self.session.cmd_output("ls %s" % disk),
                      "After detach, disk still exists")

    def test_disk_attach_exist(self):
        """
        Attach an existed disk to the VM
        :return:
        """
        self.log.info("Attach an existed disk to VM %s" % self.vm.name)
        mount_point = "/mnt/newdisk1"
        # Attach disk1
        self.assertEqual(
            self.vm.disk_attach_new(self.blob_list[1].params.get("size"),
                                    self.blob_list[1].params), 0,
            "Fail to attach new disk before re-attach: azure cli fail")
        time.sleep(5)
        self.vm.wait_for_running()
        self.assertTrue(self.vm.verify_alive(), "Cannot login")
        # Get the volume in VM
        disk = self.vm.get_device_name()
        self.assertIsNotNone(
            disk, "Fail to attach new disk before re-attach: no device name")
        self.assertTrue(
            self.vm.vm_disk_mount(disk=disk, mount_point=mount_point, size=1),
            "Cannot mount the disk before detach the disk.")
        self.session.cmd_output("echo \"test\" > %s/file0" % mount_point)
        self.session.cmd_output("umount %s" % mount_point)
        self.vm.vm_update()
        try:
            if self.azure_mode == "asm":
                disk_name = copy.deepcopy(
                    self.vm.params.get("DataDisks")[0].get("name"))
            else:
                disk_name = copy.deepcopy(
                    self.vm.params.get("storageProfile").get("dataDisks")
                    [0].get("name"))
                disk_name = "https://%s.blob.core.windows.net/%s/%s.vhd" % (
                    self.vm_params["StorageAccountName"],
                    self.vm_params["Container"], disk_name)
        except IndexError as e:
            self.fail("Fail to get datadisk name. Exception: %s" % str(e))
        self.log.info("DISKNAME: %s", disk_name)
        # Detach disk
        self.assertEqual(
            self.vm.disk_detach(disk_lun=0), 0,
            "Fail to detach disk before re-attach: azure cli fail")
        time.sleep(5)
        self.vm.wait_for_running()
        max_retry = 5
        for retry in xrange(1, max_retry + 1):
            try:
                self.vm.disk_attach(disk_name)
            except:
                self.log.info("Attach disk retry %d/%d times." %
                              (retry, max_retry))
            else:
                break
        else:
            self.fail("After retry %d times, fail to attach disk." % max_retry)
        time.sleep(5)
        self.vm.wait_for_running()
        self.assertTrue(
            self.vm.vm_has_datadisk(),
            "Fail to re-attached the disk: cannot get datadisk params")
        self.assertTrue(self.vm.verify_alive(), "Cannot login")
        disk = self.vm.get_device_name()
        self.assertIsNotNone(disk,
                             "Fail to re-attach the disk: no device name")
        self.session.cmd_output("mount %s %s" % (disk + "1", mount_point))
        self.assertEqual(
            self.session.cmd_output("cat %s/file0" % mount_point).strip('\n'),
            "test", "The previous data on the disk is destroyed.")
        self.assertTrue(self.vm.vm_disk_check(mount_point),
                        "The disk cannot work well.")

    def _disk_attach_detach(self):
        """
        Attach new, detach, attach existed disk to the VM
        """
        # 1. Attach 3 new disks with different host-caching
        self.log.info("1. Attach new disks to the vm %s",
                      self.vm_params["VMName"])
        self.assertTrue(self.vm.verify_alive())
        for bn in range(1, 4):
            self.assertEqual(
                self.vm.disk_attach_new(self.blob_list[bn].params.get("size"),
                                        self.blob_list[bn].params), 0,
                "Fail to attach new disk %s host-caching: azure cli fail" %
                self.blob_params.get("host_caching"))
            time.sleep(5)
            self.vm.wait_for_running()
            # parted, mkfs, mount, test
            self.assertTrue(self.vm.verify_alive(), "Cannot login")
            disk = self.vm.get_device_name()
            self.assertIsNotNone(
                disk,
                "Fail to attach new disk %s host-caching: no device name" %
                self.blob_params.get("host_caching"))
            mount_point = "/mnt/newdisk%d" % bn
            self.assertTrue(
                self.vm.vm_disk_mount(disk=disk,
                                      mount_point=mount_point,
                                      size=1), "Fail to mount disk")
            self.assertTrue(self.vm.vm_disk_check(mount_point),
                            "Fail to check disk")
        # 2. Detach the first disk
        self.log.info("2. Detach a disk from VM")
        mount_point = "/mnt/newdisk1"
        disk = "/dev/sdc"
        #        disk = self.vm.get_device_name()
        #        self.assertIsNotNone(
        #            disk,
        #            "Fail to attach new disk before detach: no device name")
        #        self.assertTrue(
        #            self.vm.vm_disk_mount(disk, mount_point,
        #                                  project=float(self.project),
        #                                  end=1000))
        self.session.cmd_output("echo \"test\" > %s/file0" % mount_point)
        self.session.cmd_output("umount %s" % mount_point)
        self.vm.vm_update()
        try:
            if self.azure_mode == "asm":
                disk_name = copy.deepcopy(
                    self.vm.params.get("DataDisks")[0].get("name"))
            else:
                disk_name = copy.deepcopy(
                    self.vm.params.get("storageProfile").get("dataDisks")
                    [0].get("name"))
                disk_name = "https://%s.blob.core.windows.net/%s/%s.vhd" % (
                    self.vm_params["StorageAccountName"],
                    self.vm_params["Container"], disk_name)
        except IndexError, e:
            self.fail("Fail to get datadisk name. Exception: %s" % str(e))
        self.log.info("DISKNAME: %s", disk_name)
        self.assertEqual(self.vm.disk_detach(disk_lun=0), 0,
                         "Fail to detach disk: azure cli fail")
        time.sleep(5)
        self.vm.wait_for_running()
        self.assertTrue(self.vm.verify_alive(), "Cannot login")
        self.assertIn("No such file", self.session.cmd_output("ls %s" % disk),
                      "After detach, disk still exists")
        # 3. Attach an existed disk
        self.log.info("3. Attach an existed disk to VM %s" % self.vm.name)
        #        # Attach disk1
        #        self.assertEqual(self.vm.disk_attach_new(
        #            self.blob_list[1].params.get("size"),
        #            self.blob_list[1].params), 0,
        #            "Fail to attach new disk before re-attach: azure cli \
        # fail")
        #        time.sleep(5)
        #        self.vm.wait_for_running()
        #        self.assertTrue(self.vm.verify_alive(), "Cannot login")
        #        # Get the volume in VM
        #        disk = self.vm.get_device_name()
        #        self.assertIsNotNone(
        #           disk, "Fail to attach new disk before re-attach: no \
        # device name")
        #        self.assertTrue(
        #            self.vm.vm_disk_mount(
        #                disk, mount_point, project=float(self.project),
        #                end=1000),
        #            "Cannot mount the disk before detach the disk.")
        # Detach disk
        #        self.assertEqual(self.vm.disk_detach(disk_lun=0), 0,
        #            "Fail to detach disk before re-attach: azure cli fail")
        #        time.sleep(5)
        #        self.vm.wait_for_running()
        max_retry = 5
        for retry in xrange(1, max_retry + 1):
            try:
                self.vm.disk_attach(disk_name)
            except:
                self.log.info("Attach disk retry %d/%d times." %
                              (retry, max_retry))
            else:
                break
        else:
            self.fail("After retry %d times, fail to attach disk." % max_retry)
        time.sleep(5)
        self.vm.wait_for_running()
        self.assertTrue(
            self.vm.vm_has_datadisk(),
            "Fail to re-attached the disk: cannot get datadisk params")
        self.assertTrue(self.vm.verify_alive(), "Cannot login")
        #        disk = self.vm.get_device_name()
        self.assertIsNotNone(disk,
                             "Fail to re-attach the disk: no device name")
        self.session.cmd_output("mount %s %s" % (disk + "1", mount_point))
        self.assertEqual(
            self.session.cmd_output("cat %s/file0" % mount_point).strip('\n'),
            "test", "The previous data in the disk is destroyed.")
        self.assertTrue(self.vm.vm_disk_check(mount_point),
                        "The disk cannot work well.")

    def test_disk_attach_detach_standard(self):
        """
        Attach new, detach, attach existed disk to the VM in standard storage
        account
        """
        self._disk_attach_detach()

    def test_disk_attach_detach_premium(self):
        """
        Attach new, detach, attach existed disk to the VM in premium storage
        account
        """
        self._disk_attach_detach()

    def test_attach_detach_64_disks(self):
        """
        Attach and Detach 64 disks
        """
        self.log.info("Attach and Detach 64 disks")
        # Login with root account
        with open(utils_misc.get_sshkey_file(), 'r') as f:
            sshkey = f.read()
        self.session.cmd_output(
            "cp -a /home/%s/.ssh /root/;chown root:root -R /root/.ssh/" %
            self.vm.username)
        self.vm.session_close()
        self.vm.username = "root"
        self.assertTrue(self.vm.verify_alive(authentication="publickey"),
                        "Cannot login with root account")
        self.vm.session_close()
        # Attach 64 disks
        disk_num = 64
        disk_blob_size = 1
        disk_blob_params = dict()
        disk_blob_params["host_caching"] = "None"
        for bn in range(1, disk_num + 1):
            self.assertEqual(
                self.vm.disk_attach_new(disk_blob_size, disk_blob_params), 0,
                "Fail to attach new disk %s" % bn)
        self.assertTrue(self.vm.wait_for_running(),
                        "After attaching 64 disks, VM cannot become running")
        self.assertTrue(self.vm.verify_alive(authentication="publickey"),
                        "After attaching 64 disks, cannot login VM")
        # Put 64 dev names into dev_list
        import string
        count = 0
        dev_list = []
        for letter1 in [''] + list(string.lowercase[:26]):
            for letter2 in list(string.lowercase[:26]):
                dev_list.append("/dev/sd%s" % (letter1 + letter2))
                count += 1
                if count == disk_num + 2:
                    break
            if count == disk_num + 2:
                break
        # remove /dev/sda and /dev/sdb
        dev_list = dev_list[2:]
        self.log.info(dev_list)
        # Check the devices
        fdisk_list = self.session.cmd_output("ls /dev/sd*").split()
        self.assertTrue(
            set(dev_list).issubset(fdisk_list),
            "Wrong devices. Devices in VM: %s" % fdisk_list)
        # Check the 64 disks
        mountpoint = "/mnt/newdisk"
        for dev in dev_list:
            self.assertTrue(
                self.vm.vm_disk_mount(disk=dev_list[0],
                                      mount_point=mountpoint,
                                      size=1,
                                      sudo=False),
                "Cannot mount the first disk")
            self.assertTrue(self.vm.vm_disk_check(mountpoint),
                            "Check disk %s result fail" % dev)
            self.session.cmd_output("umount %s" % mountpoint)
        # Detach 64 disks
        for bn in range(0, disk_num):
            self.assertEqual(self.vm.disk_detach(disk_lun=bn), 0,
                             "Fail to detach disk lun=%s: azure cli fail" % bn)
        self.assertTrue(self.vm.wait_for_running(),
                        "After detaching 64 disks, VM cannot become running")
        self.assertTrue(self.vm.verify_alive(authentication="publickey"),
                        "After detaching 64 disks, cannot login VM")
        # Check the devices
        fdisk_list = self.session.cmd_output("ls /dev/sd*").split()
        self.assertEqual(
            0, len(set(fdisk_list).intersection(set(dev_list))),
            "There's some disks left. Current disks: %s" % fdisk_list)

    def test_change_os_disk_size(self):
        """
        Change OS disk size
        """
        self.log.info("Change OS disk size")
        # Reduce os disk size
        os_disk_name = "%s.vhd" % self.vm.params.get("storageProfile").get(
            "osDisk").get("name")
        os_blob = copy.deepcopy(self.blob_list[0])
        os_blob.name = os_disk_name
        os_blob.update()
        self.log.info(os_blob.params)
        current_size_kb = int(os_blob.params.get("contentLength"))
        current_size = (current_size_kb - 512) / 1024 / 1024 / 1024
        smaller_size = current_size - 2
        larger_size = current_size + 2
        larger_size_kb = larger_size * 1024 * 1024 * 1024 + 512
        self.vm.shutdown()
        self.vm.wait_for_deallocated()
        # Change os disk size to smaller size
        self.assertEqual(
            self.vm.os_disk_resize(smaller_size), 0,
            "Fail to change os disk size smaller: azure cli fail")
        time.sleep(5)
        os_blob.update()
        self.assertEqual(int(os_blob.params.get("contentLength")),
                         current_size_kb, "OS disk size should not be reduced")
        # Change os disk size to larger size
        self.assertEqual(self.vm.os_disk_resize(larger_size), 0,
                         "Fail to change os disk size larger: azure cli fail")
        time.sleep(5)
        os_blob.update()
        self.assertEqual(int(os_blob.params.get("contentLength")),
                         larger_size_kb,
                         "OS disk size is not changed to the larger size")
        self.assertEqual(self.vm.start(), 0)
        self.assertTrue(self.vm.wait_for_running())
        self.assertTrue(self.vm.verify_alive(),
                        "Cannot start the VM after increase os disk size")
        mount_point = "/mnt/newdisk1"
        disk = "/dev/sda"
        self.assertTrue(
            self.vm.vm_disk_mount(disk=disk,
                                  mount_point=mount_point,
                                  partition=3,
                                  del_part=False),
            "Fail to part and mount %s" % disk)
        self.assertTrue(self.vm.vm_disk_check(mount_point),
                        "Fail to check the new partition on %s" % disk)
        self.log.info("Resize os disk successfully")
'''

if __name__ == "__main__":
    main()
