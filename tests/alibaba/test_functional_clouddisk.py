from avocado import Test
from avocado.core.exceptions import TestSkipError
from avocado_cloud.app import Setup


class CloudDiskTest(Test):
    def setUp(self):
        self.cloud = Setup(self.params, self.name)
        self.vm = self.cloud.vm
        pre_delete = False
        pre_stop = False
        if self.name.name.endswith(
                "test_offline_attach_detach_cloud_disks"
        ) or self.name.name.endswith(
                "test_offline_attach_detach_scsi_cloud_disks"):
            pre_stop = True
        self.session = self.cloud.init_vm(pre_delete=pre_delete,
                                          pre_stop=pre_stop)
        self.cloud_disk_count = self.params.get('cloud_disk_count', '*/Disk/*')
        self.cloud_disk_size = self.params.get('cloud_disk_size', '*/Disk/*')
        self.local_disk_count = self.params.get(
            'disk_count', '*/{0}/*'.format(self.vm.flavor), 0)
        self.local_disk_size = self.params.get(
            'disk_size', '*/{0}/*'.format(self.vm.flavor), 0)
        self.local_disk_type = self.params.get(
            'disk_type', '*/{0}/*'.format(self.vm.flavor), "")
        if self.name.name.endswith("test_local_disks"):
            if self.local_disk_count == 0:
                self.cancel("No local disk. Skip this case.")
        self.disk_ids = self.cloud.init_cloud_disks(self.cloud_disk_count)
        if self.cloud.cloud_provider == "huawei" and \
           self.params.get('virt', '*/{0}/*'.format(self.vm.flavor)) == "kvm":
            self.scsi_disk = True
            self.disk_ids_scsi = self.cloud.init_cloud_disks(
                self.cloud_disk_count, scsi=True)
        if self.cloud.cloud_provider == "alibaba":
            self.dev_name = "vd"
        elif self.cloud.cloud_provider == "huawei" and \
                self.params.get(
                    'virt', '*/{0}/*'.format(self.vm.flavor)) == "xen":
            self.dev_name = "xvd"
        elif self.cloud.cloud_provider == "huawei" and \
                self.params.get(
                    'virt', '*/{0}/*'.format(self.vm.flavor)) == "kvm":
            self.dev_name = "vd"
        else:
            self.dev_name = "vd"

    def _cloud_disk_test(self,
                         initial="b",
                         disk_count=None,
                         disk_type=None,
                         disk_size=None):
        if not disk_count:
            disk_count = self.cloud_disk_count
        if not disk_size:
            disk_size = self.cloud_disk_size
        for i in range(1, disk_count + 1):
            if disk_type == "nvme":
                dev_fullname = "nvme%sn1" % (i - 1)
            else:
                if disk_type == "scsi":
                    dev_name = "sd"
                else:
                    dev_name = self.dev_name
                delta = ord(initial) - 97 + i
                if delta <= 26:
                    idx = chr(96 + delta)
                else:
                    idx = 'a' + chr(96 + delta % 26)
                dev_fullname = dev_name + idx
            self._verify_disk(dev_fullname, disk_size)

    def _verify_disk(self, dev_fullname, disk_size):
        cmd = "fdisk -l /dev/{0} | grep /dev/{0}"
        output = self.session.cmd_output(cmd.format(dev_fullname))

        if self.cloud.cloud_provider == 'alibaba' and 'GPT' in output:
            self.log.info('WORKAROUND: Alibaba local volume untrimmed issue.')
            self.session.cmd_output(
                'dd if=/dev/zero of=/dev/{0} bs=5000 count=1'.format(
                    dev_fullname))
            output = self.session.cmd_output(cmd.format(dev_fullname))

        # if output.split(',')[0].split(' ')[3] == "GB":
        #     expected_size = float(disk_size)*(1.024**3)
        # elif output.split(',')[0].split(' ')[3] == "GiB":
        #     expected_size = float(disk_size)
        # else:
        #     self.fail("Attach disk size unit is not GB or GiB.")
        #
        # real_size = float(output.split(',')[0].split(' ')[2])

        # Get the real size in bytes
        # The outputs for `fdisk -l /dev/{0} | grep /dev/{0}`:
        # (RHEL7.6)
        # Disk /dev/vdd: 107.4 GB, 107374182400 bytes, 209715200 sectors
        # (RHEL8.0)
        # Disk /dev/vdb: 1.8 TiB, 1919850381312 bytes, 3749707776 sectors
        if output.split(',')[1].split(' ')[2] == "bytes":
            real_size = int(output.split(',')[1].split(' ')[1])
        else:
            self.fail("Fail to get the real disk size.")

        # The disk_size was specified in GiB, should covert to bytes
        expected_size = int(disk_size) * (1024**3)

        self.log.info(
            "real_size: {0}; expected_size: {1}; delta: 1/1000.".format(
                real_size, expected_size))

        self.assertAlmostEqual(first=real_size,
                               second=expected_size,
                               delta=expected_size / 1000.0,
                               msg="Attach disk size is not as expected.\n\
Real: {0}; Expected: {1}".format(real_size, expected_size))

        # Make a 10GB partition in case the whole disk is too large (1800G for
        # local disk)
        cmd = "parted /dev/{0} mklabel msdos -s"
        self.session.cmd_output(cmd.format(dev_fullname))
        cmd = "parted /dev/{0} mkpart primary ext4 0 10GB -s"
        self.session.cmd_output(cmd.format(dev_fullname))
        # cmd = "fdisk -l /dev/{0}|grep -o '^/dev/[a-z0-9]*'|cut -b 6-"
        # part_fullname = self.session.cmd_output(cmd.format(dev_fullname))
        cmd = "fdisk -l /dev/{0}|grep -o '^/dev/[a-z0-9]*'"
        part_fullname = self.session.cmd_output(
            cmd.format(dev_fullname)).strip().split(" ")[0].split("/")[2]
        cmd = "[[ -d /mnt/{0} ]] || mkdir /mnt/{0}"
        self.session.cmd_output(cmd.format(part_fullname))
        cmd = "mkfs.ext4 -F /dev/{0};mount /dev/{0} /mnt/{0} && \
echo test_content > /mnt/{0}/test_file"

        self.session.cmd_output(cmd.format(part_fullname), timeout=60)
        cmd = "cat /mnt/{0}/test_file"
        output = self.session.cmd_output(cmd.format(part_fullname))
        self.assertEqual(
            output, "test_content",
            "Cannot write files on attached disk.\n {0}".format(output))
        cmd = "umount /mnt/{0}"
        self.session.cmd_output(cmd.format(part_fullname))
        cmd = "parted /dev/{0} rm 1"
        self.session.cmd_output(cmd.format(dev_fullname))

    def test_online_attach_detach_cloud_disks(self):
        self.log.info("Online attach a cloud disk to VM")
        vols = self.vm.query_cloud_disks()
        for vol in vols:
            s = vol.get("status") or vol.get("Status")
            self.assertEqual(s.lower(), u'available',
                             "Disk status is not available")
        for disk_id in self.disk_ids:
            if self.dev_name == "xvd":
                dev = "sd"
            else:
                dev = "vd"
            if self.local_disk_type == "scsi" and dev == "sd":
                self.vm.attach_cloud_disks(
                    disk_id=disk_id,
                    dev=dev,
                    local_disk_count=self.local_disk_count,
                    wait=True)
            else:
                self.vm.attach_cloud_disks(disk_id=disk_id, dev=dev, wait=True)
        vols = self.vm.query_cloud_disks()
        for vol in vols:
            s = vol.get("status") or vol.get("Status")
            self.assertEqual(s.lower().replace('_', '-'), u"in-use",
                             "Disk status is not in-use")
        self.session.cmd_output('sudo su -')

        if self.local_disk_type in ('ssd', 'hdd'):  # for alibaba
            self._cloud_disk_test(initial=chr(98 + self.local_disk_count))
        else:
            self._cloud_disk_test()

        self.log.info("Online detach a cloud disk to VM")
        for disk_id in self.disk_ids:
            self.vm.detach_cloud_disks(disk_id=disk_id, wait=True)
        vols = self.vm.query_cloud_disks()
        for vol in vols:
            s = vol.get("status") or vol.get("Status")
            self.assertEqual(s.lower(), u'available',
                             "Disk status is not available")
        for i in range(1, self.cloud_disk_count + 1):
            delta = self.local_disk_count + i
            if delta <= 25:
                idx = chr(97 + delta)
            else:
                idx = 'a' + chr(97 - 1 + delta % 25)
            cmd = "fdisk -l | grep /dev/%s%s"
            output = self.session.cmd_output(cmd % (self.dev_name, idx))
            self.assertEqual(output, "",
                             "Disk not detached.\n {0}".format(output))

    def test_online_attach_detach_scsi_cloud_disks(self):
        self.dev_name = "sd"
        if self.params.get('virt', '*/{0}/*'.format(self.vm.flavor)) != "kvm":
            self.log.info(
                "SCSI disk attach/detach only supported on KVM hypervisor")
            raise TestSkipError
        self.log.info("Online attach a scsi cloud disk to VM")
        vols = self.vm.query_cloud_disks(scsi=True)
        for vol in vols:
            s = vol.get("status") or vol.get("Status")
            self.assertEqual(s.lower(), u'available',
                             "Disk status is not available")
        for disk_id in self.disk_ids_scsi:
            dev = "sd"
            if self.local_disk_type == "scsi":
                self.vm.attach_cloud_disks(
                    disk_id=disk_id,
                    dev=dev,
                    local_disk_count=self.local_disk_count,
                    wait=True)
            else:
                self.vm.attach_cloud_disks(disk_id=disk_id, dev=dev, wait=True)
        vols = self.vm.query_cloud_disks(scsi=True)
        for vol in vols:
            s = vol.get("status") or vol.get("Status")
            self.assertEqual(s.lower().replace('_', '-'), u"in-use",
                             "Disk status is not in-use")
        self.session.cmd_output('sudo su -')
        if self.local_disk_type == "scsi":
            self._cloud_disk_test(initial=chr(97 + self.local_disk_count))
        else:
            self._cloud_disk_test(initial="a")

        self.log.info("Online detach a scsi cloud disk to VM")
        for disk_id in self.disk_ids_scsi:
            self.vm.detach_cloud_disks(disk_id=disk_id, wait=True, scsi=True)
        vols = self.vm.query_cloud_disks(scsi=True)
        for vol in vols:
            s = vol.get("status") or vol.get("Status")
            self.assertEqual(s.lower(), u'available',
                             "Disk status is not available")
        for i in range(1, self.cloud_disk_count + 1):
            delta = self.local_disk_count + i
            if delta <= 25:
                idx = chr(97 + delta)
            else:
                idx = 'a' + chr(97 - 1 + delta % 25)
            cmd = "fdisk -l | grep /dev/%s%s"
            output = self.session.cmd_output(cmd % (self.dev_name, idx))
            self.assertEqual(output, "",
                             "Disk not detached.\n {0}".format(output))

    def test_offline_attach_detach_cloud_disks(self):
        self.log.info("Offline attach a cloud disk to VM")
        vols = self.vm.query_cloud_disks()
        for vol in vols:
            s = vol.get("status") or vol.get("Status")
            self.assertEqual(s.lower(), u'available',
                             "Disk status is not available")
        for disk_id in self.disk_ids:
            if self.dev_name == "xvd":
                dev = "sd"
            else:
                dev = "vd"
            if self.local_disk_type == "scsi" and dev == "sd":
                self.vm.attach_cloud_disks(
                    disk_id=disk_id,
                    dev=dev,
                    local_disk_count=self.local_disk_count,
                    wait=True)
            else:
                self.vm.attach_cloud_disks(disk_id=disk_id, dev=dev, wait=True)
        vols = self.vm.query_cloud_disks()
        for vol in vols:
            s = vol.get("status") or vol.get("Status")
            self.assertEqual(s.lower().replace('_', '-'), u"in-use",
                             "Disk status is not in-use")
        self.vm.start(wait=True)
        self.session.connect(timeout=300)
        output = self.session.cmd_output('whoami')
        self.assertEqual(
            self.vm.vm_username, output,
            "Start VM error: output of cmd `who` unexpected -> %s" % output)
        self.session.cmd_output('sudo su -')

        if self.local_disk_type in ('ssd', 'hdd'):  # for alibaba
            self._cloud_disk_test(initial=chr(98 + self.local_disk_count))
        else:
            self._cloud_disk_test()

        self.log.info("Offline detach a cloud disk to VM")
        self.vm.stop(wait=True)
        self.assertTrue(self.vm.is_stopped(),
                        "Stop VM error: VM status is not SHUTOFF")
        for disk_id in self.disk_ids:
            self.vm.detach_cloud_disks(disk_id=disk_id, wait=True)
        vols = self.vm.query_cloud_disks()
        for vol in vols:
            s = vol.get("status") or vol.get("Status")
            self.assertEqual(s.lower(), u'available',
                             "Disk status is not available")
        self.vm.start(wait=True)
        self.session.connect(timeout=300)
        output = self.session.cmd_output('whoami')
        self.assertEqual(
            self.vm.vm_username, output,
            "Start VM error: output of cmd `who` unexpected -> %s" % output)
        self.session.cmd_output('sudo su -')
        for i in range(1, self.cloud_disk_count + 1):
            delta = self.local_disk_count + i
            if delta <= 25:
                idx = chr(97 + delta)
            else:
                idx = 'a' + chr(97 - 1 + delta % 25)
            cmd = "fdisk -l | grep /dev/%s%s"
            output = self.session.cmd_output(cmd % (self.dev_name, idx))
            self.assertEqual(output, "",
                             "Disk not detached.\n {0}".format(output))

    def test_offline_attach_detach_scsi_cloud_disks(self):
        self.dev_name = "sd"
        if self.params.get('virt', '*/{0}/*'.format(self.vm.flavor)) != "kvm":
            self.log.info(
                "SCSI disk attach/detach only supported on KVM hypervisor")
            raise TestSkipError
        self.log.info("Offline attach a cloud disk to VM")
        vols = self.vm.query_cloud_disks(scsi=True)
        for vol in vols:
            s = vol.get("status") or vol.get("Status")
            self.assertEqual(s.lower(), u'available',
                             "Disk status is not available")
        for disk_id in self.disk_ids_scsi:
            dev = "sd"
            if self.local_disk_type == "scsi":
                self.vm.attach_cloud_disks(
                    disk_id=disk_id,
                    dev=dev,
                    local_disk_count=self.local_disk_count,
                    wait=True)
            else:
                self.vm.attach_cloud_disks(disk_id=disk_id, dev=dev, wait=True)
        vols = self.vm.query_cloud_disks(scsi=True)
        for vol in vols:
            s = vol.get("status") or vol.get("Status")
            self.assertEqual(s.lower().replace('_', '-'), u"in-use",
                             "Disk status is not in-use")
        self.vm.start(wait=True)
        self.session.connect(timeout=300)
        output = self.session.cmd_output('whoami')
        self.assertEqual(
            self.vm.vm_username, output,
            "Start VM error: output of cmd `who` unexpected -> %s" % output)
        self.session.cmd_output('sudo su -')
        if self.local_disk_type == "scsi":
            self._cloud_disk_test(initial=chr(97 + self.local_disk_count))
        else:
            self._cloud_disk_test(initial="a")

        self.log.info("Offline detach a cloud disk to VM")
        self.vm.stop(wait=True)
        self.assertTrue(self.vm.is_stopped(),
                        "Stop VM error: VM status is not SHUTOFF")
        for disk_id in self.disk_ids_scsi:
            self.vm.detach_cloud_disks(disk_id=disk_id, wait=True, scsi=True)
        vols = self.vm.query_cloud_disks(scsi=True)
        for vol in vols:
            s = vol.get("status") or vol.get("Status")
            self.assertEqual(s.lower(), u'available',
                             "Disk status is not available")
        self.vm.start(wait=True)
        self.session.connect(timeout=300)
        output = self.session.cmd_output('whoami')
        self.assertEqual(
            self.vm.vm_username, output,
            "Start VM error: output of cmd `who` unexpected -> %s" % output)
        self.session.cmd_output('sudo su -')
        for i in range(1, self.cloud_disk_count + 1):
            delta = self.local_disk_count + i
            if delta <= 25:
                idx = chr(97 + delta)
            else:
                idx = 'a' + chr(97 - 1 + delta % 25)
            cmd = "fdisk -l | grep /dev/%s%s"
            output = self.session.cmd_output(cmd % (self.dev_name, idx))
            self.assertEqual(output, "",
                             "Disk not detached.\n {0}".format(output))

    def test_local_disks(self):
        self.log.info("Test local disks on VM")
        self.session.cmd_output('sudo su -')

        if self.cloud.cloud_provider == "alibaba":
            initial = 'b'
        else:
            initial = 'a'

        self._cloud_disk_test(initial=initial,
                              disk_count=self.local_disk_count,
                              disk_type=self.local_disk_type,
                              disk_size=self.local_disk_size)

    def tearDown(self):
        self.log.info("TearDown")
