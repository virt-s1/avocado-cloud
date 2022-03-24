from avocado import Test
from avocado.core.exceptions import TestSkipError
from avocado_cloud.app import Setup


class CloudDiskTest(Test):
    def setUp(self):
        self.cloud = Setup(self.params, self.name)
        self.vm = self.cloud.vm
        pre_delete = False
        pre_stop = False
        if self.name.name.endswith('test_offline_attach_detach_cloud_disks'):
            pre_stop = True
        self.session = self.cloud.init_vm(pre_delete=pre_delete,
                                          pre_stop=pre_stop)

        if self.vm.disk_quantity:
            self.cloud_disk_count = self.vm.disk_quantity - 1
        else:
            self.cloud_disk_count = self.params.get(
                'cloud_disk_count', '*/Disk/*')

        self.cloud_disk_size = self.params.get('cloud_disk_size', '*/Disk/*')
        self.cloud_disk_driver = self.vm.cloud_disk_driver
        self.local_disk_driver = self.vm.local_disk_driver
        self.local_disk_count = self.vm.disk_count
        self.local_disk_size = self.vm.disk_size
        self.local_disk_type = self.vm.disk_type

        if self.name.name.endswith('test_local_disks'):
            if self.local_disk_count == 0:
                self.cancel('No local disk. Skip this case.')

        self.disk_ids = self.cloud.init_cloud_disks(self.cloud_disk_count)
        self.dev_name = 'vd'

    def _disk_test(self, disk_type, initial, disk_count, disk_size):
        """Verify each one of the disks."""

        self.log.debug('Function _disk_test: type={}, init={}, count={}, size={}'.format(
            disk_type, initial, disk_count, disk_size))

        dev_names = []
        for i in range(1, disk_count + 1):
            if disk_type == 'nvme':
                dev_fullname = 'nvme%sn1' % (initial + i - 1)
            else:
                delta = ord(initial) - 97 + i
                if delta <= 26:
                    idx = chr(96 + delta)
                else:
                    self.log.warn('disk idx exceeds "z".')
                    idx = 'a' + chr(96 + delta % 26)
                dev_fullname = self.dev_name + idx

            self._verify_disk(dev_fullname, disk_size)
            dev_names.append(dev_fullname)

        return dev_names

    def _verify_disk(self, dev_fullname, disk_size):
        """Check the size of a disk and mount, partd, format, unmount it."""

        self.log.debug('Function _verify_disk: name={}, size={}'.format(
            dev_fullname, disk_size))

        cmd = 'fdisk -l /dev/{0} | grep /dev/{0}'
        output = self.session.cmd_output(cmd.format(dev_fullname))

        # WORKAROUND: Alibaba local volume untrimmed issue
        if 'GPT' in output:
            self.log.info('WORKAROUND: Alibaba local volume untrimmed issue.')
            self.session.cmd_output(
                'dd if=/dev/zero of=/dev/{0} bs=5000 count=1'.format(
                    dev_fullname))
            output = self.session.cmd_output(cmd.format(dev_fullname))

        if output.split(',')[1].split(' ')[2] == 'bytes':
            real_size = int(output.split(',')[1].split(' ')[1])
        else:
            self.fail('Fail to get the real disk size.')

        # The disk_size was specified in GiB, should covert to bytes
        expected_size = int(disk_size) * (1024**3)

        self.log.info(
            'real_size: {0}; expected_size: {1}; delta: 1/1000.'.format(
                real_size, expected_size))

        self.assertAlmostEqual(first=real_size,
                               second=expected_size,
                               delta=expected_size / 1000.0,
                               msg='Attach disk size is not as expected.\n\
Real: {0}; Expected: {1}'.format(real_size, expected_size))

        # Make a 10GB partition in case the whole disk is too large (1800G for
        # local disk)
        cmd = 'parted /dev/{0} mklabel msdos -s'
        self.session.cmd_output(cmd.format(dev_fullname))
        cmd = 'parted /dev/{0} mkpart primary ext4 0 10GB -s'
        self.session.cmd_output(cmd.format(dev_fullname))
        # cmd = 'fdisk -l /dev/{0}|grep -o '^/dev/[a-z0-9]*'|cut -b 6-'
        # part_fullname = self.session.cmd_output(cmd.format(dev_fullname))
        cmd = 'fdisk -l /dev/{0}|grep -o "^/dev/[a-z0-9]*"'
        part_fullname = self.session.cmd_output(
            cmd.format(dev_fullname)).strip().split(' ')[0].split('/')[2]
        cmd = '[[ -d /mnt/{0} ]] || mkdir /mnt/{0}'
        self.session.cmd_output(cmd.format(part_fullname))
        cmd = 'mkfs.ext4 -F /dev/{0};mount /dev/{0} /mnt/{0} && \
echo test_content > /mnt/{0}/test_file'

        self.session.cmd_output(cmd.format(part_fullname), timeout=60)
        cmd = 'cat /mnt/{0}/test_file'
        output = self.session.cmd_output(cmd.format(part_fullname))
        self.assertEqual(
            output, 'test_content',
            'Cannot write files on attached disk.\n {0}'.format(output))
        cmd = 'umount /mnt/{0}'
        self.session.cmd_output(cmd.format(part_fullname))
        cmd = 'parted /dev/{0} rm 1'
        self.session.cmd_output(cmd.format(dev_fullname))

    def test_online_attach_detach_cloud_disks(self):
        """Test case for avocado framework.

        case_name:
            [Aliyun]CloudDiskTest.test_online_attach_detach_cloud_disks
        description:
            Test case for checking online attach and detach cloud disk.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]CloudDiskTest.test_online_attach_detach_cloud_disks"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Online attach cloud disks to VM;
            2. Verify the cloud disks inside the VM;
            3. Online detach cloud disks;
            4. Check if they are disappeared;
        pass_criteria:
            All the functionality should work normally.
        """

        self.log.info('Online attach a cloud disk to VM')

        vols = self.vm.query_cloud_disks()
        for vol in vols:
            s = vol.get('status') or vol.get('Status')
            self.assertEqual(s.lower(), u'available',
                             'Disk status is not available')

        for disk_id in self.disk_ids:
            self.vm.attach_cloud_disks(
                disk_id=disk_id, dev=self.dev_name, wait=True)

        vols = self.vm.query_cloud_disks()
        for vol in vols:
            s = vol.get('status') or vol.get('Status')
            self.assertEqual(s.lower().replace('_', '-'), u'in-use',
                             'Disk status is not in-use')

        self.session.cmd_output('sudo su -')

        # Test cloud disks
        self.log.debug('self.cloud_disk_driver = {}'.format(
            self.cloud_disk_driver))
        self.log.debug('self.cloud_disk_count = {}'.format(
            self.cloud_disk_count))
        self.log.debug('self.cloud_disk_size = {}'.format(
            self.cloud_disk_size))
        self.log.debug('self.local_disk_driver = {}'.format(
            self.local_disk_driver))
        self.log.debug('self.local_disk_type = {}'.format(
            self.local_disk_type))
        self.log.debug('self.local_disk_count = {}'.format(
            self.local_disk_count))
        self.log.debug('self.local_disk_size = {}'.format(
            self.local_disk_size))

        if self.cloud_disk_driver not in ('virtio_blk', 'nvme'):
            self.fail('Unsuported cloud_disk_driver "{}".'.format(
                self.cloud_disk_driver))

        if self.local_disk_driver not in ('virtio_blk', 'nvme'):
            self.fail('Unsuported local_disk_driver "{}".'.format(
                self.local_disk_driver))

        if self.cloud_disk_driver == 'virtio_blk':
            _disk_type = 'cloud_ssd'
            if self.local_disk_driver == 'nvme':
                _initial = 'b'
            else:
                _initial = chr(ord('b') + self.local_disk_count)
        else:
            _disk_type = 'nvme'
            if self.local_disk_driver == 'nvme':
                _initial = 1 + self.local_disk_count
            else:
                _initial = 1

        self.log.debug('_disk_type = {}'.format(_disk_type))
        self.log.debug('_initial = {}'.format(_initial))

        dev_names = self._disk_test(disk_type=_disk_type,
                                    initial=_initial,
                                    disk_count=self.cloud_disk_count,
                                    disk_size=self.cloud_disk_size)
        self.log.debug('dev_names = {}'.format(dev_names))

        self.log.info('Online detach a cloud disk to VM')

        for disk_id in self.disk_ids:
            self.vm.detach_cloud_disks(disk_id=disk_id, wait=True)

        vols = self.vm.query_cloud_disks()
        for vol in vols:
            s = vol.get('status') or vol.get('Status')
            self.assertEqual(s.lower(), u'available',
                             'Disk status is not available')

        for dev in dev_names:
            cmd = 'fdisk -l /dev/{} 2>/dev/null'.format(dev)
            output = self.session.cmd_output(cmd)
            self.assertEqual(
                output, '', 'Disk not detached.\n {}'.format(output))

    def test_offline_attach_detach_cloud_disks(self):
        """Test case for avocado framework.

        case_name:
            [Aliyun]CloudDiskTest.test_offline_attach_detach_cloud_disks
        description:
            Test case for checking offline attach and detach cloud disk.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]CloudDiskTest.test_offline_attach_detach_cloud_disks"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Stop the instance and offline attach cloud disks to VM;
            2. Start the VM and verify the cloud disks inside the VM;
            3. Stop the instance and offline detach cloud disks;
            4. Start the VM and check if they are disappeared;
        pass_criteria:
            All the functionality should work normally.
        """

        # Set timeout for Alibaba baremetal
        if 'ecs.ebm' in self.vm.flavor:
            connect_timeout = 600
        else:
            connect_timeout = 120

        self.log.info('Offline attach a cloud disk to VM')

        vols = self.vm.query_cloud_disks()
        for vol in vols:
            s = vol.get('status') or vol.get('Status')
            self.assertEqual(s.lower(), u'available',
                             'Disk status is not available')

        for disk_id in self.disk_ids:
            self.vm.attach_cloud_disks(
                disk_id=disk_id, dev=self.dev_name, wait=True)

        vols = self.vm.query_cloud_disks()
        for vol in vols:
            s = vol.get('status') or vol.get('Status')
            self.assertEqual(s.lower().replace('_', '-'), u'in-use',
                             'Disk status is not in-use')

        self.vm.start(wait=True)
        self.session.connect(timeout=connect_timeout)
        output = self.session.cmd_output('whoami')
        self.assertEqual(
            self.vm.vm_username, output,
            'Start VM error: output of cmd `who` unexpected -> %s' % output)
        self.session.cmd_output('sudo su -')

        # Test cloud disks
        self.log.debug('self.cloud_disk_driver = {}'.format(
            self.cloud_disk_driver))
        self.log.debug('self.cloud_disk_count = {}'.format(
            self.cloud_disk_count))
        self.log.debug('self.cloud_disk_size = {}'.format(
            self.cloud_disk_size))
        self.log.debug('self.local_disk_driver = {}'.format(
            self.local_disk_driver))
        self.log.debug('self.local_disk_type = {}'.format(
            self.local_disk_type))
        self.log.debug('self.local_disk_count = {}'.format(
            self.local_disk_count))
        self.log.debug('self.local_disk_size = {}'.format(
            self.local_disk_size))

        if self.cloud_disk_driver not in ('virtio_blk', 'nvme'):
            self.fail('Unsuported cloud_disk_driver "{}".'.format(
                self.cloud_disk_driver))

        if self.local_disk_driver not in ('virtio_blk', 'nvme'):
            self.fail('Unsuported local_disk_driver "{}".'.format(
                self.local_disk_driver))

        if self.cloud_disk_driver == 'virtio_blk':
            _disk_type = 'cloud_ssd'
            if self.local_disk_driver == 'nvme':
                _initial = 'b'
            else:
                _initial = chr(ord('b') + self.local_disk_count)
        else:
            _disk_type = 'nvme'
            if self.local_disk_driver == 'nvme':
                _initial = 1 + self.local_disk_count
            else:
                _initial = 1

        self.log.debug('_disk_type = {}'.format(_disk_type))
        self.log.debug('_initial = {}'.format(_initial))

        dev_names = self._disk_test(disk_type=_disk_type,
                                    initial=_initial,
                                    disk_count=self.cloud_disk_count,
                                    disk_size=self.cloud_disk_size)
        self.log.debug('dev_names = {}'.format(dev_names))

        self.log.info('Offline detach a cloud disk to VM')

        self.vm.stop(wait=True)
        self.assertTrue(self.vm.is_stopped(),
                        'Stop VM error: VM status is not SHUTOFF')

        for disk_id in self.disk_ids:
            self.vm.detach_cloud_disks(disk_id=disk_id, wait=True)

        vols = self.vm.query_cloud_disks()
        for vol in vols:
            s = vol.get('status') or vol.get('Status')
            self.assertEqual(s.lower(), u'available',
                             'Disk status is not available')

        self.vm.start(wait=True)
        self.session.connect(timeout=connect_timeout)
        output = self.session.cmd_output('whoami')
        self.assertEqual(
            self.vm.vm_username, output,
            'Start VM error: output of cmd `who` unexpected -> %s' % output)
        self.session.cmd_output('sudo su -')

        for dev in dev_names:
            cmd = 'fdisk -l /dev/{} 2>/dev/null'.format(dev)
            output = self.session.cmd_output(cmd)
            self.assertEqual(
                output, '', 'Disk not detached.\n {}'.format(output))

    def test_local_disks(self):
        """Test case for avocado framework.

        case_name:
            [Aliyun]CloudDiskTest.test_local_disks
        description:
            Test case for checking local disks.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]CloudDiskTest.test_local_disks"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Check the amount of the local disks inside the VM;
            2. Verify each disk by mounting, formating, unmounting;
        pass_criteria:
            All the functionality should work normally.
        """

        self.log.info('Test local disks on VM')
        self.session.cmd_output('sudo su -')

        # Test local disks
        self.log.debug('self.cloud_disk_driver = {}'.format(
            self.cloud_disk_driver))
        self.log.debug('self.cloud_disk_count = {}'.format(
            self.cloud_disk_count))
        self.log.debug('self.cloud_disk_size = {}'.format(
            self.cloud_disk_size))
        self.log.debug('self.local_disk_driver = {}'.format(
            self.local_disk_driver))
        self.log.debug('self.local_disk_type = {}'.format(
            self.local_disk_type))
        self.log.debug('self.local_disk_count = {}'.format(
            self.local_disk_count))
        self.log.debug('self.local_disk_size = {}'.format(
            self.local_disk_size))

        if self.cloud_disk_driver not in ('virtio_blk', 'nvme'):
            self.fail('Unsuported cloud_disk_driver "{}".'.format(
                self.cloud_disk_driver))

        if self.local_disk_driver not in ('virtio_blk', 'nvme'):
            self.fail('Unsuported local_disk_driver "{}".'.format(
                self.local_disk_driver))

        if self.local_disk_driver == 'virtio_blk':
            _disk_type = self.local_disk_type
            if self.cloud_disk_driver == 'nvme':
                _initial = 'a'
            else:
                _initial = 'b'
        else:
            _disk_type = 'nvme'
            if self.cloud_disk_driver == 'nvme':
                _initial = 1
            else:
                _initial = 0

        self.log.debug('_disk_type = {}'.format(_disk_type))
        self.log.debug('_initial = {}'.format(_initial))

        dev_names = self._disk_test(disk_type=_disk_type,
                                    initial=_initial,
                                    disk_count=self.local_disk_count,
                                    disk_size=self.local_disk_size)
        self.log.debug('dev_names = {}'.format(dev_names))

    def tearDown(self):
        self.log.info('TearDown')
