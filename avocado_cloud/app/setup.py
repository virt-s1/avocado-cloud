from .guest import GuestSession
from avocado.core.exceptions import TestSkipError, TestError
import time


class Setup(object):
    def __init__(self, params, name, **kwargs):
        self._filter_case(params, name)
        self.cloud_provider = params.get('provider', '*/Cloud/*')
        if self.cloud_provider == 'openstack':
            from .openstack import OpenstackVM
            self.vm = OpenstackVM(params, **kwargs)
        elif self.cloud_provider == 'aws':
            from .aws import EC2VM
            self.vm = EC2VM(params)
        elif self.cloud_provider == 'huawei':
            from .huawei import HuaweiVM
            self.vm = HuaweiVM(params)
        elif self.cloud_provider == "azure":
            from .azure import AzureVM
            self.vm = AzureVM(params, **kwargs)
        elif self.cloud_provider == "alibaba":
            from .alibaba import AlibabaVM
            self.vm = AlibabaVM(params)
        elif self.cloud_provider == "libvirt":
            from .libvirt import LibvirtVM
            self.vm = LibvirtVM(params)
        else:
            raise TestError()

    def init_vm(self, pre_delete=False, pre_stop=False):
        if pre_delete and self.vm.exists():
            self.vm.delete(wait=True)
        if not self.vm.exists():
            self.vm.create(wait=True)
        if pre_stop is False and self.vm.is_stopped():
            self.vm.start(wait=True)
        if pre_stop is True and self.vm.is_started():
            self.vm.stop(wait=True)
        session = self.init_session()
        if self.vm.is_started():
            session.connect(timeout=600)
        return session

    def init_session(self):
        return GuestSession(self.vm)

    def init_cloud_disks(self, disk_count, scsi=False):
        vols = self.vm.query_cloud_disks(scsi=scsi)
        for vol in vols:
            s = vol.get("status") or vol.get("Status")
            if s.lower().replace('_', '-') == u"in-use":
                disk_id = vol.get('id') or vol.get('DiskId')
                self.vm.detach_cloud_disks(disk_id=disk_id,
                                           wait=True,
                                           scsi=scsi)
        if len(vols) < disk_count:
            i = 0
            while i < (disk_count - len(vols)):
                self.vm.create_cloud_disk(wait=True, scsi=scsi)
                i = i + 1
        elif len(vols) > disk_count:
            i = 0
            while i < (len(vols) - disk_count):
                disk_id = vols[i].get('id') or vols[i].get('DiskId')
                self.vm.delete_cloud_disk(disk_id, wait=True)
                i = i + 1
        vols = self.vm.query_cloud_disks(scsi=scsi)
        disk_ids = list(disk.get('id') or disk.get("DiskId") for disk in vols)
        return disk_ids

    def init_nics(self, nic_count):
        self.primary_nic_id = None

        if self.cloud_provider != "alibaba":
            nics = self.vm.query_nics()
            if len(nics) > 1:
                for nic in nics:
                    try:
                        self.vm.detach_nics(self.vm.get_nic_id(nic))
                    except SystemExit:
                        pass
                for i in range(0, 30):
                    nics = self.vm.query_nics()
                    if len(nics) == 1:
                        break
                    time.sleep(10)
                else:
                    raise Exception("Fail to remove all NICs durning setup")
            self.primary_nic_id = self.vm.get_nic_id(nics[0])
        else:
            # For alibaba cloud, detach all secondary NICs
            secondary_nics = self.vm.query_secondary_nics()
            if len(secondary_nics) > 0:
                nic_ids = [self.vm.get_nic_id(nic) for nic in secondary_nics]
                self.vm.detach_nics(nic_ids, True)
            self.primary_nic_id = self.vm.get_nic_id(self.vm.query_nics()[0])

            # For alibaba cloud, need to create NICs before attach
            available_count = 0
            for nic in self.vm.list_nics():
                if nic.get("Status") == "Available":
                    available_count += 1
            while (nic_count - available_count) > 0:
                self.vm.create_nic(wait=True)
                available_count += 1

        return

    @staticmethod
    def _filter_case(params, case):
        case_name = case.name.split(':')[-1]
        if case_name not in params.get('cases', '*/test/*'):
            raise TestSkipError
