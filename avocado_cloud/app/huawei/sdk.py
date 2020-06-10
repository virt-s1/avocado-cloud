from ..base import VM
from .huawei import ECSApi
from avocado_cloud.utils import utils_misc
import logging
import time


class HuaweiVM(VM):
    def __init__(self, params):
        super(HuaweiVM, self).__init__(params)
        self._data = None

        # VM parameters
        self.keypair = params.get('keypair', '*/VM/*')
        self.vm_name = params.get('vm_name', '*/VM/*')
        self.user_data = None
        self.flavor = params.get('name', '*/Flavor/*')
        self.nic_count = params.get('nic_count', '*/Flavor/*')

        # VM access parameters
        self.vm_username = params.get('username', '*/VM/*')
        self.vm_password = params.get('password', '*/VM/*')

        self.arch = 'x86_64'

        self.ecs = ECSApi(params)

    @property
    def data(self):
        if not self._data:
            self._data = {}
            for ecs in self.ecs.query_ecs_detail()['servers']:
                if ecs["name"] == self.ecs.vm_name:
                    self._data = ecs
                    break
        return self._data

    @property
    def floating_ip(self):
        f_ip = None
        for net in self.data.get('addresses').values():
            for ip in net:
                if ip['OS-EXT-IPS:type'] == 'floating':
                    f_ip = ip['addr']
        return f_ip

    def wait_for_status(self, job_id, timeout, error_message, endpoint='ecs'):
        for count in utils_misc.iterate_timeout(timeout, error_message):
            res = self.ecs.query_task_status(job_id, endpoint=endpoint)
            if res['status'] == 'SUCCESS':
                break

    def create(self, wait=False):
        logging.info("Create ECSs")
        res = self.ecs.create_ecss(
            self.user_data.decode() if self.user_data is not None else None)
        if wait:
            time.sleep(60)
            self.wait_for_status(
                res['job_id'], 300,
                "Timed out waiting for server to get created.")
            # Sleep to wait for cloud-init finished
            time.sleep(60)
        self._data = None

    def delete(self, wait=False):
        logging.info("Delete ECSs")
        res = self.ecs.delete_ecss([self.data.get('id')])
        if wait:
            time.sleep(20)
            self.wait_for_status(
                res['job_id'], 300,
                "Timed out waiting for server to get deleted.")

    def start(self, wait=False):
        logging.info("Start ECSs")
        res = self.ecs.start_ecss([self.data.get('id')])
        if wait:
            time.sleep(20)
            self.wait_for_status(
                res['job_id'], 300,
                "Timed out waiting for server to get started.")

    def stop(self, wait=False):
        logging.info("Stop ECSs")
        res = self.ecs.stop_ecss([self.data.get('id')])
        if wait:
            time.sleep(20)
            self.wait_for_status(
                res['job_id'], 300,
                "Timed out waiting for server to get stopped.")

    def reboot(self, wait=False):
        logging.info("Restart ECSs")
        res = self.ecs.restart_ecss([self.data.get('id')])
        if wait:
            time.sleep(20)
            self.wait_for_status(
                res['job_id'], 120,
                "Timed out waiting for server to get rebooted.")

    def exists(self):
        self._data = None
        count = sum(1 for i in self.data)
        if count > 0:
            return True
        else:
            return False

    def _get_status(self):
        self._data = None
        return self.data.get('status')

    def is_started(self):
        return self._get_status() == 'ACTIVE'

    def is_stopped(self):
        return self._get_status() == 'SHUTOFF'

    def show(self):
        return self.data

    def attach_nics(self, nic_count, wait=False):
        logging.info("Add %s NICs to ECS" % nic_count)
        server_id = self.data.get('id')
        res = self.ecs.attach_nics(server_id, nic_count)
        if wait:
            self.wait_for_status(
                res['job_id'], 300,
                "Timed out waiting for server to attach nics")

    def detach_nics(self, nic_ids, wait=False):
        logging.info("Delete NICs from ECS.")
        server_id = self.data.get('id')
        if nic_ids:
            res = self.ecs.detach_nics(server_id, nic_ids)
            if wait:
                self.wait_for_status(
                    res['job_id'], 300,
                    "Timed out waiting for server to detach nics")

    def query_nics(self):
        logging.info("Getting NIC information about ECS")
        server_id = self.data.get('id')
        return self.ecs.query_nics(server_id).get("interfaceAttachments")

    def get_private_ip_address(self, nic):
        logging.debug("Getting private IP address")
        return nic['fixed_ips'][0]['ip_address']

    def get_nic_id(self, nic):
        logging.info("Getting NIC ID")
        return nic.get("port_id")

    def create_cloud_disk(self, scsi=False, wait=False):
        logging.info("Create an EVS disk")
        cloud_disk_name = self.params.get('cloud_disk_name', '*/Disk/*')
        cloud_disk_size = self.params.get('cloud_disk_size', '*/Disk/*')
        cloud_disk_type = self.params.get('cloud_disk_type', '*/Disk/*')
        if scsi:
            passthrough = True
            cloud_disk_name = cloud_disk_name + "_scsi"
        else:
            passthrough = False
            cloud_disk_name = cloud_disk_name + "_vbd"
        res = self.ecs.create_evss(cloud_disk_name,
                                   cloud_disk_size,
                                   cloud_disk_type,
                                   passthrough=passthrough,
                                   count=1)
        if wait:
            self.wait_for_status(
                res['job_id'], 60,
                "Timed out waiting for cloud disk to be created", 'evs')

    def delete_cloud_disk(self, disk_id, wait=False):
        logging.info("Delete an EVS disk")
        self.ecs.delete_evs(disk_id)
        if wait:
            for count in utils_misc.iterate_timeout(
                    60, "Timed out waiting for cloud disk to be deleted"):
                res = self.query_cloud_disks(disk_id=disk_id.encode("ascii"))
                if len(res) == 0:
                    break

    def attach_cloud_disks(self,
                           disk_id,
                           dev="sd",
                           local_disk_count=0,
                           wait=False):
        logging.info("Attach a disk to ECS")
        res = self._query_cloud_disk_attachments()
        attached_list = [vol['device'] for vol in res.get('volumeAttachments')]
        i = local_disk_count
        while True:
            i = i + 1
            if i <= 25:
                idx = chr(97 + i)
            else:
                idx = 'a' + chr(97 - 1 + i % 25)
            if "/dev/%s%s" % (dev, idx) not in attached_list:
                break
        logging.debug("Attaching disk %s as /dev/%s%s..." %
                      (disk_id, dev, idx))
        res = self.ecs.attach_volume(self.data.get('id'), disk_id,
                                     "/dev/%s%s" % (dev, idx))
        if wait:
            time.sleep(10)
            self.wait_for_status(
                res['job_id'], 60,
                "Timed out waiting for cloud disk to be attached")

    def detach_cloud_disks(self, disk_id, wait=False, scsi=False):
        logging.info("Detach an EVS disk from ECS")
        self.ecs.detach_volume(self.data.get('id'), disk_id)
        if wait:
            time.sleep(5)
            for count in utils_misc.iterate_timeout(
                    60, "Timed out waiting for cloud disk to be detached"):
                res = self.query_cloud_disks(disk_id=disk_id, scsi=scsi)
                status = res[0].get("status")
                if status == u"available":
                    break

    def _query_cloud_disk_attachments(self):
        res = self.ecs.query_volumes(self.data.get('id'))
        return res

    def query_cloud_disks(self, disk_id=None, scsi=False):
        logging.info("Getting information about all EVS disks")
        cloud_disk_name = self.params.get('cloud_disk_name', '*/Disk/*')
        if scsi:
            cloud_disk_name = cloud_disk_name + "_scsi"
        else:
            cloud_disk_name = cloud_disk_name + "_vbd"
        res = self.ecs.query_evss(cloud_disk_name)
        if disk_id:
            vols = []
            for disk in res.get("volumes"):
                if disk['id'] == disk_id:
                    vols.append(disk)
        else:
            vols = list(res.get("volumes"))
            for disk in res.get("volumes"):
                if disk['name'] != cloud_disk_name:
                    vols.remove(disk)
        return vols
