from ..base import VM
from .nutanix import PrismApi
from avocado_cloud.utils import utils_misc
from avocado_cloud.utils import ssh_key
import logging
import time


class NutanixVM(VM):
    def __init__(self, params):
        super(NutanixVM, self).__init__(params)
        self._data = None

        # VM parameters
        self.vm_name = params.get('vm_name', '*/VM/*')

        # VM access parameters
        self.vm_username = params.get('username', '*/VM/*')
        self.vm_password = params.get('password', '*/VM/*')
        self.vm_user_data = params.get('custom_data', '*/VM/*')
        self.network_uuid = params.get('network_uuid', '*/VM/*')
        self.ssh_pubkey = ssh_key.get_public_key()
        self.arch = 'x86_64'
        self.vm_custom_file = None

        self.prism = PrismApi(params)

    @property
    def data(self):
        if not self._data:
            self._data = {}
            for vm in self.prism.list_vm_detail()['entities']:
                if vm["name"] == self.vm_name:
                    self._data = vm
                    break
        return self._data

    @property
    def floating_ip(self):
        f_ip = None
        for nic in self.data.get('vm_nics'):
            if nic['network_uuid'] == self.network_uuid:
                f_ip = nic['ip_address']
        return f_ip

    def wait_for_status(self, task_uuid, timeout, error_message):
        for count in utils_misc.iterate_timeout(timeout, error_message):
            res = self.prism.list_tasks(task_uuid)
            if res['progress_status'] == 'Succeeded':
                break

    def create(self, wait=False):
        logging.info("Create VM")
        self.prism.vm_user_data = self.vm_user_data
        self.prism.vm_custom_file = self.vm_custom_file
        res = self.prism.create_vm(self.ssh_pubkey)
        if wait:
            self.wait_for_status(
                res['task_uuid'], 60,
                "Timed out waiting for server to get created.")
        self._data = None

    def delete(self, wait=False):
        logging.info("Delete VM")
        res = self.prism.delete_vm(self.data.get('uuid'))
        if wait:
            self.wait_for_status(
                res['task_uuid'], 30,
                "Timed out waiting for server to get deleted.")

    def start(self, wait=False):
        res = self.prism.start_vm(self.data.get('uuid'))
        if wait:
            self.wait_for_status(
                res['task_uuid'], 120,
                "Timed out waiting for server to get started.")
            for count in utils_misc.iterate_timeout(
                    120, "Timed out waiting for getting IP address."):
                if self.exists() and self.floating_ip:
                    break

    def stop(self, wait=False):
        logging.info("Stop VM")
        res = self.prism.stop_vm(self.data.get('uuid'))
        if wait:
            self.wait_for_status(
                res['task_uuid'], 60,
                "Timed out waiting for server to get stopped.")
            for count in utils_misc.iterate_timeout(
                    30, "Timed out waiting for server to get stopped."):
                if self.is_stopped():
                    break

    def reboot(self, wait=False):
        logging.info("Restart VM")
        res = self.prism.restart_vm(self.data.get('uuid'))
        if wait:
            self.wait_for_status(
                res['task_uuid'], 60,
                "Timed out waiting for server to get rebooted.")
            for count in utils_misc.iterate_timeout(
                    120, "Timed out waiting for getting IP address."):
                if self.exists() and self.floating_ip:
                    break

    def exists(self):
        self._data = None
        count = sum(1 for i in self.data)
        if count > 0:
            return True
        else:
            return False

    def _get_status(self):
        self._data = None
        return self.data.get('power_state')

    def is_started(self):
        return self._get_status() == 'on'

    def is_stopped(self):
        return self._get_status() == 'off'

    def show(self):
        return self.data

    def cvm_cmd(self, command):
        return self.prism.cvm_cmd(command)

    def attach_disk(self, size, wait=False):
        logging.info("Creating and attaching disk")
        res = self.prism.attach_disk(self.data.get('uuid'), size)
        if wait:
            self.wait_for_status(
                res['task_uuid'], 30,
                "Timed out attaching disk.")
