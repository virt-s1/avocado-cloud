import base64
from ..base import VM
from .alibaba import AlibabaSDK
from avocado_cloud.utils import utils_misc
import logging
import time


class AlibabaVM(VM):
    def __init__(self, params):
        super(AlibabaVM, self).__init__(params)
        self._data = None

        # VM parameters
        self.keypair = params.get('keypair', '*/VM/*')
        self.vm_name = params.get('vm_name', '*/VM/*').replace('_', '-')
        self.user_data = None
        self.nic_name = params.get('nic_name', '*/NIC/*')

        self.flavor = params.get('name', '*/Flavor/*')
        self.cpu = params.get('cpu', '*/Flavor/*')
        self.memory = params.get('memory', '*/Flavor/*')
        self.disk_count = params.get('disk_count', '*/Flavor/*', 0)
        self.disk_size = params.get('disk_size', '*/Flavor/*', 0)
        self.disk_type = params.get('disk_type', '*/Flavor/*', '')
        self.nic_count = params.get('nic_count', '*/Flavor/*', 1)
        self.disk_quantity = params.get('disk_quantity', '*/Flavor/*', 0)

        # VM access parameters
        self.vm_username = params.get('username', '*/VM/*')
        self.vm_password = params.get('password', '*/VM/*')

        self.arch = 'x86_64'

        self.ecs = AlibabaSDK(params)

    @property
    def data(self):
        if not self._data:
            self._data = []
            for ecs in self.ecs.describe_instances().get('Instances').get(
                    'Instance'):
                if ecs["InstanceName"] == self.vm_name:
                    self._data = ecs
                    break
        return self._data

    @property
    def floating_ip(self):
        f_ip = None
        for ip in self.data.get('PublicIpAddress').get('IpAddress'):
            f_ip = ip
        return f_ip

    def wait_for_status(self, status, timeout=300):
        error_message = "Timed out waiting for server to get %s." % status
        for count in utils_misc.iterate_timeout(timeout,
                                                error_message,
                                                wait=20):
            current_status = self._get_status()
            logging.debug('Target: {0}, Current: {1}'.format(
                status, current_status))
            if current_status == status:
                return True

            # Exceptions (detect wrong status to save time)
            if status == 'Running' and current_status not in ('Stopping',
                                                              'Starting'):
                logging.error('While waiting for the server to get Running, \
its status cannot be {0} rather than Stopping or Starting.'.format(
                    current_status))
                return False

    @property
    def id(self):
        return self.data.get("InstanceId")

    def create(self, wait=False):
        """
        This helps to create a VM
        """
        logging.info("Create VM")
        authentication = "publickey"
        if self.keypair is None:
            authentication = "password"
        self.ecs.create_instance(authentication=authentication)
        if wait:
            time.sleep(10)
            self.wait_for_status(status="Stopped")
        self._data = None
        self.ecs.allocate_public_ip_address(self.id)
        time.sleep(5)

    def start(self, wait=False):
        """
        This helps to start a VM
        """
        logging.info("Start VM")
        self.ecs.start_instance(self.id)
        time.sleep(60)
        if wait:
            self.wait_for_status(status="Running")

    def stop(self, wait=False, force=False):
        """
        This helps to stop a VM
        """
        logging.info("Stop VM")
        self.ecs.stop_instance(self.id, force=force)
        if wait:
            self.wait_for_status(status="Stopped")

    def reboot(self, wait=False, force=False):
        """
        This helps to restart a VM
        """
        logging.info("Restart VM")
        self.ecs.reboot_instance(self.id, force=force)
        if wait:
            self.wait_for_status(status="Running")

    def delete(self, wait=False):
        """
        This helps to delete a VM
        The VM can be deleted only if the status is stopped(sdk/cli only)
        """
        logging.info("Delete VM")
        if not self.is_stopped():
            self.stop(wait=True)
        self.ecs.delete_instance(self.id)
        if wait:
            for count in utils_misc.iterate_timeout(
                    300, "Timed out waiting for server to get deleted.",
                    wait=10):
                if not self.exists():
                    break

    def reset_password(self, new_password):
        logging.info("Reset password for VM")
        return self.ecs.modify_instance_attribute(self.id, new_password)

    def create_nic(self, wait=False):
        logging.debug("Create NIC")
        nic_id = self.ecs.create_nic().get("NetworkInterfaceId")
        if wait:
            for count in utils_misc.iterate_timeout(
                    300, "Timed out waiting for nics to be created.", wait=5):
                # nic_status = self.ecs.describe_nics(
                #     nic_ids=[nic_id]).get("Status")
                # logging.debug(
                #     'Status: {0} / Wanted: "Available"'.format(nic_status))
                # if nic_status == "Available":
                #     break

                # Cannot check status with nic_ids because of bug
                # https://github.com/aliyun/aliyun-openapi-python-sdk/issues/78
                # This is a workaround. All nics must not be Creating status
                available_count = creating_count = other_count = 0
                for nic in self.list_nics():
                    if nic.get("Status") == "Available":
                        available_count += 1
                    elif nic.get("Status") == "Creating":
                        creating_count += 1
                    else:
                        other_count += 1
                logging.debug(
                    'Status: Available/Creating/Other: "{0}/{1}/{2}"'.format(
                        available_count, creating_count, other_count))
                if creating_count == 0:
                    break

    def attach_nics(self, nic_count, wait=False):
        logging.debug("Attach %s NICs to ECS" % nic_count)
        origin_count = len(self.query_nics())
        nics_list = self.list_nics()
        if len(nics_list) >= nic_count:
            for nic in nics_list[0:nic_count]:
                self.ecs.attach_nic(self.id, nic.get("NetworkInterfaceId"))
        else:
            raise Exception("No enough NICs. Need: %s; Exists: %s" %
                            (nic_count, len(nics_list)))
        if wait:
            for count in utils_misc.iterate_timeout(
                    300, "Timed out waiting for nics to be attached.",
                    wait=20):
                attached_count = len(self.query_nics()) - origin_count
                logging.debug("Attached: {0} / Wanted: {1}".format(
                    attached_count, nic_count))
                if attached_count >= nic_count:
                    break

    def detach_nics(self, nic_ids, wait=False):
        logging.info("Detach NICs from ECS")
        if nic_ids is None or nic_ids == []:
            return
        if not isinstance(nic_ids, list):
            nic_ids = [nic_ids]

        origin_count = len(self.query_nics())
        forks = 10
        if len(nic_ids) > forks:
            # When detaching more than 20 disks at the same time,
            # some of them will be failed, this is the workaround.
            logging.debug("Detaching first {0} from {1} NIC(s)...".format(
                forks, len(nic_ids)))
            self.detach_nics(nic_ids[:forks], True)
            self.detach_nics(nic_ids[forks:], True)
        else:
            for nic_id in nic_ids:
                self.ecs.detach_nic(self.id, nic_id)
            if wait:
                for count in utils_misc.iterate_timeout(
                        300, "Timed out waiting for nics to be detached",
                        wait=20):
                    detached_count = origin_count - len(self.query_nics())
                    logging.debug("Detached: {0} / Wanted: {1}".format(
                        detached_count, len(nic_ids)))
                    if detached_count >= len(nic_ids):
                        break

    def query_nics(self):
        """Get NIC list of the current instance."""
        logging.info("Getting NICs attached to the ECS")
        return self.ecs.describe_nics(instance_id=self.id, nic_name=None).get(
            "NetworkInterfaceSets").get("NetworkInterfaceSet")

    def query_secondary_nics(self):
        """Get Secondary NIC list of the current instance."""
        logging.info("Getting Secondary NICs attached to the ECS")
        return self.ecs.describe_nics(
            instance_id=self.id, nic_type="Secondary").get(
                "NetworkInterfaceSets").get("NetworkInterfaceSet")

    # SDK issue, can not get the primary nic.
    def query_primary_nic(self):
        """Get primary NIC of the current instance."""
        logging.info("Getting Primary NIC attached to the ECS")
        logging.debug(self.id)
        logging.debug(
            self.ecs.describe_nics(
                instance_id=self.id, nic_type="Primary").get(
                    "NetworkInterfaceSets").get("NetworkInterfaceSet"))
        return self.ecs.describe_nics(
            instance_id=self.id, nic_type="Primary").get(
                "NetworkInterfaceSets").get("NetworkInterfaceSet")[0]

    def list_nics(self):
        """List NICs with default NetworkInterfaceName in the current region.

        Returns a list of NetworkInterfaceSet.
        """
        logging.info("List all NICs in this region")
        return self.ecs.describe_nics().get("NetworkInterfaceSets").get(
            "NetworkInterfaceSet")

    def get_private_ip_address(self, nic):
        """Get private ip of the specified NIC."""
        logging.info("Getting private IP address")
        return nic.get("PrivateIpAddress")

    def get_nic_id(self, nic):
        """Get NIC ID of the specified NIC."""
        logging.info("Getting NIC ID")
        return nic.get("NetworkInterfaceId")

    def get_nic_type(self, nic):
        """Get type of the specified NIC.
        
        Returns 'Primary' or 'Secondary'.
        """
        logging.info("Getting NIC Type")
        return nic.get("Type")

    def delete_nic(self, nic_id):
        """Delete the specified NIC."""
        logging.debug("Delete NIC")
        self.ecs.delete_nic(nic_id)

    def delete_nics(self, nic_name='default', wait=False):
        """Delete the specified NICs by the name."""
        logging.debug("Delete NICs (Name: {0})".format(nic_name))
        nics = self.ecs.describe_nics(nic_name=nic_name).get(
            "NetworkInterfaceSets").get("NetworkInterfaceSet")
        for nic in nics:
            self.delete_nic(nic['NetworkInterfaceId'])
        if wait:
            for count in utils_misc.iterate_timeout(
                    300, "Timed out waiting for nics to be deleted.", wait=1):
                remaining = len(
                    self.ecs.describe_nics(nic_name=nic_name).get(
                        "NetworkInterfaceSets").get("NetworkInterfaceSet"))
                logging.debug(
                    'Remaining {0} NIC(s) to be deleted.'.format(remaining))
                if remaining == 0:
                    break

    def create_cloud_disk(self, wait=False, **args):
        logging.info("Create cloud disk")
        output = self.ecs.create_disk()
        diskid = output.get("DiskId").encode("ascii")
        if wait:
            for count in utils_misc.iterate_timeout(
                    300, "Timed out waiting for cloud disk to be created.",
                    wait=5):
                if self.query_cloud_disks(
                        disk_id=diskid)[0].get("Status") == u'Available':
                    break
        return output

    def delete_cloud_disk(self, disk_id, wait=False):
        """Delete specified cloud disk."""
        logging.info("Delete a cloud disk")
        disk_id = disk_id.encode('ascii')
        self.ecs.delete_disk(disk_id)
        if wait:
            for count in utils_misc.iterate_timeout(
                    300, "Timed out waiting for cloud disk to be deleted",
                    wait=5):
                res = self.query_cloud_disks(disk_id=disk_id)
                if res == []:
                    break

    def delete_cloud_disks(self, wait=False):
        """Delete default cloud disks."""
        logging.info('Delete cloud disks')
        disks = self.query_cloud_disks()
        for disk in disks:
            self.delete_cloud_disk(disk['DiskId'], wait)

    def query_cloud_disks(self, disk_id=None, **args):
        logging.info("Describe cloud disks")
        if disk_id is not None:
            disk_id = disk_id.encode("ascii")
        output = self.ecs.describe_disks(diskids=disk_id)
        if output:
            return output.get("Disks").get("Disk")
        return output

    def attach_cloud_disks(self, disk_id, wait=False, **args):
        logging.info("Attach cloud disk to VM")
        disk_id = disk_id.encode("ascii")
        output = self.ecs.attach_disk(self.id, disk_id)
        if wait:
            for count in utils_misc.iterate_timeout(
                    300,
                    "Timed out waiting for cloud disk to be attached.",
                    wait=5):
                if self.query_cloud_disks(
                        disk_id=disk_id)[0].get("Status") == u"In_use":
                    break
        return output

    def detach_cloud_disks(self, disk_id=None, wait=False, **args):
        logging.info("Detach cloud disk to VM")
        disk_id = disk_id.encode("ascii")
        output = self.ecs.detach_disk(self.id, disk_id)
        if wait:
            for count in utils_misc.iterate_timeout(
                    300,
                    "Timed out waiting for cloud disk to be detached.",
                    wait=5):
                if self.query_cloud_disks(
                        disk_id=disk_id)[0].get("Status") == u"Available":
                    break
        return output

    def exists(self):
        self._data = None
        count = sum(1 for i in self.data)
        if count > 0:
            return True
        else:
            return False

    def _get_status(self):
        self._data = None
        return self.data.get('Status')

    def is_started(self):
        """Return True if VM is running."""
        return self._get_status() == 'Running'

    def is_stopped(self):
        """Return True if VM is stopped."""
        return self._get_status() == 'Stopped'

    def show(self):
        logging.info("Show VM params")
        return self.data

    def modify_instance_type(self, new_type):
        """Modify Instance Type."""
        self.ecs.modify_instance_spec(self.id, new_type)

    def get_console_log(self):
        """Get console log."""
        logging.info('Get console log')
        try:
            output = self.ecs.get_console_log(self.id)
            b64code = output.get('ConsoleOutput')
            console_output = base64.b64decode(b64code)
            return True, console_output
        except Exception as err:
            logging.error("Failed to get console log! %s" % err)
            return False, err
