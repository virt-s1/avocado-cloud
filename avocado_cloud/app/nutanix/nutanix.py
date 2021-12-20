import json
import base64
import logging
from requests.compat import urljoin
import requests
import subprocess

# Disable HTTPS verification warnings.
try:
    from requests.packages import urllib3
except ImportError:
    import urllib3
else:
    urllib3.disable_warnings()

logger = logging.getLogger('urllib3')
logger.setLevel(logging.DEBUG)

class PrismSession(object):
    def __init__(self, cvmIP, username, password):
        self.s = requests.Session()
        # Base Url v2 API
        self.base_url = "https://" + cvmIP + ":9440/PrismGateway/services/rest/v2.0/"
        credential = base64.b64encode(
            ('%s:%s' % (username, password)).encode()).decode()
        self.headers = {"Authorization": "Basic %s" % credential}
        self.s.headers.update(self.headers)
        self.r = None

    def get(self, url):
        # logging.debug("Making api get call to %s" % url)
        try:
            self.r = self.s.get(url, headers=self.headers, verify=False)
        except requests.exceptions.RequestException as e:
            logging.error("Failed to connect to Prism")
        # convert response to json
        return self.__json()

    def post(self, url, data):
        # logging.debug("Making api post call to %s" % url)
        try:
            self.r = self.s.post(url, json=data, headers=self.headers)
        except requests.exceptions.RequestException:
            logging.error("Failed to connect to Prism")
        # convert response to json
        return self.__json()

    def put(self, url, data):
        # logging.debug("Making api put call to %s" % url)
        try:
            self.r = self.s.put(url, json=data, headers=self.headers)
        except requests.exceptions.RequestException:
            logging.error("Failed to connect to Prism")
        # convert response to json
        return self.__json()

    def delete(self, url):
        # logging.debug("Making api delete call to %s" % url)
        try:
            self.r = self.s.delete(url, headers=self.headers)
        except requests.exceptions.RequestException:
            logging.error("Failed to connect to Prism")
        # convert response to json
        return self.__json()

    def __json(self):
        try:
            json_obj = json.loads(self.r.text)
            return json_obj
        except ValueError:
            if self.r.text:
                logging.error("Unable to convert string to json\n %s" %
                          self.r.text)
            else:
                logging.debug("Response has no content.")

class PrismApi(PrismSession):
    def __init__(self, params):

        # Nutanix connection credentials
        self.cvmIP = params.get('cvm_ip', '*/Cloud/*')
        username = params.get('username', '*/Credential/*')
        password = params.get('password', '*/Credential/*')

        # VM creation parameters
        self.vm_name = params.get('vm_name', '*/VM/*')
        self.vm_username = params.get('username', '*/VM/*')
        self.vm_password = params.get('password', '*/VM/*')
        self.image_name = params.get('image_name', '*/VM/*')
        self.storage_container_uuid = params.get('storage_container_uuid',
                                                 '*/VM/*')
        self.disk = params.get('size', '*/Flavor/*')
        self.network_uuid = params.get('network_uuid', '*/VM/*')
        self.cpu = params.get('cpu', '*/Flavor/*')
        self.memory = params.get('memory', '*/Flavor/*')
        self.vm_user_data = params.get('custom_data', '*/VM/*')
        self.vm_custom_file = None

        self.base_cmd = ["ssh", username+"@"+self.cvmIP]

        super(PrismApi, self).__init__(self.cvmIP, username, password)

    def make_request(self, endpoint, action, data=None):
        functions = {
            'get': self.get,
            'post': self.post,
            'put': self.put,
            'delete': self.delete
        }
        func = functions[action]
        if data:
            json_obj = func(endpoint, data=data)
        else:
            json_obj = func(endpoint)
        if self.r.status_code not in (200, 201) and not \
          (self.r.status_code == 204 and action == "delete"):
            logging.error("%s %s." % (self.r.status_code, self.r.text))
            exit(self.r.status_code)
        return json_obj

    def create_vm(self, ssh_pubkey=None):
        logging.debug("Create VM")
        endpoint = urljoin(self.base_url, "vms")
	# Attach image.
        images = self.list_images()
        vmdisk_uuid = ""
        for image in images['entities']:
            if self.image_name == image['name']:
                vmdisk_uuid = image['vm_disk_id']
        if vmdisk_uuid == "":
            logging.error("Image %s not found." % self.image_name)
            exit(1)
        # Attach ssh keys.
        ssh_key = ''
        ssh_pwauth = '\nchpasswd:\n  list: |\n    %s:%s\n  expire: false\nssh_pwauth: yes' % (
            self.vm_username, self.vm_password)
        if (ssh_pubkey):
            ssh_key = '\nssh_authorized_keys:\n- %s' % ssh_pubkey
            ssh_pwauth = ''
        # Attach user_data.
        user_data = '#cloud-config\ndisable_root: false\nlock_passwd: false%s%s\n' % (
            ssh_pwauth, ssh_key)
        if self.vm_user_data:
            user_data += self.vm_user_data
        # Attach user script.
	user_script=[]
        if self.vm_custom_file:
            user_script = [{'source_path': 'adsf:///{}/{}'.format(self.get_container()['name'], self.vm_custom_file),
                      'destination_path': '/tmp/{}'.format(self.vm_custom_file)}]
        # Attach NICs (all).
        network_uuids = []
        for network in self.list_networks_detail()["entities"]:
            network_uuids.append({"network_uuid": network["uuid"]})
        data = {
            'boot': {
                'uefi_boot': False
            },
            'memory_mb':
            self.memory * 1024,
            'name':
            self.vm_name,
            'num_cores_per_vcpu':
            1,
            'num_vcpus':
            self.cpu,
            'timezone':
            'UTC',
            'vm_customization_config': {
                'datasource_type': 'CONFIG_DRIVE_V2',
                'userdata': user_data,
                'files_to_inject_list': user_script
            },
            'vm_disks': [{
                'is_cdrom': False,
                'is_empty': False,
                'is_scsi_pass_through': True,
                'is_thin_provisioned': False,
                'vm_disk_clone': {
                    'disk_address': {
                        'device_bus': 'scsi',
                        'device_index': 0,
                        'vmdisk_uuid': vmdisk_uuid
                    },
                    'minimum_size': self.disk*1024*1024*1024,
                    'storage_container_uuid': self.storage_container_uuid
                }
            }],
            'vm_nics': network_uuids
        }

        return self.make_request(endpoint, 'post', data=data)

    def delete_vm(self, vm_uuid):
        logging.debug("Delete VM")
        endpoint = urljoin(self.base_url, "vms/%s" % vm_uuid)
        return self.make_request(endpoint, 'delete')

    def restart_vm(self, vm_uuid):
        logging.debug("Restart VM")
        endpoint = urljoin(self.base_url, "vms/%s/set_power_state" % vm_uuid)
        data = {"transition": "ACPI_REBOOT"}
        return self.make_request(endpoint, 'post', data=data)

    def stop_vm(self, vm_uuid):
        logging.debug("Stop VM")
        endpoint = urljoin(self.base_url, "vms/%s/set_power_state" % vm_uuid)
        data = {"transition": "ACPI_SHUTDOWN"}
        return self.make_request(endpoint, 'post', data=data)

    def start_vm(self, vm_uuid):
        logging.debug("Start VM")
        endpoint = urljoin(self.base_url, "vms/%s/set_power_state" % vm_uuid)
        data = {"transition": "ON"}
        return self.make_request(endpoint, 'post', data=data)

    def list_vm_detail(self):
        logging.debug("Query details about VM")
        endpoint = urljoin(
            self.base_url,
            "vms/?include_vm_nic_config=True&include_vm_disk_config=True&filter=vm_name==%s"
            % self.vm_name)
        return self.make_request(endpoint, 'get')

    def list_tasks(self, task_uuid):
        logging.debug("Query the execution status of task %s" % task_uuid)
        endpoint = urljoin(self.base_url, "tasks/%s" % task_uuid)
        return self.make_request(endpoint, 'get')

    def list_images(self):
        logging.debug("Getting list of images")
        endpoint = urljoin(self.base_url, "images")
        return self.make_request(endpoint, 'get')

    def cvm_cmd(self, command):
        cmd = self.base_cmd
        cmd.append(command)
        return subprocess.check_output(cmd)

    def list_networks_detail(self):
        logging.debug("Query details about netowrks")
        endpoint = urljoin(
            self.base_url,
            "networks/")
        return self.make_request(endpoint, 'get')

    def create_network(self):
        logging.debug("Creating virtual network")
        networks = self.list_networks_detail()
        exst_IPs = []
        for network in networks["entities"]:
            exst_IPs.append(network["ip_config"]["network_address"])
        for dig in range(2, 254):
            if "192.168."+str(dig)+".0" not in exst_IPs:
                new_prefix = "192.168."+str(dig)
                break
        endpoint = urljoin(self.base_url, "networks/")
        data = {
                "vlan_id": dig,
                "name": "nic%s" % str(dig),
                "ip_config": {
                  "default_gateway": "%s.1" % new_prefix,
                  "network_address": "%s.0" % new_prefix,
                  "pool": [{
                  "range": "%s.2 %s.253" % (new_prefix, new_prefix)
                }],
                "prefix_length": 24
               }}
        return self.make_request(endpoint, 'post', data=data)

    def delete_networks(self):
        # We delete all NICs leaving the one in .yaml.
        logging.debug("Deleting virtual networks")
        networks = self.list_networks_detail()
        for network in networks["entities"]:
            if not network["uuid"] == self.network_uuid:
                endpoint = urljoin(self.base_url, "networks/%s" % network["uuid"])
                self.make_request(endpoint, 'delete')

    def attach_disk(self, vm_uuid, disk_size):
        logging.debug("Creating a disk and attach to VM")
        endpoint = urljoin(self.base_url, "vms/%s/disks/attach" % vm_uuid)
        data = {"vm_disks": [{
                    "is_cdrom": False,
                    "is_empty": True,
                    "is_scsi_pass_through": True,
                    "is_thin_provisioned": False,
                    "vm_disk_create": {
                        "size": disk_size*1024*1024*1024,
                         "storage_container_uuid": self.storage_container_uuid
               }}]}
        return self.make_request(endpoint, 'post', data=data)

    def get_container(self):
        endpoint = urljoin(self.base_url, "storage_containers/%s" % self.storage_container_uuid)
        return self.make_request(endpoint, 'get')
        
    def get_disk(self, disk_uuid):
        endpoint = urljoin(self.base_url, "virtual_disks/%s" % disk_uuid)
        return self.make_request(endpoint, 'get')
        
    def expand_disk(self, disk_uuid, disk_size):
        # Shrinking disk is not available in Nutanix.
        logging.debug("Expanding designated disk.")
        disk = get_disk(disk_uuid)
        endpoint = urljoin(self.base_url, "vms/%s/disks/update" % disk['attached_vm_uuod']）
        data = {"vm_disks": [{
                    "disk_address": {
                         "vmdisk_uuid": disk_uuid,
                         "device_uuid": disk['device_uuid'],
                         "device_index": 0,
                         "device_bus": "scsi"},
                    "flash_mode_enabled": False,
                    "is_cdrom": False,
                    "is_empty": False,
                    "vm_disk_create": {
                         "storage_container_uuid": disk['container_uuid'],
                         "size": disk_size*1024*1024*1024}
                    }]}
        return self.make_request(endpoint, 'put', data=data)
