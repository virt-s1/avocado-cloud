import json
import base64
import logging
from requests.compat import urljoin
import requests

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
            logging.error("Unable to convert string to json\n %s" %
                          self.r.text)


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
        self.network_uuid = params.get('network_uuid', '*/VM/*')
        self.cpu = params.get('cpu', '*/Flavor/*')
        self.memory = params.get('memory', '*/Flavor/*')

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
        if self.r.status_code not in (200, 201):
            logging.error("%s %s." % (self.r.status_code, self.r.text))
            exit(self.r.status_code)
        return json_obj

    def create_vm(self):
        logging.debug("Create VM")
        endpoint = urljoin(self.base_url, "vms")
        images = self.list_images()
        vmdisk_uuid = ""
        for image in images['entities']:
            if self.image_name == image['name']:
                vmdisk_uuid = image['vm_disk_id']
        if vmdisk_uuid == "":
            logging.error("Image %s not found." % self.image_name)
            exit(1)
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
                'datasource_type':
                'CONFIG_DRIVE_V2',
                'userdata':
                '#cloud-config\ndisable_root: false\nlock_passwd: false\nchpasswd:\n  list: |\n    %s:%s\n  expire: false\nssh_pwauth: yes\nssh_authorized_keys:\n- ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCwHpsVy4G9QRu7yznBe2Y4oD1GyhXM7RfAMNv22ladhR+shzG76wFecfFq5iUAG6CQl9EzCYVlFEOm8Uf4hcCdNYMy7TYU0JluXxwAahP/z8L9quQoOkrweYaCBgW/jBkuZp0gB8rULcxWyfzHMqV/iLI8dPOizXK2WPSedxrtR57rjT2LRRbKmn0OllROmMQgEBZCorsCoMGeuE71JVnYmDt6rq3XhEm673QmTSk0HItqii8PoDi0oXU84ZyUlIrO9IRkF4OZDCxnu4EAf2EyePrT+TBkc61W/eVPNmG//AP2jOjlm7vs4HH6vHDTsuGozVAjckj/rQWATPGX1Kdt wshi@wshi-desktop'
                % (self.vm_username, self.vm_password)
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
                    'storage_container_uuid': self.storage_container_uuid
                }
            }],
            'vm_nics': [{
                'network_uuid': self.network_uuid
            }]
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
            "vms?include_vm_nic_config=True&include_vm_disk_config=True&filter=vm_name==%s"
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
