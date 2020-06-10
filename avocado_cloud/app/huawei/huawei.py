import json
import logging
from requests.compat import urljoin
from datetime import datetime, timedelta
import requests
import os

# Disable HTTPS verification warnings.
try:
    from requests.packages import urllib3
except ImportError:
    import urllib3
else:
    urllib3.disable_warnings()

logger = logging.getLogger('urllib3')
logger.setLevel(logging.INFO)
token_file = os.path.expanduser('~') + '/.ecs_token'


def get_token(base_url, project_name, domain_name, username, password):
    token_uri = "/v3/auth/tokens"
    auth_url = urljoin(base_url, token_uri)
    # If change region the token_file is inavailable. Can we consider to
    # remove it everytime?
    # if os.path.isfile(token_file):
    #     with open(token_file, 'r') as fp:
    #         j_token = json.load(fp)
    #     expire_date = datetime.strptime(j_token['expires_at'],
    #         '%Y-%m-%dT%H:%M:%S.%fZ')
    #     # expire_date = datetime.strptime(j_token['expires_at'],
    #     #   '%Y-%m-%dT%H:%M:%S.%fZ') + timedelta(hours=8)
    #     now = datetime.now()
    #     if now > expire_date:
    #         token, project_id = ecs_get_token(auth_url, project_name,
    #             domain_name, username, password)
    #     else:
    #         token = j_token['token']
    #         project_id = j_token['project_id']
    # else:
    #     token, project_id = ecs_get_token(auth_url, project_name,
    #         domain_name, username, password)
    token, project_id = ecs_get_token(auth_url, project_name, domain_name,
                                      username, password)
    return token, project_id


def ecs_get_token(auth_url, project_name, domain_name, username, password):
    s = requests.Session()
    data = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": username,
                        "password": password,
                        "domain": {
                            "name": domain_name
                        }
                    }
                }
            },
            "scope": {
                "project": {
                    "name": project_name
                }
            }
        }
    }
    logging.debug("Request for token")
    headers = {'Content-Type': 'application/json;charset=utf8'}
    r = s.post(auth_url, json=data, headers=headers)
    if r.status_code != 201:
        logging.error("%s %s." % (r.status_code, r.text))
        exit(r.status_code)
    j_content = json.loads(r.text)
    token = r.headers['X-Subject-Token']
    project_id = j_content['token']['project']['id']
    j_token = {
        'token': token,
        'expires_at': j_content['token']['expires_at'],
        'project_id': project_id
    }
    with open(token_file, 'w') as fp:
        json.dump(j_token, fp)
    return token, project_id


# def validate_token(token, auth_url):
#     logging.debug("Validate token")
#     s = requests.Session()
#     headers = {'Content-Type': 'application/json;charset=utf8',
#         'X-Auth-Token': token, 'X-Subject-Token': token}
#     r = s.get(auth_url, headers=headers)
#     if r.status_code != 200:
#         logging.error("%s %s." % (r.status_code, r.text))
#         exit(r.status_code)
#     j_content = json.loads(r.text)
#     print(j_content['token']['expires_at'])


class ECSSession(object):
    def __init__(self, auth_url, project_name, domain_name, username,
                 password):
        self.s = requests.Session()
        self.headers = {'Content-Type': 'application/json;charset=utf8'}
        self.token, self.project_id = get_token(auth_url, project_name,
                                                domain_name, username,
                                                password)
        self.headers['X-Auth-Token'] = self.token
        self.s.headers.update(self.headers)
        self.r = None

    def get(self, url):
        # logging.debug("Making api get call to %s" % url)
        try:
            self.r = self.s.get(url, headers=self.headers)
        except requests.exceptions.RequestException:
            logging.error("connection to ecs failed")
        # convert response to json
        return self.__json()

    def post(self, url, data):
        # logging.debug("Making api post call to %s" % url)
        try:
            self.r = self.s.post(url, json=data, headers=self.headers)
        except requests.exceptions.RequestException:
            logging.error("connection to ecs failed")
        # convert response to json
        return self.__json()

    def put(self, url, data):
        # logging.debug("Making api put call to %s" % url)
        try:
            self.r = self.s.put(url, json=data, headers=self.headers)
        except requests.exceptions.RequestException:
            logging.error("connection to ecs failed")
        # convert response to json
        return self.__json()

    def delete(self, url):
        # logging.debug("Making api delete call to %s" % url)
        try:
            self.r = self.s.delete(url, headers=self.headers)
        except requests.exceptions.RequestException:
            logging.error("connection to ecs failed")

    def __json(self):
        try:
            json_obj = json.loads(self.r.text)
            return json_obj
        except ValueError:
            logging.error("Unable to convert string to json\n %s" %
                          self.r.text)


class ECSApi(ECSSession):
    def __init__(self, params):

        # Huawei connection credentials
        project_name = params.get('project_name', '*/Cloud/*')
        base_patten = params.get('base_url', '*/Cloud/*')
        if "%project_name%" in base_patten:
            self.base_url = base_patten.replace("%project_name%", project_name,
                                                1)
        else:
            self.base_url = base_patten
        auth_url = self.base_url.replace("ecs", "iam", 1)
        domain_name = params.get('domain_name', '*/Credential/*')
        username = params.get('username', '*/Credential/*')
        password = params.get('password', '*/Credential/*')

        # VM creation parameters
        self.keypair = params.get('keypair', '*/VM/*')
        self.vm_name = params.get('vm_name', '*/VM/*')
        self.image_ref = params.get('image_ref', '*/VM/*')
        self.vpc_id = params.get('vpc_id', '*/VM/*')
        self.subnet_id = params.get('subnet_id', '*/VM/*')
        self.sg_id = params.get('sg_id', '*/VM/*')
        self.az = params.get('az', '*/VM/*')
        self.flavor = params.get('name', '*/Flavor/*')

        super(ECSApi, self).__init__(auth_url, project_name, domain_name,
                                     username, password)

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
        if self.r.status_code != 200:
            logging.error("%s %s." % (self.r.status_code, self.r.text))
            exit(self.r.status_code)
        return json_obj

    def create_ecss(self, user_data):
        """ This interface is used to create one or more ECSs. """
        logging.debug("Create ECSs")
        endpoint = urljoin(self.base_url,
                           "/v1/%s/cloudservers" % self.project_id)
        data = {
            "server": {
                "availability_zone": self.az,
                "name": self.vm_name,
                "imageRef": self.image_ref,
                "root_volume": {
                    "volumetype": "SATA",
                    "size": 40
                },
                "flavorRef": self.flavor,
                "vpcid": self.vpc_id,
                "security_groups": [{
                    "id": self.sg_id
                }],
                "nics": [{
                    "subnet_id": self.subnet_id
                }],
                "publicip": {
                    "eip": {
                        "iptype": "5_sbgp",
                        "bandwidth": {
                            "size": 1,
                            "sharetype": "PER"
                        }
                    }
                },
                "key_name": self.keypair,
                "user_data": user_data,
                "count": 1
            }
        }
        return self.make_request(endpoint, 'post', data=data)

    def delete_ecss(self, server_ids):
        """ This interface is used to delete ECSs based on a specified ECS ID list.
        The ECSs can be deleted one by one or in batches. """
        logging.debug("Delete ECSs")
        endpoint = urljoin(self.base_url,
                           "/v1/%s/cloudservers/delete" % self.project_id)
        data = {"servers": [], "delete_publicip": True, "delete_volume": True}
        for server_id in server_ids:
            data["servers"].append({"id": server_id})
        return self.make_request(endpoint, 'post', data=data)

    def restart_ecss(self, server_ids):
        """ This interface is used to restart ECSs in batches based
        on specified ECS IDs."""
        logging.debug("Restart ECSs")
        endpoint = urljoin(self.base_url,
                           "/v1/%s/cloudservers/action" % self.project_id)
        data = {"reboot": {"type": "SOFT", "servers": []}}
        for server_id in server_ids:
            data["reboot"]["servers"].append({"id": server_id})
        return self.make_request(endpoint, 'post', data=data)

    def stop_ecss(self, server_ids):
        """ This interface is used to stop ECSs in batches based on specified
        ECS IDs. """
        logging.debug("Stop ECSs")
        endpoint = urljoin(self.base_url,
                           "/v1/%s/cloudservers/action" % self.project_id)
        data = {"os-stop": {"type": "HARD", "servers": []}}
        for server_id in server_ids:
            data["os-stop"]["servers"].append({"id": server_id})
        return self.make_request(endpoint, 'post', data=data)

    def start_ecss(self, server_ids):
        """ This interface is used to start ECSs in batches based on specified
        ECS IDs. """
        logging.debug("Start ECSs")
        endpoint = urljoin(self.base_url,
                           "/v1/%s/cloudservers/action" % self.project_id)
        data = {"os-start": {"type": "HARD", "servers": []}}
        for server_id in server_ids:
            data["os-start"]["servers"].append({"id": server_id})
        return self.make_request(endpoint, 'post', data=data)

    def query_ecs(self):
        """ This interface is used to query ECS. """
        logging.debug("Query ECS")
        endpoint = urljoin(
            self.base_url,
            "/v2/%s/servers?name=%s" % (self.project_id, self.vm_name))
        return self.make_request(endpoint, 'get')

    def query_ecs_detail(self):
        """ This interface is used to query details about ECS. """
        logging.debug("Query details about ECS")
        endpoint = urljoin(
            self.base_url,
            "/v2/%s/servers/detail?name=%s" % (self.project_id, self.vm_name))
        return self.make_request(endpoint, 'get')

    def modify_ecs_info(self, server_id, name):
        """ This interface is used to modify ECS information. Only the name of
        the ECS can be modified currently. """
        logging.debug("Modify the name of the ECS %s" % server_id)
        endpoint = urljoin(self.base_url,
                           "/v2/%s/servers/%s" % (self.project_id, server_id))
        data = {"server": {"name": ""}}
        data["server"]["name"] = name
        return self.make_request(endpoint, 'put', data=data)

    def resize_ecs(self, server_id, flavor):
        """ This interface is used to modify the specifications of an ECS. """
        logging.debug("Modify the specifications of the ECS %s" % server_id)
        endpoint = urljoin(
            self.base_url,
            "/v1/%s/cloudservers/%s/resize" % (self.project_id, server_id))
        data = {"resize": {"flavorRef": "normal1"}}
        data["resize"]["flavorRef"] = flavor
        return self.make_request(endpoint, 'post', data=data)

    def query_ssh_keypairs(self):
        """ This interface is used to query SSH key pairs. """
        logging.debug("Query SSH key pairs")
        endpoint = urljoin(self.base_url,
                           "/v2/%s/os-keypairs" % self.project_id)
        return self.make_request(endpoint, 'get')

    def query_task_status(self, job_id, endpoint='ecs'):
        """ This interface is used to query the execution status of a task,
        such as the ECS creation, ECS deletion, ECS batch operation, and NIC
        operation. After a task is issued, a task ID is returned, based on
        which you can query the execution status of the task. """
        logging.debug("Query the execution status of task %s" % job_id)
        base_url = self.base_url.replace("ecs", endpoint, 1)
        endpoint = urljoin(base_url,
                           "/v1/%s/jobs/%s" % (self.project_id, job_id))
        return self.make_request(endpoint, 'get')

    def list_flavors(self):
        """ This interface is used to query available VM flavors. After
        receiving the request, Nova queries the flavor information from the
        database using the nova-api process. """
        logging.debug("Getting list of flavors")
        endpoint = urljoin(self.base_url, "/v2/%s/flavors" % self.project_id)
        return self.make_request(endpoint, 'get')

    def query_images(self):
        """ This interface is used to query images using search criteria and
        to display the images in a list. """
        logging.debug("Getting list of images")
        endpoint = urljoin(
            self.base_url, "/v2/cloudimages?__imagetype=gold\
&__platform=RedHat&sort_key=created_at")
        return self.make_request(endpoint, 'get')

    def query_vpcs(self):
        """ This interface is used to query VPCs using search criteria and to
        display the VPCs in a list. """
        logging.debug("Getting list of VPCs")
        endpoint = urljoin(self.base_url, "/v1/%s/vpcs" % self.project_id)
        return self.make_request(endpoint, 'get')

    def query_subnets(self, vpc_id):
        """ This interface is used to query subnets using search criteria and
        to display the subnets in a list. """
        logging.debug("Getting list of subnets")
        endpoint = urljoin(
            self.base_url,
            "/v1/%s/subnets?vpc_id=%s" % (self.project_id, vpc_id))
        return self.make_request(endpoint, 'get')

    def query_eips(self):
        """ This interface is used to query elastic IP addresses using search criteria
        and to display the elastic IP addresses in a list. """
        logging.debug("Getting list of elastic IP addresses")
        endpoint = urljoin(self.base_url, "/v1/%s/publicips" % self.project_id)
        return self.make_request(endpoint, 'get')

    def query_security_groups(self):
        """ This interface is used to query security groups using search criteria
        and to display the security groups in a list. """
        logging.debug("Getting list of security groups")
        endpoint = urljoin(self.base_url,
                           "/v1/%s/security-groups" % self.project_id)
        return self.make_request(endpoint, 'get')

    def query_availability_zones(self):
        """ This interface is used to query availability zones (AZs). """
        logging.debug("Getting list of availability zones")
        endpoint = urljoin(self.base_url,
                           "/v2/%s/os-availability-zone" % self.project_id)
        return self.make_request(endpoint, 'get')

    def query_projects(self):
        """ This interface is used to query the list of projects accessible to
        users. """
        logging.debug("Getting list of projects accessible to users")
        endpoint = urljoin(self.base_url, "/v3/auth/projects")
        return self.make_request(endpoint, 'get')

    def query_project_info(self, project_name):
        """ This interface is used to query information about a specified
        project. """
        logging.debug("Query information about project %s" % project_name)
        endpoint = urljoin(self.base_url,
                           "/v3/projects?name=%s" % project_name)
        return self.make_request(endpoint, 'get')

    def query_nics(self, server_id):
        """ This interface is used to query NIC information about ECS. """
        logging.debug("Getting NIC information about ECS")
        endpoint = urljoin(
            self.base_url,
            "/v2/%s/servers/%s/os-interface" % (self.project_id, server_id))
        return self.make_request(endpoint, 'get')

    def attach_nics(self, server_id, count):
        """ This interface is used to attach one or multiple NICs to an ECS.
        """
        logging.debug("Add one or multiple NICs to an ECS")
        endpoint = urljoin(
            self.base_url,
            "/v1/%s/cloudservers/%s/nics" % (self.project_id, server_id))
        data = {"nics": []}
        nic = {
            "subnet_id": self.subnet_id,
            "security_groups": [{
                "id": self.sg_id
            }]
        }
        for i in range(int(count)):
            data["nics"].append(nic)
        return self.make_request(endpoint, 'post', data=data)

    def detach_nics(self, server_id, nic_ids):
        """ This interface is used to detach one or multiple NICs from an ECS.
        """
        logging.debug("Delete one or multiple NICs from an ECS.")
        endpoint = urljoin(
            self.base_url, "/v1/%s/cloudservers/%s/nics/delete" %
            (self.project_id, server_id))
        data = {"nics": []}
        if isinstance(nic_ids, str):
            nic_ids = [nic_ids]
        for nic_id in nic_ids:
            data["nics"].append({"id": nic_id})
        return self.make_request(endpoint, 'post', data=data)

    def query_volumes(self, server_id):
        """ This interface is used to query information about the disks
        attached to an ECS. """
        logging.debug("Getting information about the disks attached to an ECS")
        endpoint = urljoin(
            self.base_url, "/v2/%s/servers/%s/os-volume_attachments" %
            (self.project_id, server_id))
        return self.make_request(endpoint, 'get')

    def attach_volume(self, server_id, volume_id, device):
        """ This interface is used to attach a disk to an ECS. """
        logging.debug("Attach a disk to an ECS")
        endpoint = urljoin(
            self.base_url, "/v1/%s/cloudservers/%s/attachvolume" %
            (self.project_id, server_id))
        data = {"volumeAttachment": {"volumeId": volume_id, "device": device}}
        return self.make_request(endpoint, 'post', data=data)

    def detach_volume(self, server_id, volume_id):
        """ This interface is used to detach an EVS disk from an ECS. """
        logging.debug("Detach an EVS disk from an ECS")
        endpoint = urljoin(
            self.base_url, "/v1/%s/cloudservers/%s/detachvolume/%s" %
            (self.project_id, server_id, volume_id))
        return self.make_request(endpoint, 'delete')

    def create_evss(self, name, size, vol_type, passthrough=False, count=1):
        """ This interface is used to create one or multiple Elastic Volume
        Service (EVS) disks.
        :param passthrough: True=SCSI; False=VBD
        """
        logging.debug(
            "Create one or multiple Elastic Volume Service (EVS) disks")
        endpoint = urljoin(self.base_url,
                           "/v2/%s/cloudvolumes" % self.project_id)
        data = {
            "volume": {
                "count": count,
                "availability_zone": self.az,
                "size": int(size),
                "name": name,
                "volume_type": vol_type,
            }
        }
        if passthrough:
            data["volume"]["metadata"] = {"hw:passthrough": "true"}
        return self.make_request(endpoint, 'post', data=data)

    def delete_evs(self, volume_id):
        """ This interface is used to delete an EVS disk. """
        logging.debug("Delete an EVS disk")
        endpoint = urljoin(
            self.base_url,
            "/v2/%s/cloudvolumes/%s" % (self.project_id, volume_id))
        return self.make_request(endpoint, 'delete')

    def query_evss(self, name):
        """ This interface is used to query details about all EVS disks. """
        logging.debug("Getting information about all EVS disks")
        endpoint = urljoin(
            self.base_url,
            "/v2/%s/cloudvolumes/detail?name=%s" % (self.project_id, name))
        return self.make_request(endpoint, 'get')

    def query_quota(self):
        logging.debug("Getting information about the tenant quota")
        endpoint = urljoin(self.base_url,
                           "/v1/%s/cloudservers/limits" % self.project_id)
        return self.make_request(endpoint, 'get')
