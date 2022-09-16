"""
This module is used for converting linux 'ibmcloud' command to python function
"""
import json
import time
import re
import logging

from avocado_cloud.app import VM
from avocado_cloud.app.base import Base
from avocado_cloud.utils.utils_ibmcloud import acommand as command
from avocado_cloud.utils import utils_misc

LOG = logging.getLogger('avocado.test')
logging.basicConfig(level=logging.DEBUG)


class IbmcloudSdkError(Exception):
    def __init__(self, msg, output):
        super(IbmcloudSdkError, self).__init__(msg, output)
        self.msg = msg
        self.output = output

    def __str__(self):
        return "[{}]\n{})".format(self.msg, self.output)


class IbmcloudAccount(object):
    def __init__(self, params):
        self.username = params.get('username', '*/Credential/*')
        self.password = params.get('password', '*/Credential/*')
        self.api_endpoint = params.get('endpoint', '*/Credential/*')
        self.account_id = params.get('account_id', '*/Credential/*')

    def login(self):
        cmd = 'ibmcloud login -a "{}" -u "{}" -p "{}" -c "{}" --no-region'.format(
            self.api_endpoint, self.username, self.password, self.account_id)
        command(cmd)

    def logout(self):
        cmd = "ibmcloud logout"
        command(cmd)

    @staticmethod
    def show():
        cmd = "ibmcloud account show"
        ret = command(cmd)
        return json.loads(ret.stdout)

    @staticmethod
    def list():
        cmd = "ibmcloud account list"
        command(cmd)


class BootImage(Base):
    basecli = 'ibmcloud pi image'

    def __init__(self, params, **kwargs):
        """
        :param: name:[REQUIRED]image name
        """
        super(BootImage, self).__init__(params)
        self.name = kwargs.get("name") if "name" in kwargs else params.get(
            "image_name", "*/VM/*")
        self.path = params.get("image_path", "*/VM/*")
        self.ostype = kwargs.get("ostype") if "ostype" in kwargs else params.get(
            "ostype", "*/VM/*")
        self.accesskey = params.get("accesskey", "*/VM/*")
        self.secretkey = params.get("secretkey", "*/VM/*")
        # 
        self.id = None
        self.properties = None

    def imageimport(self):
        cmd = self.basecli + '-import {}  --image-path {}  --os-type {}  --access-key {}  --secret-key {} --json'.format(
            self.name, self.path, self.ostype, self.accesskey, self.secretkey)
        command(cmd)
        return True

    def delete(self):
        cmd = self.basecli + '-delete {} '.format(self.name)
        command(cmd)
        return True

    def show(self):
        cmd = self.basecli + ' {} '.format(self.name)
        try:
            ret = command(cmd)
        except:
            return False
        if len(ret.stdout):
            info = json.loads(ret.stdout)
            self.id = info["id"]
            self.properties = info
            return True

    def is_active(self):
        return self.properties.get("state") == "active"

    def listimages(self):
        cmd = self.basecli + "s --json"
        ret = command(cmd)
        return json.loads(ret.stdout)

    def exists(self):
        return self.show()

class Key(Base):
    basecli = 'ibmcloud pi key'
    def __init__(self, params):
        """
        :param: name:[REQUIRED]key name
        """
        super(Key, self).__init__(params)
        self.name = params.get("key", "*/VM/*")
        # 
        self.id = None
        self.properties = None

    def create(self):
        cmd = self.basecli + '-create {}  --json'.format(self.name)
        command(cmd)
        return self.show()

    def delete(self):
        cmd = self.basecli + '-delete {} '.format(self.name)
        command(cmd)
        return True

    def show(self):
        cmd = self.basecli + ' {}  --json'.format(self.name)
        try:
            ret = command(cmd)
        except:
            return False
        if len(ret.stdout):
            info = json.loads(ret.stdout)
            self.id = info["id"]
            self.properties = info
            return True

    def listkeys(self):
        cmd = self.basecli + "s --json"
        ret = command(cmd)
        return json.loads(ret.stdout)

class Network(Base):
    basecli = 'ibmcloud pi network'
    def __init__(self, params, **kwargs):
        """
        :param: name:[REQUIRED]network name
        """
        super(Network, self).__init__(params)
        self.name = params.get("network", "*/VM/*")
        #self.cidr = params.get("network", "*/VM/*")
        #self.ip_range = params.get("ip-range", "*/VM/*")
        #self.dns = params.get("dns", "*/VM/*")
        # 
        self.id = None
        self.properties = None

    # def create_private(self):
    #     cmd = self.basecli + '-create-private {}  --json'.format(self.name)
    #     command(cmd)
    #     return True

    # def create_public(self):
    #     cmd = self.basecli + '-create-public {}  --json'.format(self.name)
    #     command(cmd)
    #     return True

    # def delete(self):
    #     cmd = self.basecli + '-delete {} '.format(self.name)
    #     command(cmd)
    #     return True

    def show(self):
        cmd = self.basecli + ' {}  --json'.format(self.name)
        try:
            ret = command(cmd)
        except:
            return False
        if len(ret.stdout):
            info = json.loads(ret.stdout)
            self.id = info["id"]
            self.properties = info
            return True

    def listnetworks(self):
        cmd = self.basecli + "s --json"
        ret = command(cmd)
        return json.loads(ret.stdout)

class Service(object):
    basecli = 'ibmcloud pi service'
    def __init__(self, params):
        self.name = params.get("service", "*/VM/*")
        # 
        self.id = None
        self.properties = None

    def target(self):
        cmd = self.basecli + '-target {} '.format(self.name)
        command(cmd)
        return True
    
    @staticmethod
    def list(self):
        cmd = self.basecli + "-list --json"
        ret = command(cmd)
        return json.loads(ret.stdout)

class PowerVM(VM):
    basecli = 'ibmcloud pi instance'
    def __init__(self, params, **kwargs):
        super(PowerVM, self).__init__(params)
        self.vm_name = params.get("vm_name", "*/VM/*")
        self.image = params.get("image", "*/VM/*")
        self.memory = params.get("memory", "*/VM/*")
        # self.processors = params.get("processors", "*/VM/*")
        self.processor_type = params.get("processor_type", "*/VM/*")
        self.ssh_key_name = params.get("ssh_key_name", "*/VM/*")
        # self.volumes = params.get("volumes", "*/VM/*")
        # self.sys_type = params.get("sys_type", "*/VM/*")
        # self.storage_type = params.get("storage_type", "*/VM/*")
        self.storage_pool = params.get("storage-pool", "*/VM/*")
        self.network = params.get("network", "*/VM/*")
        #self.nics = kwargs.get("nics")
        self.id = None
        self.properties = {}
        self.public_network = {}

        # VM access parameters
        self.vm_username = params.get('username', '*/VM/*')
        self.vm_password = params.get('password', '*/VM/*')

    def show(self):
        name = self.id if self.id is not None else self.vm_name
        cmd = self.basecli + ' "{}" --json'.format(name)
        try:
            ret = command(cmd)
        except:
            return False   # when no vm exists
        if len(ret.stdout):
            info = json.loads(ret.stdout)
            self.properties = info
            if self.id is None:
                self.id = self.properties.get("pvmInstanceID")
            status = self.properties.get("status")
            if status == "ACTIVE":
                network_list = self.properties.get("networks")
                for network in network_list:
                    if network.get("networkName") == self.network:
                        self.public_network = network
                        return True
            return True
        return False

    def create(self, wait=True):
        cmd = self.basecli + '-create  "{}"  --image "{}" --json'\
            .format(self.vm_name, self.image)
        if self.memory:
            cmd += ' --memory {}'.format(self.memory)
        if self.network:
            cmd += ' --network {}'.format(self.network)
        if self.ssh_key_name:
            cmd += ' --key-name {}'.format(self.ssh_key_name) 
        # if self.processors:
        #     cmd += ' --processors "{}"'.format(self.processors)
        if self.processor_type:
            cmd += ' --processor-type "{}"'.format(self.processor_type)
        if self.storage_pool:
            cmd += ' --storage-pool {}'.format(self.storage_pool)
        # if self.volumes:
        #     cmd += ' --volumes {}'.format(self.volumes)
        # if self.sys_type:
        #     cmd += ' --sys-type "{}"'.format(self.sys_type)
        # if self.storage_type:
        #     cmd += ' --storage-type {}'.format(self.storage_type)

        try:
            ret = command(cmd)
        except:
            return False
        # waiting for VM is active
        LOG.info("Waiting for the health status of VM to be OK in 12 minutes...")
        time.sleep(720)
        if len(ret.stdout):
            info = json.loads(ret.stdout)
            self.properties = info[0]
            self.id = self.properties.get("pvmInstanceID")
            if wait:
                error_message = "Timed out waiting for server to be active."
                LOG.info("Waiting for the health status of VM to be OK in another 2 minutes...")
                time.sleep(120)
                for count in utils_misc.iterate_timeout(100,
                                                        error_message,
                                                        wait=10):
                    if self.show():
                        if self.is_started():
                            return True
            else:
                return self.show()
        # not active or not wait, just return the VM info
        return False

    def delete(self, wait=True):
        name = self.id if self.id is not None else self.vm_name
        cmd = self.basecli + '-delete "{}"'.format(name)
        try:
            command(cmd)
        except:
            return False
        # Sometimes VM still exists for a while after cli finished
        LOG.info("Waiting for the VM to be cleaned in 10 minutes...")
        time.sleep(600)
        if wait:
            error_message = "Timed out waiting for server to get deleted."
            for count in utils_misc.iterate_timeout(100,
                                                    error_message,
                                                    wait=10):
                if not self.exists():
                    time.sleep(60)  # waiting for other resource (network) release
                    break
    
    def capture(self, wait=True):
        capture_image_name = self.vm_name + "_capture_image"
        cmd = self.basecli + '-capture "{}" --destination image-catalog --name "{}" --json'\
            .format(self.vm_name, capture_image_name)
        # if self.volumes:
        #     cmd += ' --volumes {}'.format(self.volumes)
        ret = command(cmd)
        capture_image = BootImage(self.params, name=capture_image_name)
        # waiting for captured image is active
        if wait:
            error_message = "Timed out waiting for image to be active."
            for count in utils_misc.iterate_timeout(100,
                                                    error_message,
                                                    wait=10):
               
                capture_image.show()
                if capture_image.is_active():
                    return True
        # not active or not wait, just return the captured image info
        if len(ret.stdout):
            return capture_image.show()      

    def start(self, wait=True):
        cmd = self.basecli + '-start "{}"'.format(self.vm_name)
        ret = command(cmd)
        # waiting for VM is active
        if wait:
            error_message = "Timed out waiting for server to be active."
            for count in utils_misc.iterate_timeout(100,
                                                    error_message,
                                                    wait=10):
                self.show()
                if self.is_started():
                    return True
        # not active or not wait, just return the VM info
        if len(ret.stdout):
            return self.show()

    def reboot(self, wait=True):
        cmd = self.basecli + '-soft-reboot "{}"'.format(self.vm_name)
        ret = command(cmd)
        # waiting for VM is active
        if wait:
            error_message = "Timed out waiting for server to be active."
            for count in utils_misc.iterate_timeout(100,
                                                    error_message,
                                                    wait=10):
                self.show()
                if self.is_started():
                    return True
        # not active or not wait, just return the VM info
        if len(ret.stdout):
            return self.show()

    def hardreboot(self, wait=True):
        cmd = self.basecli + '-hard-reboot "{}"'.format(self.vm_name)
        ret = command(cmd)
        # waiting for VM is active
        if wait:
            error_message = "Timed out waiting for server to be active."
            for count in utils_misc.iterate_timeout(100,
                                                    error_message,
                                                    wait=10):
                self.show()
                if self.is_started():
                    return True
        # not active or not wait, just return the VM info
        if len(ret.stdout):
            return self.show()

    def shutdown(self, wait=True):
        cmd = self.basecli + '-immediate-shutdown "{}"'.format(self.vm_name)
        ret = command(cmd)
        # waiting for VM is stopped
        if wait:
            error_message = "Timed out waiting for server to be stopped."
            for count in utils_misc.iterate_timeout(100,
                                                    error_message,
                                                    wait=10):
                self.show()
                if self.is_stopped():
                    return True
        # not active or not wait, just return the VM info
        if len(ret.stdout):
            return self.show()

    def stop(self, wait=True):
        cmd = self.basecli + '-stop "{}"'.format(self.vm_name)
        ret = command(cmd)
        # waiting for VM is stopped
        if wait:
            error_message = "Timed out waiting for server to be stopped."
            for count in utils_misc.iterate_timeout(100,
                                                    error_message,
                                                    wait=10):
                self.show()
                if self.is_stopped():
                    return True
        # not active or not wait, just return the VM info
        if len(ret.stdout):
            return self.show()
    
    def exists(self):
        return self.show()

    def is_started(self):
        #return self.properties.get("status") == "ACTIVE"
        return self.properties.get("health").get("status") == "OK"

    def is_stopped(self):
        return self.properties.get("status") == "SHUTOFF"

    @property
    def public_ip(self):
        return self.public_network.get("externalIP")

    @property
    def floating_ip(self):
        return self.public_ip

    def __str__(self):
        return "[Name]:{}|[Image]:{}\
        ".format(self.vm_name, self.image)
