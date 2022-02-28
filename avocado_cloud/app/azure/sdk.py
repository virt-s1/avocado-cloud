"""
This module is used for converting linux 'az' commnad to python function
"""
import json
import time
import re

from avocado_cloud.app import VM
from avocado_cloud.app.base import Base
from avocado_cloud.utils.utils_azure import acommand as command
from avocado_cloud.utils import utils_misc


class AzureSdkError(Exception):
    def __init__(self, msg, output):
        super(AzureSdkError, self).__init__(msg, output)
        self.msg = msg
        self.output = output

    def __str__(self):
        return "[{}]\n{})".format(self.msg, self.output)


class AzureAccount(object):
    def __init__(self, params):
        self.username = params.get('username', '*/Credential/*')
        self.password = params.get('password', '*/Credential/*')

    def login(self):
        return
        cmd = 'az login -u "{}" -p "{}" --output json'.format(
            self.username, self.password)
        command(cmd)

    def logout(self):
        cmd = "az logout"
        command(cmd)

    @staticmethod
    def show():
        cmd = "az account show"
        ret = command(cmd)
        return json.loads(ret.stdout)

    @staticmethod
    def list():
        cmd = "az account list"
        command(cmd)


class AzureGroup(Base):
    def __init__(self, params, **kwargs):
        super(AzureGroup, self).__init__(params)
        size = kwargs.get("size") if "size" in kwargs else params.get(
            "size", "*/VM/*")
        self.name = params.get("resource_group",
                               "*/vm_sizes/{}/*".format(size))
        self.location = params.get("location", "*/vm_sizes/{}/*".format(size))
        # After the resource group creating,below properties will be setted
        self.id = None
        self.properties = None
        # self.managedby = None
        # self.tags = None

    def create(self):
        cmd = 'az group create --location "{}" --resource-group "{}"'.format(
            self.location, self.name)
        ret = command(cmd)
        if len(ret.stdout):
            info = json.loads(ret.stdout)
            self.id = info["id"]
            self.properties = info["properties"]
            return True

    def delete(self, wait=False):
        cmd = 'az group delete --resource-group "{}" -y'.format(self.name)
        if not wait:
            cmd += " --no-wait"
        command(cmd)
        return True

    def show(self):
        cmd = 'az group show --resource-group "{}"'.format(self.name)
        try:
            ret = command(cmd)
        except:
            return False
        if len(ret.stdout):
            info = json.loads(ret.stdout)
            self.id = info["id"]
            self.properties = info["properties"]
            return True

    def update(self):
        pass

    @staticmethod
    def list(location=None):
        cmd = "az group list"
        if location:
            cmd += " --query \"[?location=='{}']\"".format(location)
        ret = command(cmd)
        return json.loads(ret.stdout)

    def exists(self):
        cmd = 'az group exists --resource-group "{}"'.format(self.name)
        ret = command(cmd)
        # return true or false
        return ret.stdout


class AzureStorage(Base):
    def __init__(self, params):
        pass


class AzureVNET(Base):
    def __init__(self, params):
        pass


class AzureSubnet(Base):
    def __init__(self, params, **kwargs):
        super(AzureSubnet, self).__init__(params)
        size = kwargs.get("size") if "size" in kwargs else params.get(
            "size", "*/VM/*")
        self.resource_group = params.get("resource_group",
                                         "*/vm_sizes/{}/*".format(size))
        self.vnet = self.resource_group
        self.name = kwargs.get("name", self.vnet)
        # After the subnet is created, properties below will be set
        self.id = None
        self.properties = None
        # self.tags = None


class AzureNIC(Base):
    basecli = 'az network nic'

    def __init__(self, params, **kwargs):
        super(AzureNIC, self).__init__(params)
        '''
        :param: publicip: If set publicip name, this publicip will be assigned
                          to NIC while creating
        :param: sriov: true/false. If set true, accelerated-networking will be
                       enabled while creating NIC
        :param: ip_version: IPv4/IPv6
        '''
        size = kwargs.get("size") if "size" in kwargs else params.get(
            "size", "*/VM/*")
        self.resource_group = params.get("resource_group",
                                         "*/vm_sizes/{}/*".format(size))
        self.vnet = kwargs.get("vnet", self.resource_group)
        self.subnet = kwargs.get("subnet", self.vnet)
        timestamp = time.strftime("%m%d%H%M%S", time.localtime())
        self.name = kwargs.get("name", self.subnet + timestamp)
        self.publicip = kwargs.get("publicip")
        self.sriov = kwargs.get("sriov")
        self.ip_version = kwargs.get("ip_version")
        # After it is created, properties below will be set
        self.id = None
        self.properties = None
        # self.tags = None

    def create(self):
        cmd = self.basecli + ' create --name "{}" --resource-group "{}" '\
            '--vnet-name {} --subnet {}'.format(
                self.name, self.resource_group, self.vnet, self.subnet)
        if self.publicip:
            cmd += " --public-ip-address {}".format(self.publicip)
        if self.sriov:
            cmd += " --accelerated-networking {}".format(self.sriov)
        if self.ip_version:
            cmd += " --private-ip-address-version {}".format(self.ip_version)
        ret = command(cmd)
        if len(ret.stdout):
            info = json.loads(ret.stdout).get("NewNIC")
            self.id = info["id"]
            self.properties = info
            return True

    def delete(self, wait=False):
        cmd = self.basecli + \
            ' delete --name {} --resource-group "{}"'.format(
                self.name, self.resource_group)
        if not wait:
            cmd += " --no-wait"
        command(cmd)
        return True

    def show(self):
        cmd = self.basecli + \
            ' show --name {} --resource-group "{}"'.format(
                self.name, self.resource_group)
        try:
            ret = command(cmd)
        except:
            return False
        if len(ret.stdout):
            info = json.loads(ret.stdout)
            self.id = info["id"]
            self.properties = info
            return True

    def update(self):
        self.show()

    def list(self):
        cmd = self.basecli + " list"
        ret = command(cmd)
        return json.loads(ret.stdout)

    def exists(self):
        return self.show()


class AzurePublicIP(Base):
    basecli = 'az network public-ip'

    def __init__(self, params, **kwargs):
        """
        :param: name:[REQUIRED]publicip name
        :param: ip_version: IPv4/IPv6
        """
        super(AzurePublicIP, self).__init__(params)
        size = kwargs.get("size") if "size" in kwargs else params.get(
            "size", "*/VM/*")
        self.resource_group = params.get("resource_group",
                                         "*/vm_sizes/{}/*".format(size))
        timestamp = time.strftime("%m%d%H%M%S", time.localtime())
        self.name = kwargs.get("name", self.resource_group + timestamp)
        self.ip_version = kwargs.get("ip_version")
        # After it is created, properties below will be set
        self.id = None
        self.properties = None
        # self.tags = None

    def create(self):
        cmd = self.basecli + \
            ' create --name "{}" --resource-group "{}"'.format(
                self.name, self.resource_group)
        ret = command(cmd)
        if len(ret.stdout):
            info = json.loads(ret.stdout).get("publicIp")
            self.id = info["id"]
            self.properties = info
            return True

    def delete(self, wait=False):
        cmd = self.basecli + \
            ' delete --name {} --resource-group "{}"'.format(
                self.name, self.resource_group)
        if not wait:
            cmd += " --no-wait"
        command(cmd)
        return True

    def show(self):
        cmd = self.basecli + \
            ' show --name {} --resource-group "{}"'.format(
                self.name, self.resource_group)
        try:
            ret = command(cmd)
        except:
            return False
        if len(ret.stdout):
            info = json.loads(ret.stdout)
            self.id = info["id"]
            self.properties = info
            return True

    def update(self):
        self.show()

    def list(self):
        cmd = self.basecli + " list"
        ret = command(cmd)
        return json.loads(ret.stdout)

    def exists(self):
        return self.show()


class AzureNicIpConfig(Base):
    basecli = 'az network nic ip-config'

    def __init__(self, params, **kwargs):
        """
        :param: name:[REQUIRED]ip-config name
        :param: nic_name:[REQUIRED]The NIC name this ip-config will be added to
        :param: ip_version: IPv4/IPv6
        """
        super(AzureNicIpConfig, self).__init__(params)
        size = kwargs.get("size") if "size" in kwargs else params.get(
            "size", "*/VM/*")
        self.resource_group = params.get("resource_group",
                                         "*/vm_sizes/{}/*".format(size))
        timestamp = time.strftime("%m%d%H%M%S", time.localtime())
        self.name = kwargs.get("name", self.resource_group + timestamp)
        self.nic_name = kwargs.get("nic_name")
        self.vnet = kwargs.get("vnet", self.resource_group)
        self.subnet = kwargs.get("subnet", self.vnet)
        if not self.nic_name:
            raise Exception("Not specify NIC name")
        self.ip_version = kwargs.get("ip_version")
        # After it is created, properties below will be set
        self.id = None
        self.properties = None
        # self.tags = None

    def create(self):
        cmd = self.basecli + ' create --name "{}" --resource-group "{}" '\
            '--nic-name {} --vnet-name {} --subnet {}'.format(self.name,
                                                              self.resource_group, self.nic_name,
                                                              self.vnet, self.subnet)
        if self.ip_version:
            cmd += ' --private-ip-address-version {}'.format(self.ip_version)
        ret = command(cmd)
        if len(ret.stdout):
            info = json.loads(ret.stdout)
            self.id = info["id"]
            self.properties = info
            return True

    def delete(self, wait=False):
        cmd = self.basecli + ' delete --name {} --resource-group "{}" '\
            '--nic-name {}'.format(self.name,
                                   self.resource_group, self.nic_name)
        if not wait:
            cmd += " --no-wait"
        command(cmd)
        return True

    def show(self):
        cmd = self.basecli + ' show --name {} --resource-group "{}" '\
            '--nic-name {}'.format(self.name,
                                   self.resource_group, self.nic_name)
        try:
            ret = command(cmd)
        except:
            return False
        if len(ret.stdout):
            info = json.loads(ret.stdout)
            self.id = info["id"]
            self.properties = info
            return True

    def update(self):
        self.show()

    def list(self):
        cmd = self.basecli + " list"
        ret = command(cmd)
        return json.loads(ret.stdout)

    def exists(self):
        return self.show()


class AzureImage(Base):
    basecli = 'az image'

    def __init__(self, params, **kwargs):
        """
        :param: name:[REQUIRED]image name
        :param: source:[REQUIRED]The source(.vhd url) of the image
        """
        super(AzureImage, self).__init__(params)
        size = kwargs.get("size") if "size" in kwargs else params.get(
            "size", "*/VM/*")
        self.resource_group = params.get("resource_group",
                                         "*/vm_sizes/{}/*".format(size))
        vhd_name = params.get("image", "*/VM/*")
        storage_account = params.get("storage_account",
                                     "*/vm_sizes/{}/*".format(size))
        self.source = "https://{}.blob.core.windows.net/vhds/{}"\
                      .format(storage_account, vhd_name)
        timestamp = time.strftime("%m%d%H%M%S", time.localtime())
        self.generation = kwargs.get("generation", "V1")
        self.name = kwargs.get("name", "{}-{}-{}".format(vhd_name.replace(".vhd", ''),
                               self.generation, timestamp))
        # After it is created, properties below will be set
        self.id = None
        self.properties = None

    def create(self):
        cmd = self.basecli + ' create --name "{}" --resource-group "{}" '\
            '--source {} --hyper-v-generation {} --os-type linux'.format(
                self.name, self.resource_group, self.source, self.generation)
        ret = command(cmd)
        if len(ret.stdout):
            info = json.loads(ret.stdout)
            self.id = info["id"]
            self.properties = info
            return True

    def delete(self):
        cmd = self.basecli + ' delete --name {} --resource-group "{}"'.format(
                self.name, self.resource_group)
        command(cmd)
        return True

    def show(self):
        cmd = self.basecli + ' show --name {} --resource-group "{}"'.format(
                self.name, self.resource_group)
        try:
            ret = command(cmd)
        except:
            return False
        if len(ret.stdout):
            info = json.loads(ret.stdout)
            self.id = info["id"]
            self.properties = info
            return True

    def update(self):
        self.show()

    def list(self):
        cmd = self.basecli + " list"
        ret = command(cmd)
        return json.loads(ret.stdout)

    def exists(self):
        return self.show()


class AzureVM(VM):
    def __init__(self, params, **kwargs):
        super(AzureVM, self).__init__(params)
        vm_name_prefix = params.get("vm_name_prefix", "*/VM/*")
        size = kwargs.get("size") if "size" in kwargs else params.get(
            "size", "*/VM/*")
        self.vm_name = vm_name_prefix + \
            re.sub("[_-]", "", size.lower())
        self.resource_group = params.get("resource_group",
                                         "*/vm_sizes/{}/*".format(size))
        self.storage_account = params.get("storage_account",
                                          "*/vm_sizes/{}/*".format(size))
        self.size = params.get("name", "*/vm_sizes/{}/*".format(size))
        self.region = params.get("region", "*/vm_sizes/{}/*".format(size))
        self.image = params.get("image", "*/VM/*")
        if ".vhd" in self.image:
            self.image = "https://{}.blob.core.windows.net/vhds/{}"\
                         .format(self.storage_account, self.image)
        self.vm_username = params.get("vm_username", "*/VM/*", "azureuser")
        self.generate_ssh_keys = params.get("generate_ssh_keys", "*/VM/*")
        self.vm_password = params.get("vm_password", "*/VM/*")
        self.ssh_key_value = params.get("ssh_key_value", "*/VM/*")
        self.authentication_type = "ssh" if self.generate_ssh_keys or \
            self.ssh_key_value else "password"
        self.custom_data = params.get("custom_data", "*/VM/*")
        self.user_data = params.get("user_data", "*/VM/*")
        self.use_unmanaged_disk = params.get("use_unmanaged_disk", "*/VM/*")
        self.assign_identity = False
        subscription_id = AzureAccount.show().get("id")
        self.scope = "/subscriptions/{0}/resourceGroups/{1}"\
                     .format(subscription_id, self.resource_group)
        self.os_type = "linux"
        # 03.19 15:17:20  -->  0319151720
        self.os_disk_name = self.vm_name + "_os" + \
            time.strftime("%m%d%H%M%S", time.localtime())
        self.vnet_name = self.resource_group
        self.subnet = self.resource_group
        self.rhel_version = params.get("rhel_ver", "*/VM/*")
        self.nics = kwargs.get("nics")
        self.os_disk_size = kwargs.get("os_disk_size")
        self.properties = {}

    def show(self):
        cmd = 'az vm show -d --name "{}" --resource-group "{}"'.format(
            self.vm_name, self.resource_group)
        try:
            ret = command(cmd)
        except:
            return False
        if len(ret.stdout):
            info = json.loads(ret.stdout)
            self.properties = info
            return True
        return False

    def create(self, wait=True):
        cmd = 'az vm create --name "{}" --resource-group "{}" --image "{}" '\
            '--size "{}" --admin-username "{}" --authentication-type "{}" '\
            ' --os-disk-name "{}"'\
            .format(self.vm_name, self.resource_group, self.image,
                    self.size, self.vm_username, self.authentication_type,
                    self.os_disk_name)
        if self.ssh_key_value:
            cmd += ' --ssh-key-value {}'.format(self.ssh_key_value)
        elif self.generate_ssh_keys:
            cmd += " --generate-ssh-keys"
        if self.vm_password and self.authentication_type != "ssh":
            cmd += ' --admin-password "{}"'.format(self.vm_password)
        if self.custom_data:
            cmd += ' --custom-data "{}"'.format(self.custom_data)
        if self.user_data:
            cmd += ' --user-data "{}"'.format(self.user_data)
        if self.use_unmanaged_disk:
            cmd += ' --use-unmanaged-disk --storage-account {}'.format(self.storage_account)
        if self.assign_identity:
            cmd += " --assign-identity"
            cmd += ' --scope "{}"'.format(self.scope)
        if ".vhd" in self.image:
            cmd += ' --os-type "{}"'.format(self.os_type)
        if self.nics:
            cmd += ' --nics {}'.format(self.nics)
        else:
            cmd += ' --vnet-name "{}" --subnet "{}"'.format(
                self.vnet_name, self.subnet)
        if self.os_disk_size:
            cmd += ' --os-disk-size-gb {}'.format(self.os_disk_size)
        if not wait:
            cmd += " --no-wait"
        ret = command(cmd)
        if len(ret.stdout):
            return self.show()

    def delete(self, wait=True):
        cmd = 'az vm delete --name "{}" --resource-group "{}" --yes'.format(
            self.vm_name, self.resource_group)
        if not wait:
            cmd += " --no-wait"
        command(cmd)
        # Sometimes VM still exists for a while after cli finished
        if wait:
            error_message = "Timed out waiting for server to get deleted."
            for count in utils_misc.iterate_timeout(100,
                                                    error_message,
                                                    wait=10):
                if not self.exists():
                    break

    def start(self, wait=True):
        cmd = 'az vm start --name "{}" --resource-group "{}"'.format(
            self.vm_name, self.resource_group)
        if not wait:
            cmd += " --no-wait"
        command(cmd)
        self.show()

    def reboot(self, wait=True):
        cmd = 'az vm restart --name "{}" --resource-group "{}"'.format(
            self.vm_name, self.resource_group)
        if not wait:
            cmd += " --no-wait"
        command(cmd)
        self.show()

    def stop(self, wait=True):
        self.deallocate(wait)

    def deallocate(self, wait=True):
        cmd = 'az vm deallocate --name "{}" --resource-group "{}"'.format(
            self.vm_name, self.resource_group)
        if not wait:
            cmd += " --no-wait"
        command(cmd)
        self.show()

    def redeploy(self, wait=True):
        cmd = 'az vm redeploy --name "{}" --resource-group "{}"'.format(
            self.vm_name, self.resource_group)
        if not wait:
            cmd += " --no-wait"
        command(cmd)
        self.show()

    def exists(self):
        return self.show()

    def is_started(self):
        return self.properties.get("powerState") == "VM running"

    def is_stopped(self):
        return self.is_deallocated()

    def is_deallocated(self):
        return self.properties.get("powerState") == "VM deallocated"

    def osdisk_resize(self, size, wait=True):
        cmd = 'az vm update --name "{}" --resource-group {} '\
              '--set storageProfile.osDisk.diskSizeGB={}'\
              .format(self.vm_name, self.resource_group, size)
        if not wait:
            cmd += " --no-wait"
        command(cmd)

    def unmanaged_disk_attach(self, name, size, new=True, disk_uri=""):
        cmd = 'az vm unmanaged-disk attach --name {} --vm-name "{}" '\
              '--resource-group {} --size-gb {}'\
              .format(name, self.vm_name, self.resource_group, size)
        if new:
            cmd += " --new"
        else:
            cmd += " --vhd-uri {}".format(disk_uri)
        command(cmd)

    def unmanaged_disk_detach(self, name):
        cmd = 'az vm unmanaged-disk detach \
--name {} --vm-name "{}" --resource-group {}'.format(name, self.vm_name,
                                                     self.resource_group)
        command(cmd)

    def disk_attach(self, name, size, new=True):
        cmd = 'az vm disk attach --name {} --vm-name "{}" '\
              '--resource-group {} --size-gb {}'\
              .format(name, self.vm_name, self.resource_group, size)
        if new:
            cmd += " --new"
        command(cmd)

    def disk_detach(self, name):
        cmd = 'az vm disk detach --name {} --vm-name "{}" '\
              '--resource-group {}'.format(name, self.vm_name,
                                           self.resource_group)
        command(cmd)

    def user_update(self, username, password=None, ssh_key_value=None):
        cmd = 'az vm user update --name "{}" \
--resource-group {} --username {}'.format(self.vm_name, self.resource_group,
                                          username)
        if ssh_key_value:
            cmd += ' --ssh-key-value "{}"'.format(ssh_key_value)
        if password:
            cmd += ' --password "{}"'.format(password)
        command(cmd)

    def user_reset_ssh(self, timeout=1200):
        cmd = 'az vm user reset-ssh --name "{}" --resource-group {}'\
              .format(self.vm_name, self.resource_group)
        command(cmd, timeout)

    def run_command(self,
                    command_id="RunShellScript",
                    scripts=None,
                    parameters=None):
        cmd = 'az vm run-command invoke --name "{}" --resource-group {} \
--command-id {}'.format(self.vm_name, self.resource_group, command_id)
        if scripts:
            cmd += ' --scripts \'{}\''.format(scripts)
        if parameters:
            cmd += ' --parameters \'{}\''.format(parameters)
        ret = command(cmd)
        return json.loads(ret.stdout).get("value")[0].get("message")

    def extension_set(self,
                      name,
                      publisher,
                      settings='',
                      protected_settings=''):
        cmd = 'az vm extension set --name "{}" --vm-name "{}" \
--resource-group {} --publisher "{}"'.format(name, self.vm_name,
                                             self.resource_group, publisher)
        if protected_settings:
            cmd += " --protected-settings '{}'".format(protected_settings)
        if settings:
            cmd += " --settings '{}'".format(settings)
        command(cmd)

    def extension_delete(self, name):
        cmd = 'az vm extension delete --name "{}" --vm-name "{}" \
--resource-group {}'.format(name, self.vm_name, self.resource_group)
        command(cmd)

    @property
    def public_ip(self):
        return self.properties.get("publicIps")

    @property
    def floating_ip(self):
        return self.public_ip

    def __str__(self):
        return "[Name]:{}|[Resource_Group]:{}|[Image]:{}|[size]:{}|[Admin_username]:{}\
        ".format(self.vm_name, self.resource_group, self.image, self.size,
                 self.vm_username)
