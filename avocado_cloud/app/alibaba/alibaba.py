import json
import logging
import os
from aliyunsdkcore.client import AcsClient
from aliyunsdkecs.request.v20140526 import DescribeInstancesRequest
from aliyunsdkecs.request.v20140526 import CreateInstanceRequest
from aliyunsdkecs.request.v20140526 import StartInstanceRequest
from aliyunsdkecs.request.v20140526 import StopInstanceRequest
from aliyunsdkecs.request.v20140526 import RebootInstanceRequest
from aliyunsdkecs.request.v20140526 import DeleteInstanceRequest
from aliyunsdkecs.request.v20140526 import DescribeInstanceAttributeRequest
from aliyunsdkecs.request.v20140526 import ModifyInstanceAttributeRequest
from aliyunsdkecs.request.v20140526 import ModifyInstanceSpecRequest
from aliyunsdkecs.request.v20140526 import AllocatePublicIpAddressRequest
from aliyunsdkecs.request.v20140526 import DescribeKeyPairsRequest
from aliyunsdkecs.request.v20140526 import CreateKeyPairRequest
from aliyunsdkecs.request.v20140526 import ImportKeyPairRequest
from aliyunsdkecs.request.v20140526 import DeleteKeyPairsRequest
from aliyunsdkecs.request.v20140526 import DescribeImagesRequest
from aliyunsdkecs.request.v20140526 import CreateImageRequest
from aliyunsdkecs.request.v20140526 import DescribeDisksRequest
from aliyunsdkecs.request.v20140526 import CreateDiskRequest
from aliyunsdkecs.request.v20140526 import DeleteDiskRequest
from aliyunsdkecs.request.v20140526 import AttachDiskRequest
from aliyunsdkecs.request.v20140526 import DetachDiskRequest
from aliyunsdkecs.request.v20140526 import CreateNetworkInterfaceRequest
from aliyunsdkecs.request.v20140526 import AttachNetworkInterfaceRequest
from aliyunsdkecs.request.v20140526 import DescribeNetworkInterfacesRequest
from aliyunsdkecs.request.v20140526 import DetachNetworkInterfaceRequest
from aliyunsdkecs.request.v20140526 import DeleteNetworkInterfaceRequest
from aliyunsdkecs.request.v20140526 import GetInstanceConsoleOutputRequest
from aliyunsdkecs.request.v20140526 import DescribeAvailableResourceRequest
from aliyunsdkecs.request.v20140526 import AssignPrivateIpAddressesRequest
from aliyunsdkecs.request.v20140526 import UnassignPrivateIpAddressesRequest
from aliyunsdkecs.request.v20140526 import RunInstancesRequest

class AliyunConfig(object):

    aliyuncli = os.path.join(os.path.expanduser('~'), ".aliyuncli")
    configure = {"path": os.path.join(aliyuncli, "configure")}
    credentials = {"path": os.path.join(aliyuncli, "credentials")}
    ossutilconfig = {"path": os.path.join(aliyuncli, ".ossutilconfig")}

    configure["content"] = """\
[default]
output = json
region = %(region)s
"""

    credentials["content"] = """\
[default]
aliyun_access_key_secret = %(access_key_secret)s
aliyun_access_key_id = %(access_key_id)s
"""

    ossutilconfig["content"] = """\
[Credentials]
language=CH
endpoint=oss-%(region)s.aliyuncs.com
accessKeyID=%(access_key_id)s
accessKeySecret=%(access_key_secret)s
"""

    def __init__(self,
                 access_key_id=None,
                 access_key_secret=None,
                 region=None):
        self.config = dict()
        self.config["access_key_id"] = access_key_id
        self.config["access_key_secret"] = access_key_secret
        self.config["region"] = region
        if not os.path.isdir(self.aliyuncli):
            os.makedirs(self.aliyuncli, 0o755)

    def _write_file(self, cfile):
        with open(cfile["path"], 'w') as f:
            f.write(cfile["content"] % self.config)

    def update(self):
        self._write_file(self.credentials)
        self._write_file(self.configure)
        self._write_file(self.ossutilconfig)
        logging.info("Update configurations finished.")


class AlibabaSDK(object):
    def __init__(self, params):
        # Alibaba connection credentials
        access_key_id = params.get('access_key_id', '*/Credential/*')
        access_key_secret = params.get('secretaccess_key', '*/Credential/*')
        region = params.get('region', '*/VM/*')

        AliyunConfig(access_key_id=access_key_id,
                     access_key_secret=access_key_secret,
                     region=region).update()
        self.clt = AcsClient(access_key_id, access_key_secret, region)

        # VM parameters
        self.vm_params = dict()
        self.vm_params["InstanceType"] = params.get('name', '*/Flavor/*')
        self.vm_params["RegionId"] = region
        self.vm_params["InstanceName"] = params.get('vm_name',
                                                    '*/VM/*').replace(
                                                        '_', '-')
        self.vm_params["HostName"] = self.vm_params["InstanceName"]
        self.vm_params["Username"] = params.get('username', '*/VM/*')
        self.vm_params["Password"] = params.get('password', '*/VM/*')
        self.vm_params["KeyPairName"] = params.get('keypair', '*/VM/*')
        self.vm_params["ZoneId"] = params.get('az', '*/VM/*')
        self.vm_params["DedicatedHostId"] = params.get('ddh_id', '*/VM/*')
        self.vm_params["ImageName"] = params.get('name', '*/Image/*')
        self.vm_params["ImageId"] = params.get('id', '*/Image/*')
        self.vm_params["SecurityGroupId"] = params.get('id',
                                                       '*/SecurityGroup/*')
        self.vm_params["VSwitchId"] = params.get('id', '*/Network/VSwitch/*')
        self.vm_params["DiskName"] = params.get('cloud_disk_name', '*/Disk/*')
        self.vm_params["Size"] = params.get('cloud_disk_size', '*/Disk/*')
        self.vm_params["NetworkInterfaceName"] = params.get(
            'nic_name', '*/NIC/*')

        # Assign SystemDiskCategory and DiskCategory
        self.vm_params["SystemDiskCategory"] = self.select_disk_category(
            'SystemDisk')
        self.vm_params["DiskCategory"] = self.select_disk_category('DataDisk')

        logging.info('Assigned. SystemDiskCategory="{}"; DiskCategory="{}".'.format(
            self.vm_params['SystemDiskCategory'], self.vm_params['DiskCategory']))

    def _send_request(self, request):
        request.set_accept_format('json')
        try:
            logging.debug("Run: {0}".format(request.__class__.__name__))
            #            logging.debug(
            #               "Request: %s" % request.get_query_params())
            response_str = self.clt.do_action_with_exception(request)
            response_detail = json.loads(response_str)
            #            logging.debug("Response: %s" % response_detail)
            return response_detail
        except Exception as e:
            logging.error(e)
            return e

    @staticmethod
    def _add_params(request, key_list=None, params=None):
        if params is None:
            return request
        if key_list:
            for key in key_list:
                if params.get(key) is not None:
                    value = params.get(key)
                    if "Ids" in key or "Names" in key:
                        value = str(value.split(',')).replace('\'', '"')
                    eval("request.set_{0}('{1}')".format(key, value))
        request.get_query_params()
        return request

    # Instance
    def describe_instances(self):
        request = DescribeInstancesRequest.DescribeInstancesRequest()
        key_list = ["InstanceName", "InstanceIds"]
        self.vm_params.setdefault("InstanceName",
                                  self.vm_params["InstanceName"])
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    #def run_instances(self, authentication="publickey"):
    def create_instance(self, authentication="publickey"):
        request = CreateInstanceRequest.CreateInstanceRequest()
        key_list = [
            "InstanceChargeType", "ImageId", "InstanceType",
            "InternetChargeType", "SecurityGroupId", "VSwitchId",
            "SystemDiskCategory", "HostName", "InstanceName",
            "InternetMaxBandwidthOut", "InternetMaxBandwidthIn", "ZoneId", "DedicatedHostId"
        ]
        self.vm_params.setdefault("InstanceChargeType", "PostPaid")
        self.vm_params.setdefault("InternetChargeType", "PayByTraffic")
        self.vm_params.setdefault("SystemDiskCategory",
                                  self.vm_params['SystemDiskCategory'])
        self.vm_params.setdefault("InternetMaxBandwidthIn", "5")
        self.vm_params.setdefault("InternetMaxBandwidthOut", "5")
        if authentication == "publickey":
            key_list.append("KeyPairName")
        elif authentication == "password":
            key_list.append("Password")
        request = self._add_params(request, key_list, self.vm_params)
        response = self._send_request(request)
        if isinstance(response, Exception):
            raise response
        return response

    def start_instance(self, instance_id):
        request = StartInstanceRequest.StartInstanceRequest()
        key_list = ["InstanceId"]
        self.vm_params["InstanceId"] = instance_id
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def stop_instance(self, instance_id, force=False):
        request = StopInstanceRequest.StopInstanceRequest()
        key_list = ["InstanceId", "ForceStop"]
        self.vm_params["InstanceId"] = instance_id
        if force:
            self.vm_params["ForceStop"] = force
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def reboot_instance(self, instance_id, force=False):
        request = RebootInstanceRequest.RebootInstanceRequest()
        key_list = ["InstanceId", "ForceStop"]
        self.vm_params["InstanceId"] = instance_id
        if force:
            self.vm_params["ForceStop"] = force
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def delete_instance(self, instance_id):
        request = DeleteInstanceRequest.DeleteInstanceRequest()
        key_list = ["InstanceId"]
        self.vm_params["InstanceId"] = instance_id
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def describe_instance_attribute(self, instance_id):
        request = DescribeInstanceAttributeRequest.\
            DescribeInstanceAttributeRequest()
        key_list = ["InstanceId"]
        self.vm_params["InstanceId"] = instance_id
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def modify_instance_attribute(self, instance_id, new_password):
        request = ModifyInstanceAttributeRequest.\
            ModifyInstanceAttributeRequest()
        key_list = ["InstanceId", "Password"]
        self.vm_params["InstanceId"] = instance_id
        self.vm_params["Password"] = new_password
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def modify_instance_spec(self, instance_id, new_type):
        request = ModifyInstanceSpecRequest.ModifyInstanceSpecRequest()
        key_list = [
            "InstanceId", "InstanceType", "InternetMaxBandwidthIn",
            "InternetMaxBandwidthOut"
        ]
        self.vm_params["InstanceId"] = instance_id
        self.vm_params["InstanceType"] = new_type
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    # Resource
    def describe_available_resource(self, destination_resource):
        # destination_resource: ['Zone', 'IoOptimized', 'InstanceType',
        #                        'SystemDisk', 'DataDisk', 'Network', 'ddh']
        request = DescribeAvailableResourceRequest.DescribeAvailableResourceRequest()
        key_list = ["DestinationResource", "ZoneId", "InstanceType"]
        self.vm_params["DestinationResource"] = destination_resource
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def select_disk_category(self, category):
        """Select Available Disk Category by ZoneId and InstanceType."""

        if category not in ('SystemDisk', 'DataDisk'):
            logging.error(
                'Unsupported category! category = {}'.format(category))
            return 'cloud_efficiency'

        _data = self.describe_available_resource(category)

        _azone = _data.get('AvailableZones', {}).get('AvailableZone', [])
        if len(_azone) != 1 or _azone[0].get('Status') != 'Available':
            logging.error('Resource unavailable! _azone = {}'.format(_azone))
            return 'cloud_efficiency'

        _resource = _azone[0].get(
            'AvailableResources', {}).get('AvailableResource', [])
        if len(_resource) != 1 or _resource[0].get('Type') != category:
            logging.error(
                'Resource unavailable! _resource = {}'.format(_resource))
            return 'cloud_efficiency'

        _disk = _resource[0].get(
            'SupportedResources', {}).get('SupportedResource', [])
        _disk_categories = [
            x.get('Value') for x in _disk if x.get('Status') == 'Available']

        if len(_disk_categories) == 0:
            logging.error('Resource unavailable! _disk_categories = []')
            return 'cloud_efficiency'

        if 'cloud_essd' in _disk_categories:
            disk_category = 'cloud_essd'
        elif 'cloud_ssd' in _disk_categories:
            disk_category = 'cloud_ssd'
        elif 'cloud_efficiency' in _disk_categories:
            disk_category = 'cloud_efficiency'
        else:
            disk_category = _disk_categories[0]

        logging.info('Selected {} Category "{}" from {}'.format(
            category, disk_category, _disk_categories))

        return disk_category

    # Public IP
    def allocate_public_ip_address(self, instance_id):
        request = AllocatePublicIpAddressRequest.\
            AllocatePublicIpAddressRequest()
        key_list = ["InstanceId"]
        self.vm_params["InstanceId"] = instance_id
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    # KeyPair
    def describe_keypairs(self):
        request = DescribeKeyPairsRequest.DescribeKeyPairsRequest()
        key_list = ["KeyPairName", "RegionId"]
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def create_keypair(self):
        request = CreateKeyPairRequest.CreateKeyPairRequest()
        key_list = ["KeyPairName", "RegionId"]
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def import_keypair(self):
        request = ImportKeyPairRequest.ImportKeyPairRequest()
        key_list = ["KeyPairName", "RegionId", "PublicKeyBody"]
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def delete_keypair(self):
        request = DeleteKeyPairsRequest.DeleteKeyPairsRequest()
        key_list = ["KeyPairNames", "RegionId"]
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    # Image
    def describe_images(self):
        request = DescribeImagesRequest.DescribeImagesRequest()
        key_list = ["ImageName", "ImageId"]
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def create_image(self):
        request = CreateImageRequest.CreateImageRequest()
        key_list = ["ImageName", "SnaoshotId", "Platform"]
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    # Disk
    def describe_disks(self, diskids=None):
        """Describe cloud disks.

        diskids should be a string like '"id1","id2","id3"'.
        """
        request = DescribeDisksRequest.DescribeDisksRequest()
        key_list = ["ZoneId", "DiskName", "Category", "PageSize"]
        self.vm_params.setdefault("Category", self.vm_params['DiskCategory'])
        self.vm_params.setdefault("PageSize", "100")
        if diskids:
            key_list.append("DiskIds")
            self.vm_params["DiskIds"] = diskids
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def create_disk(self):
        request = CreateDiskRequest.CreateDiskRequest()
        key_list = ["ZoneId", "DiskName", "DiskCategory", "Size"]
        self.vm_params.setdefault("DiskCategory",
                                  self.vm_params['DiskCategory'])
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def delete_disk(self, diskid):
        request = DeleteDiskRequest.DeleteDiskRequest()
        key_list = ["DiskId"]
        self.vm_params["DiskId"] = diskid
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def attach_disk(self, instance_id, diskid=None):
        request = AttachDiskRequest.AttachDiskRequest()
        key_list = ["InstanceId", "DiskId"]
        self.vm_params["InstanceId"] = instance_id
        self.vm_params["DiskId"] = diskid
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def detach_disk(self, instance_id, diskid=None):
        request = DetachDiskRequest.DetachDiskRequest()
        key_list = ["InstanceId", "DiskId"]
        self.vm_params["InstanceId"] = instance_id
        self.vm_params["DiskId"] = diskid
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def create_nic(self, primary_ip_address=None):
        request = CreateNetworkInterfaceRequest.CreateNetworkInterfaceRequest()
        key_list = [
            "NetworkInterfaceName", "PrimaryIpAddress", "VSwitchId",
            "SecurityGroupId"
        ]
        self.vm_params["PrimaryIpAddress"] = primary_ip_address
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def attach_nic(self, instance_id, nic_id):
        request = AttachNetworkInterfaceRequest.AttachNetworkInterfaceRequest()
        key_list = ["InstanceId", "NetworkInterfaceId"]
        self.vm_params["InstanceId"] = instance_id
        self.vm_params["NetworkInterfaceId"] = nic_id
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def describe_nics(self,
                      instance_id=None,
                      nic_type=None,
                      nic_name="default",
                      nic_ids=None):
        request = DescribeNetworkInterfacesRequest.\
            DescribeNetworkInterfacesRequest()
        key_list = ["InstanceId", "Type"]
        self.vm_params["InstanceId"] = instance_id
        self.vm_params["Type"] = nic_type
        if nic_name:
            if not nic_name == "default":
                self.vm_params["NetworkInterfaceName"] = nic_name
            key_list.append("NetworkInterfaceName")
        if nic_ids:
            if not isinstance(nic_ids, str):
                nic_ids = ','.join(nic_ids)
            key_list.append("NetworkInterfaceIds")
            self.vm_params["NetworkInterfaceIds"] = nic_ids
        key_list.append("PageSize")
        self.vm_params["PageSize"] = 500
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def detach_nic(self, instance_id, nic_id):
        request = DetachNetworkInterfaceRequest.DetachNetworkInterfaceRequest()
        key_list = ["InstanceId", "NetworkInterfaceId"]
        self.vm_params["InstanceId"] = instance_id
        self.vm_params["NetworkInterfaceId"] = nic_id
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    def delete_nic(self, nic_id):
        request = DeleteNetworkInterfaceRequest.DeleteNetworkInterfaceRequest()
        key_list = ["NetworkInterfaceId"]
        self.vm_params["NetworkInterfaceId"] = nic_id
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    # Assign Secondary Private IPs
    def assign_private_ips(self, nic_id, secondary_private_ip_count):
        request = AssignPrivateIpAddressesRequest.AssignPrivateIpAddressesRequest()
        key_list = ["NetworkInterfaceId", "SecondaryPrivateIpAddressCount"]
        self.vm_params["NetworkInterfaceId"] = nic_id
        self.vm_params["SecondaryPrivateIpAddressCount"] = secondary_private_ip_count
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)

    # Unassign Secondary Private IPs
    def unassign_private_ips(self, nic_id, secondary_private_ip_list):
        request = UnassignPrivateIpAddressesRequest.UnassignPrivateIpAddressesRequest()
        key_list = ["NetworkInterfaceId"]
        self.vm_params["NetworkInterfaceId"] = nic_id
        request = self._add_params(request, key_list, self.vm_params)
        request.set_PrivateIpAddresss(secondary_private_ip_list)
        return self._send_request(request)

    def get_console_log(self, instance_id):
        request = GetInstanceConsoleOutputRequest.GetInstanceConsoleOutputRequest(
        )
        key_list = ['InstanceId']
        self.vm_params["InstanceId"] = instance_id
        request = self._add_params(request, key_list, self.vm_params)
        return self._send_request(request)
