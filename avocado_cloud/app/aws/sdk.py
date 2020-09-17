import boto3
import logging
import time
from botocore.exceptions import ClientError
from botocore.config import Config
import botocore.exceptions as boto_err
from avocado_cloud.app import VM
from avocado_cloud.app import Base

LOG = logging.getLogger('avocado.test')
logging.basicConfig(level=logging.DEBUG)


class EC2VM(VM):
    config = Config(retries=dict(max_attempts=10, ))
    __resource = boto3.resource('ec2', config=config)
    __client = boto3.client('ec2', config=config)
    __ec2_instance = None

    def __init__(self, params, vendor="redhat"):
        super(EC2VM, self).__init__(params)
        self.instance_id = None
        self.ipv4 = None
        self.ssh_user = params.get('ssh_user')
        if vendor == "amzn2_x86":
            self.ami_id = params.get('amzn2_ami_id_x86')
        elif vendor == "amzn2_arm":
            self.ami_id = params.get('amzn2_ami_id_arm')
        elif vendor == "ubuntu_x86":
            self.ami_id = params.get('ubuntu_ami_id_x86')
            self.ssh_user = params.get('ubuntu_ssh_user')
        elif vendor == "ubuntu_arm":
            self.ami_id = params.get('ubuntu_ami_id_arm')
            self.ssh_user = params.get('ubuntu_ssh_user')
        else:
            self.ami_id = params.get('ami_id')
        LOG.info("AMI picked {} {} {}".format(vendor, self.ami_id, self.ssh_user))
        self.instance_type = params.get('instance_type')
        self.vm_base = params.get('base')
        self.vpc_id = params.get('vpc_id')
        if params.get('ipv6'):
            self.subnet_id = params.get('subnet_id_ipv6')
            LOG.info('Instance support ipv6, use subnet %s', self.subnet_id)
        else:
            self.subnet_id = params.get('subnet_id_ipv4')
            LOG.info('Instance only support ipv4, use subnet %s',
                     self.subnet_id)
        self.security_group_ids = params.get('security_group_ids')
        self.region = params.get('region')
        self.zone = params.get('availability_zone', '*/Cloud/*')
        self.additionalinfo = params.get('additionalinfo', '*/Cloud/*')
        self.tagname = params.get('ec2_tagname')
        self.ssh_key_name = params.get('ssh_key_name')
        self.ssh_key_path = params.get('ssh_key_path')
        self.vm_username = self.ssh_user
        self.vm_password = None
        self.ssh_conn = None
        self.__volume_id = None

    def reuse_init(self, instance_id, type_check=True):
        '''
        To reuse an exist instance than create a new one
        @params: instance_id id of existing instance
        '''
        if instance_id is None:
            return False
        try:
            self.__ec2_instance = self.__resource.Instance(instance_id)
            for x in range(10):
                if self.is_stopping():
                    LOG.info("Wait for 60 seconds, max 10 mins")
                    time.sleep(60)
                else:
                    break
            if self.is_stopping():
                LOG.info("Instance is still stopping, cannot use it ")
                return False
            if self.is_shutting_down():
                LOG.info("Instance is shutting-down, cannot reuse it")
                return False
            if self.is_deleted():
                LOG.info("Instance is terminated, cannot reuse it")
                return False
            if type_check:
                if self.__ec2_instance.instance_type == self.params.get(
                        'instance_type'):
                    LOG.info("Instance type matched, reuse it.")
                    self.boot_volume_id
                    self.instance_id = self.__ec2_instance.id
                    return True
                else:
                    LOG.error(
                        "Instance type does not match, cannot reuse %s!" %
                        instance_id)
                    return False
            else:
                LOG.info("Reuse %s without instance type check!" % instance_id)
                return True
        except Exception as err:
            LOG.error(err)
            return False

    def create(self, wait=True):
        try:
            if self.additionalinfo == None or self.additionalinfo == '':
                self.__ec2_instance = self.__resource.create_instances(
                    ImageId=self.ami_id,
                    InstanceType=self.instance_type,
                    KeyName=self.ssh_key_name,
                    #SecurityGroupIds=[
                    #    self.security_group_ids,
                    #],
                    #SubnetId=self.subnet_id,
                    MaxCount=1,
                    MinCount=1,
                    Placement={
                        'AvailabilityZone': self.zone,
                    },
                    NetworkInterfaces=[
                        {
                            'AssociatePublicIpAddress': True,
                            'DeviceIndex': 0,
                            'SubnetId': self.subnet_id,
                            'Groups': [
                                 self.security_group_ids,
                             ],
                        },
                    ],
                    UserData='#!/bin/bash\nmkdir /home/%s/instance_create_%s' %
                    (self.ssh_user, self.instance_type))[0]
            else:
                self.__ec2_instance = self.__resource.create_instances(
                    ImageId=self.ami_id,
                    InstanceType=self.instance_type,
                    KeyName=self.ssh_key_name,
                    #SecurityGroupIds=[
                    #    self.security_group_ids,
                    #],
                    #SubnetId=self.subnet_id,
                    MaxCount=1,
                    MinCount=1,
                    Placement={
                            'AssociatePublicIpAddress': True,
                            'DeviceIndex': 0,
                            'SubnetId': self.subnet_id,
                            'Groups': [
                                 self.security_group_ids,
                             ],
                    },
                    AdditionalInfo=self.additionalinfo,
                    NetworkInterfaces=[
                        {
                            'AssociatePublicIpAddress': True
                        },
                    ],
                    UserData='#!/bin/bash\nmkdir /home/%s/instance_create_%s' %
                    (self.ssh_user, self.instance_type))[0]
        except ClientError as err:
            LOG.error("Failed to create instance!")
            raise err
        except Exception as err:
            raise err

        self.create_tags()
        LOG.info("Added tag: %s to instance: %s" %
                 (self.tagname, self.__ec2_instance.id))
        if wait:
            try:
                self.__ec2_instance.wait_until_running()
                self.__ec2_instance.reload()
            except Exception as err:
                LOG.error("Failed to wait instance running! %s" % err)

        self.instance_id = self.__ec2_instance.id
        # self.ipv4 = self.__ec2_instance.public_ip_address
        self.ipv4 = self.__ec2_instance.public_dns_name
        self.boot_volume_id

    def create_tags(self):
        try:
            self.__client.create_tags(Resources=[self.__ec2_instance.id],
                                      Tags=[{
                                          'Key': 'Name',
                                          'Value': self.tagname
                                      }])
        except ClientError as err:
            LOG.error("Failed to add tag to %s" % self.__ec2_instance.id)

    def show(self):
        pass

    @property
    def res_id(self):
        '''
        return resource id for local resource management
        '''
        return self.__ec2_instance.id

    @property
    def res_type(self):
        '''
        return resource id for local resource management
        '''
        return self.__ec2_instance.instance_type

    @property
    def res_name(self):
        '''
        return resource name for local resource management
        '''
        return 'instance'

    def start(self, wait=True):
        try:
            self.__ec2_instance.start()
        except Exception as err:
            LOG.error(err)
            return False

        if wait:
            self.__ec2_instance.wait_until_running()
            if self.__ec2_instance.state['Name'] == 'running':
                LOG.info("Instance is in running state!")
            else:
                LOG.error(
                    "Instance is not in running state! It is in %s state!" %
                    self.__ec2_instance.state['Name'])
                return False
            self.__ec2_instance.reload()
            # self.ipv4 = self.__ec2_instance.public_ip_address
            self.ipv4 = self.__ec2_instance.public_dns_name
        return True

    def stop(self, wait=True, loops=4):
        try:
            LOG.info("Stopping instance %s " % self.instance_id)
            self.__ec2_instance.stop()
        except Exception as err:
            LOG.error("%s" % err)
            return False

        if wait:
            for i in xrange(0, loops):
                LOG.info("Wait loop %s, max loop %s" % (i, loops))
                try:
                    self.__ec2_instance.wait_until_stopped()
                    return self.is_stopped()
                except boto_err.WaiterError as err:
                    LOG.error("%s" % err)
            return self.is_stopped()
        return True

    def reboot(self, wait=False):
        '''
        Reboot from outside
        '''
        LOG.info("Rebooting instance: %s" % self.instance_id)
        try:
            self.__ec2_instance.reboot()
            return True
        except Exception as err:
            LOG.error(err)
            return False

    def delete(self, wait=True, loops=4):
        try:
            LOG.info("Deleting instance: %s" % self.__ec2_instance.id)
            self.__ec2_instance.terminate()
        except Exception as err:
            LOG.info(err)
            return False
        if wait:
            for i in xrange(0, loops):
                LOG.info("Wait loop %s, max loop %s" % (i, loops))
                try:
                    self.__ec2_instance.wait_until_terminated()
                    return self.is_deleted()
                except boto_err.WaiterError as err:
                    LOG.error(err)
            return self.is_deleted()
        return True

    def send_nmi(self):
        try:
            LOG.info("Send diagnostic interrupt to %s" %
                     (self.__ec2_instance.id))
            self.__client.send_diagnostic_interrupt(
                InstanceId=self.__ec2_instance.id, DryRun=False)
            return True
        except ClientError as err:
            LOG.error("Failed to send_diagnostic_interrupt to %s" %
                      self.__ec2_instance.id)
            return False

    def exists(self):
        if self.__ec2_instance is None:
            LOG.info("Instance does not exist!")
            return False
        if self.is_deleted():
            LOG.info("Instance is in terminate state!")
            return False
        else:
            LOG.info("Instance exists: %s" % self.instance_id)
            return True

    def is_started(self):
        try:
            self.__ec2_instance.reload()
            if self.__ec2_instance.state['Name'] == 'running':
                LOG.info("Instance is in running state!")
                return True
            else:
                LOG.info(
                    "Instance is not in running state! It is in %s state" %
                    self.__ec2_instance.state['Name'])
                return False
        except Exception as err:
            LOG.info(err)
            return False

    def is_stopped(self):
        self.__ec2_instance.reload()
        if self.__ec2_instance.state['Name'] == 'stopped':
            LOG.info("Instance is in stopped state!")
            return True
        else:
            LOG.info("Instance is not in stopped state! It is in %s state!" %
                     self.__ec2_instance.state['Name'])
            return False

    def is_stopping(self):
        self.__ec2_instance.reload()
        if self.__ec2_instance.state['Name'] == 'stopping':
            LOG.info("Instance is in stopping state!")
            return True
        else:
            LOG.info("Instance is not in stopping state! It is in %s state!" %
                     self.__ec2_instance.state['Name'])
            return False

    def is_shutting_down(self):
        self.__ec2_instance.reload()
        if self.__ec2_instance.state['Name'] == 'shutting-down':
            LOG.info("Instance is in shutting-down state!")
            return True
        else:
            LOG.info(
                "Instance is not in shutting-down state! It is in %s state!" %
                self.__ec2_instance.state['Name'])
            return False

    def is_deleted(self):
        try:
            self.__ec2_instance.reload()
            if self.__ec2_instance.state['Name'] == 'terminated':
                LOG.info("Instance is in terminated state!")
                return True
            else:
                LOG.error(
                    "Instance is not in terminated state! It is in %s state!" %
                    self.__ec2_instance.state['Name'])
                return False
        except Exception as err:
            LOG.info("Failed to get instance status, it may not exist! %s" %
                     err)
            return True

    @property
    def floating_ip(self):
        if self.ipv4 is None:
            LOG.info("No public ip available! Try to reload it!")

        self.__ec2_instance.reload()
        self.ipv4 = self.__ec2_instance.public_dns_name
        LOG.info("Public ip is: %s" % self.ipv4)
        return self.ipv4

    @property
    def priviate_ip(self):
        self.__ec2_instance.reload()
        LOG.info("Private ip is: %s" % self.__ec2_instance.private_ip_address)
        return self.__ec2_instance.private_ip_address

    @property
    def boot_volume_id(self):
        for i in self.__ec2_instance.volumes.all():
            if 'sda' in i.attachments[0].get('Device') \
                    or 'xvda' in i.attachments[0].get('Device') \
                    or 'nvme0' in i.attachments[0].get('Device'):
                self.__volume_id = i.id
                LOG.info("Boot volume id: %s" % self.__volume_id)
                return self.__volume_id
        return None

    def get_volumes_id(self):
        volumes_list = []
        LOG.info("Try to get all attached volumes!")
        self.__ec2_instance.reload()
        for i in self.__ec2_instance.volumes.all():
            volumes_list.append(i.id)
        LOG.info(volumes_list)
        return volumes_list

    def get_console_log(self):
        try:
            output = self.__ec2_instance.console_output(Latest=True).get('Output')
            return True, output
        except Exception as err:
            LOG.error("Failed to get console log, try without latest! %s" % err)
        try:
            output = self.__ec2_instance.console_output().get('Output')
            return True, output
        except Exception as err:
            LOG.error("Failed to get console log! %s" % err)
            return False, err

    def modify_instance_type(self, new_type):
        try:
            self.__ec2_instance.modify_attribute(
                InstanceType={'Value': new_type})
            self.instance_type = new_type
            return True
        except Exception as err:
            LOG.error("Failed to change instance type to %s, ret:%s" %
                      (new_type, err))
            return False


class EC2Snapshot(Base):
    def show(self):
        pass

    def exists(self):
        pass

    def __init__(self, params, volume_id):
        config = Config(retries=dict(max_attempts=10, ))

        super(EC2Snapshot, self).__init__(params)
        self.__resource = boto3.resource('ec2', config=config)
        self.__snapshot = None
        self.__volume_id = volume_id
        self.snap_id = None
        self.state = None
        self.tagname = params.get('ec2_tagname')

    def create(self, wait=True):
        '''
        Some version of ec2.resource create_snapshot method may not have
        'TagSpecifications' support. So add tag after created it in another
        step.
        '''
        try:
            self.__snapshot = self.__resource.create_snapshot(
                VolumeId=self.__volume_id, Description=self.tagname)
            '''
                TagSpecifications=[
                    {
                        'ResourceType': 'volume',
                        'Tags': [
                            {
                                'Key': 'Name',
                                'Value': self.tagname
                            },
                        ]
                    },
                ],
            )
            '''
            self.__snapshot.create_tags(Tags=[
                {
                    'Key': 'Name',
                    'Value': self.tagname
                },
            ])
            if wait:
                self.__snapshot.wait_until_completed()
            self.__snapshot.reload()
            self.state = self.__snapshot.state
            self.snap_id = self.__snapshot.id
            LOG.info("Snapshot created: %s " % self.snap_id)
            return True
        except Exception as err:
            LOG.error(err)
            return False

    def get_status(self):
        self.__snapshot.reload()
        self.state = self.__snapshot.state
        LOG.info("Snapshot status: %s" % self.state)
        return self.state

    def delete(self, wait=True):
        try:
            self.__snapshot.delete()
            return True
        except Exception as err:
            LOG.error("Delete snapshot failed %s" % err)
            return False


class EC2Volume(Base):
    '''
    Volume classs
    '''
    __volume = None

    def __init__(self, params):
        config = Config(retries=dict(max_attempts=10, ))
        super(EC2Volume, self).__init__(params)
        self._resource = boto3.resource('ec2', config=config)
        self.disksize = 100
        self.zone = params.get('availability_zone', '*/Cloud/*')
        self.tagname = params.get('ec2_tagname')
        self.outpostarn = params.get('outpostarn')
        self.disktype = 'standard'
        self.id = None
        self.iops = 3000

    def show(self):
        """
        Show instance properties
        Must show after VM properties are changed
        """
        pass

    @property
    def res_id(self):
        self.__volume.reload()
        return self.__volume.id

    @property
    def res_type(self):
        return self.__volume.volume_type

    @property
    def res_name(self):
        return 'volume'

    def reuse_init(self, volume_id):
        '''
        To reuse an exist volume than create a new one
        :params volume_id: id of existing volume
        '''
        if volume_id is None:
            return False
        try:
            self.__volume = self._resource.Volume(volume_id)
            if self.is_attached():
                return False
            LOG.info("Existing %s state is %s" %
                     (self.__volume.id, self.__volume.state))
            return True
        except ClientError as err:
            LOG.error(err)
            return False

    def is_attached(self):
        self.__volume.reload()
        if self.__volume.state == 'in-use':
            LOG.info("%s disk is in use.", self.__volume.id)
            return True
        return False

    def create(self, wait=True, disksize=100, disktype='standard', iops=3000):
        """
        Create volume
        :param wait: Wait for instance created
        :param disksize: disk size required, byt default it is 100GiBs
        :param disktype: options 'standard'|'io1'|'gp2'|'sc1'|'st1'
        :param iops: must for io1 type volume, range 100~20000
        :return: True|False
        """
        try:
            self.disksize = disksize
            self.disktype = disktype
            # sc1 type disk size minimal 500 GiB
            if self.disktype == 'sc1' and self.disksize < 500:
                self.disksize = 500
                LOG.info("sc1 type disk size minimal 500G, so will create \
500G disk!")
            self.iops = iops
            if self.outpostarn is None:
                if self.disktype == 'io1':
                    self.__volume = self.__snapshot = self._resource.create_volume(
                        AvailabilityZone=self.zone,
                        Size=self.disksize,
                        VolumeType=self.disktype,
                        Iops=self.iops,
                        TagSpecifications=[
                            {
                                'ResourceType': 'volume',
                                'Tags': [
                                    {
                                        'Key': 'Name',
                                        'Value': self.tagname
                                    },
                                ]
                            },
                        ])
                else:
                    self.__volume = self.__snapshot = self._resource.create_volume(
                        AvailabilityZone=self.zone,
                        Size=self.disksize,
                        VolumeType=self.disktype,
                        TagSpecifications=[
                            {
                                'ResourceType': 'volume',
                                'Tags': [
                                    {
                                        'Key': 'Name',
                                        'Value': self.tagname
                                    },
                                ]
                            },
                        ])
            else:
                if self.disktype == 'io1':
                    self.__volume = self.__snapshot = self._resource.create_volume(
                        AvailabilityZone=self.zone,
                        Size=self.disksize,
                        VolumeType=self.disktype,
                        Iops=self.iops,
                        OutpostArn=self.outpostarn,
                        TagSpecifications=[
                            {
                                'ResourceType': 'volume',
                                'Tags': [
                                    {
                                        'Key': 'Name',
                                        'Value': self.tagname
                                    },
                                ]
                            },
                        ])
                else:
                    self.__volume = self.__snapshot = self._resource.create_volume(
                        AvailabilityZone=self.zone,
                        Size=self.disksize,
                        VolumeType=self.disktype,
                        OutpostArn=self.outpostarn,
                        TagSpecifications=[
                            {
                                'ResourceType': 'volume',
                                'Tags': [
                                    {
                                        'Key': 'Name',
                                        'Value': self.tagname
                                    },
                                ]
                            },
                        ])
            self.id = self.__volume.id
            LOG.info("Volume created %s" % self.id)
            return True

        except Exception as err:
            LOG.error(err)
            return False

    def delete(self, wait=True):
        """
        Delete volume
        :param wait: Wait for volume deleted
        :return: True|False  and raise Exception if volume delete failed
        """
        if self.__volume is not None:
            LOG.info("Delete %s" % self.res_id)
            try:
                self.__volume.delete()
                return True
            except Exception as err:
                LOG.error(err)
                return False
        else:
            LOG.info("No specify volume delete.")

    def exists(self):
        """
        Judge if volume exists
        :return: True if exists.
        Example:
        return True if self._get_status() != -1 else False
        """
        try:
            self.__volume.reload()
            if self.__volume.state in "deleting | deleted":
                LOG.info("Volume is deleted %s" % self.id)
                return False
            else:
                LOG.info("Volume exists %s" % self.id)
                return True
        except Exception as err:
            LOG.info("Volume does not exists %s" % self.id)
            return False

    def attach_to_instance(self, instance_id, device_name, wait=True):
        """
        Attach disk to instance as $device_name
        :param instance_id: id of instance
        :param device_name: like sdX or xvdX
        :return: True if success, False as failed
        """
        try:
            LOG.info("Try to attach %s to %s" %
                     (self.__volume.id, instance_id))
            self.__volume.attach_to_instance(
                Device=device_name,
                InstanceId=instance_id,
            )

            if wait:
                start_time = time.time()
                while True:
                    self.__volume.reload()
                    if self.__volume.state == 'in-use':
                        LOG.info('Volume attached!')
                        return True
                    else:
                        end_time = time.time()
                        if int(end_time) - int(start_time) > 80:
                            LOG.error(
                                "Failed to attach to instance after 80s! %s" %
                                self.__volume.state)
                            return False
                    time.sleep(10)

            return True
        except Exception as err:
            LOG.error("Volume cannot attach to %s error %s" %
                      (instance_id, err))
            return False

    def detach_from_instance(self, wait=True, force=False):
        """Detach disk from instance as $device_name

        Arguments:
            instance_id {string} -- instance id
            device_name {string} -- target device name from instance, like
                                    'sdX','xvdx'

        Keyword Arguments:
            wait {bool} -- wait or not wait detach operation complete
                           (default: {True})
            force {bool} -- force or not force detach from instance
                            (default: {False})

        Returns:
            bool -- True if success, False as failed
        """
        try:
            instance_id = self.__volume.attachments[0]['InstanceId']
            device_name = self.__volume.attachments[0]['Device']
        except Exception as err:
            LOG.error("Cannot get attached instance id %s", self.__volume.id)
            LOG.error("error %s", err)
            LOG.info(self.__volume)
        try:
            self.__volume.load()
            instance_id = self.__volume.attachments[0]['InstanceId']
            device_name = self.__volume.attachments[0]['Device']
        except Exception as err:
            LOG.error("Cannot get attached instance id %s", self.__volume.id)
            LOG.error("error %s", err)
            LOG.info(self.__volume)
            return False
        try:
            instance_id = self.__volume.attachments[0]['InstanceId']
            device_name = self.__volume.attachments[0]['Device']
            LOG.info("Try to dettach %s from %s" %
                     (self.__volume.id, instance_id))

            self.__volume.detach_from_instance(
                Device=device_name,
                Force=force,
                InstanceId=instance_id,
            )
            if wait:
                start_time = time.time()
                while True:
                    self.__volume.reload()
                    if self.__volume.state == 'available':
                        LOG.info('Volume dettached!')
                        return True
                    else:
                        end_time = time.time()
                        if int(end_time) - int(start_time) > 120:
                            LOG.error(
                                "Failed to dettach to instance after 120s! %s"
                                % self.__volume.state)
                            return False
                    time.sleep(10)
        except Exception as err:
            LOG.error("Volume cannot detach from %s error %s" %
                      (instance_id, err))
            return False


class NetworkInterface(Base):
    '''
    NetworkInterface classs
    '''
    __network_interface = None
    __ec2 = boto3.resource('ec2')

    def __init__(self, params):
        super(NetworkInterface, self).__init__(params)
        self._resource = boto3.resource('ec2')
        if params.get('ipv6'):
            self.subnet_id = params.get('subnet_id_ipv6')
            LOG.info('Instance support ipv6, use subnet %s', self.subnet_id)
        else:
            self.subnet_id = params.get('subnet_id_ipv4')
            LOG.info('Instance only support ipv4, use subnet %s',
                     self.subnet_id)
        self.subnet = self.__ec2.Subnet(self.subnet_id)

        self.zone = params.get('availability_zone', '*/Cloud/*')
        self.tagname = params.get('ec2_tagname')
        self.id = None
        self.security_group_ids = params.get('security_group_ids')

    def show(self):
        """
        Show instance properties
        Must show after VM properties are changed
        """
        pass

    @property
    def res_id(self):
        return self.__network_interface.id

    @property
    def res_type(self):
        return 'interface'

    @property
    def res_name(self):
        return 'network_interface'

    def reuse_init(self, network_interface_id):
        '''
        To reuse an exist network interface than create a new one
        :params network-intserface_id: id of existing network_interface
        '''
        if network_interface_id is None:
            return False
        try:
            self.__network_interface = self.__ec2.NetworkInterface(
                network_interface_id)
            if self.is_attached():
                return False
            LOG.info(
                "Existing %s state is %s" %
                (self.__network_interface.id, self.__network_interface.status))
            return True
        except ClientError as err:
            LOG.error(err)
            return False

    def is_attached(self):
        self.__network_interface.reload()
        if self.__network_interface.status == 'in-use':
            LOG.info("%s network interface is in use.",
                     self.__network_interface.id)
            return True
        return False

    def add_tag(self):
        try:
            self.__network_interface.reload()
            self.__network_interface.create_tags(Tags=[
                {
                    'Key': 'Name',
                    'Value': self.tagname
                },
            ])
        except Exception as err:
            LOG.info("Failed to add tag to %s", self.__network_interface.id)
            LOG.error(err)

    def exists(self):
        pass

    def create(self):
        '''Create a new network interface
        '''
        try:
            self.__network_interface = self.subnet.create_network_interface(
                Description=self.tagname, Groups=[
                    self.security_group_ids,
                ])
            LOG.info("%s network interface created!" %
                     self.__network_interface.id)
            self.add_tag()
            return True
        except Exception as err:
            LOG.info("Failed to create interface")
            LOG.error(err)
            return False

    def delete(self, wait=True):
        '''
        Delete network interface
        :param wait: Wait for interface deleted
        :return: True|False  and raise Exception if interface delete failed
        '''

        if self.__network_interface is not None:
            LOG.info("Delete %s" % self.res_id)
            try:
                self.__network_interface.delete()
                return True
            except Exception as err:
                LOG.error(err)
                return False
        else:
            LOG.info("No specify network interface delete.")

    def attach_to_instance(self, instance_id, device_index, wait=True):
        """
        Attach nic to instance as $device_index
        :param instance_id: id of instance
        :param device_index: [0..9]
        :return: True if success, False as failed
        """
        try:
            LOG.info("Try to attach %s to %s" %
                     (self.__network_interface.id, instance_id))
            self.__network_interface.attach(
                DeviceIndex=device_index,
                InstanceId=instance_id,
            )

            if wait:
                start_time = time.time()
                while True:
                    self.__network_interface.reload()
                    if self.__network_interface.status == 'in-use':
                        LOG.info('NIC attached!')
                        return True
                    else:
                        end_time = time.time()
                        if int(end_time) - int(start_time) > 80:
                            LOG.error(
                                "Failed to attach to instance after 80s! %s" %
                                self.__network_interface.status)
                            return False
                    time.sleep(10)

            return True
        except Exception as err:
            LOG.error("NIC cannot attach to %s error %s" % (instance_id, err))
            return False

    def detach_from_instance(self, instance_id, wait=True, force=False):
        """Detach nic from instance as $device_name

        Arguments:
            instance_id {string} -- instance id
            device_name {string} -- target device name from instance,
                                    like 'sdX','xvdx'

        Keyword Arguments:
            wait {bool} -- wait or not wait detach operation complete
                           (default: {True})
            force {bool} -- force or not force detach from instance
                            (default: {False})

        Returns:
            bool -- True if success, False as failed
        """
        try:
            LOG.info("Try to dettach %s from %s" %
                     (self.__network_interface.id, instance_id))
            self.__network_interface.detach(Force=force)
            if wait:
                start_time = time.time()
                while True:
                    self.__network_interface.reload()
                    if self.__network_interface.status == 'available':
                        LOG.info('NIC dettached!')
                        return True
                    else:
                        end_time = time.time()
                        if int(end_time) - int(start_time) > 80:
                            LOG.error(
                                "Failed to dettach to instance after 80s! %s" %
                                self.__network_interface.status)
                            return False
                    time.sleep(10)
        except Exception as err:
            LOG.error("NIC cannot detach from %s error %s" %
                      (instance_id, err))
            return False


if __name__ == "__main__":
    pass
