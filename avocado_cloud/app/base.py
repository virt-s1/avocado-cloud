"""
avocado_cloud base class
"""

from abc import ABCMeta, abstractmethod

DEFAULT_TIMEOUT = 1200
LOGIN_TIMEOUT = 30
LOGIN_WAIT_TIMEOUT = 600
COPY_FILES_TIMEOUT = 1200
CREATE_TIMEOUT = 1200
START_TIMEOUT = 1200
RESTART_TIMEOUT = 1200
DELETE_TIMEOUT = 1200
WAIT_FOR_START_RETRY_TIMES = 30
WAIT_FOR_RETRY_TIMES = 10
RETRY_INTERVAL = 10
VM_START_RETRY_INTERVAL = 30


class Base(object):
    """
    This is a abstract class for the following classes
    """
    __metaclass__ = ABCMeta

    def __init__(self, params):
        self.params = params

    @abstractmethod
    def show(self):
        """
        Show instance properties
        Must show after VM properties are changed
        """

    @abstractmethod
    def create(self, wait=False):
        """
        Create instance
        :param wait: Wait for instance created
        :return: raise Exception if instance create failed
        """

    @abstractmethod
    def delete(self, wait=False):
        """
        Delete instance
        :param wait: Wait for instance deleted
        :return: raise Exception if instance delete failed
        """

    @abstractmethod
    def exists(self):
        """
        Judge if istance exists
        :return: True if exists.
        Example:
        return True if self._get_status() != -1 else False
        """


class VM(Base):
    """
    This is VM abstract class for different distro classes
    """
    def __init__(self, params):
        super(VM, self).__init__(params)
        self.params = params

    @property
    @abstractmethod
    def floating_ip(self):
        """
        Get floating ip
        :return: floating ip or FQDN for AWS
        """

    @abstractmethod
    def show(self):
        """
        Show VM properties and update self.params
        Must show after VM properties are changed
        """

    @abstractmethod
    def create(self, wait=False):
        """
        Create VM
        :param wait: Wait for vm created
        :return: raise Exception if VM create failed
        """

    @abstractmethod
    def delete(self, wait=False):
        """
        Delete VM
        :param wait: Wait for vm deleted
        :return: raise Exception if VM delete failed
        """

    @abstractmethod
    def start(self, wait=False):
        """
        Start VM
        :param wait: Wait for vm started
        :return: raise Exception if VM start failed
        """

    @abstractmethod
    def stop(self, wait=False):
        """
        Stop VM
        :param wait: Wait for vm stopped
        :return: raise Exception if VM stop failed
        """

    @abstractmethod
    def reboot(self, wait=False):
        """
        Reboot VM
        :param wait: Wait for vm rebooted
        :return: raise Exception if VM reboot failed
        """

    @abstractmethod
    def exists(self):
        """
        Judge if VM exists
        :return: True if exists.
        Example:
        return True if self._get_status() != -1 else False
        """

    @abstractmethod
    def is_started(self):
        """
        Judge if VM is started
        :return: True if started.
        Example:
        return True if self._get_status() == 0 else False
        """

    @abstractmethod
    def is_stopped(self):
        """
        Judge if VM is stopped
        :return: True if stopped.
        Example:
        return True if self._get_status() == 2 else False
        """
