"""
Virtualization test utility functions.

:copyright: 2016 Red Hat Inc.
"""

import time
import socket
import os
import logging
import json

from avocado.utils import process
from avocado_cloud.app import Setup


class AzureCmdError(Exception):
    def __init__(self, msg):
        super(AzureCmdError, self).__init__(msg)
        self.msg = msg

    def __str__(self):
        return "\n{}".format(self.msg)


def add_option(option, value, option_type=None):
    """
    Add option to Azure CLI

    :param option: Azure CLI options
    :param value:
    :param option_type:
    :return: Format string
    """
    fmt = ' %s "%s"'
    if option_type and option_type is bool:
        if value in ['yes', 'on', True]:
            return fmt % (option, "on")
        elif value in ['no', 'off', False]:
            return fmt % (option, "off")
    elif value and isinstance(value, bool):
        return " %s" % option
    elif value and isinstance(value, (str, int, float, unicode)):
        return fmt % (option, value)
    return ""


def acommand(cmd,
             timeout=1200,
             debug=True,
             stdout=True,
             ignore_status=False,
             **kwargs):
    """
    An easy way to run command and log output
    :param cmd: Command line
    :param kwargs: Additional args for running the command
    :return: CmdResult
    :raise: CmdError if ignore_status=False and non-zero exit status
    """
    try:
        timeout = int(timeout)
    except ValueError:
        # logging.error("Ignore the invalid timeout value: %s  and use default
        # timeout value 1200", timeout)
        timeout = 1200
    ret = process.run(cmd,
                      timeout=timeout,
                      verbose=debug,
                      ignore_status=ignore_status,
                      shell=True)
    '''
    if ret.exit_status != 0:
        raise AzureCmdError(str(ret))
    '''
    return ret


# A easy way to run command and log output (only if debug=True)


def command(cmd, timeout=1200, **kwargs):
    """
    Interface to cmd function as 'cmd' symbol is polluted.

    :param cmd: Command line
    :param kwargs: Additional args for running the command
    :return: CmdResult object
    :raise: CmdError if non-zero exit status and ignore_status=False
    """
    azure_json = kwargs.get('azure_json', False)
    debug = kwargs.get('debug', True)
    stdout = kwargs.get('stdout', True)
    ignore_status = kwargs.get('ignore_status', False)
    error_debug = kwargs.get('error_debug', True)
    #    timeout = kwargs.get('timeout', None)
    if azure_json:
        cmd += " --json"
    if debug:
        logging.info("command-----------: %s", cmd)
    if timeout:
        try:
            timeout = int(timeout)
        except ValueError:
            logging.error("Ignore the invalid timeout value: %s", timeout)
            timeout = None


#    else:
#        # Set Default Timeout
#        timeout = 600

    try:
        ret = process.run(cmd,
                          timeout=timeout,
                          verbose=debug,
                          ignore_status=ignore_status,
                          shell=True)
    except Exception as e:
        if "az" in cmd and error_debug is True:
            azure_err = "/root/.azure/azure.err"
            if os.path.isfile(azure_err):
                logging.info(azure_err)
                with open(azure_err, 'r') as f:
                    azure_error_msg = f.read()
                logging.info(azure_error_msg)
                if "TooManyRequests" in azure_error_msg:
                    logging.info("Too many requests. Wait for 300s.")
                    time.sleep(300)
        logging.info(str(e))
        raise
    if debug:
        logging.info("status: %s", ret.exit_status)
        logging.info("stderr: %s", ret.stderr.strip())
    if stdout:
        logging.info("stdout: %s", ret.stdout.strip())
    if azure_json and not ret.exit_status:
        try:
            ret.stdout = json.loads(ret.stdout)
        except ValueError as e:
            logging.warn(e)
    return ret


def postfix():
    """
    Generate a string base on current time
    :return:
    """
    return time.strftime("-%Y%m%d%H%M%S")


def check_dns(dns):
    """
    Check if the domain name can be visited.

    :return:
    -1: Wrong domain name
    0: Running/Stopped/Starting
    1: Stopped(deallocated)
    """
    try:
        ip = socket.getaddrinfo(dns, None)[0][4][0]
    except:
        logging.info("Wrong Domain Name: %s", dns)
        raise
    if ip == '0.0.0.0':
        logging.info("Cloud Service is Stopped(deallocated).")
        return False
    else:
        logging.info("Cloud Service is Running.")
        return True


def format_location(location):
    """
    This function is used to format location as an unified format
    """
    alllocation = 'centralus,eastasia,southeastasia,eastus,eastus2,westus,\
    westus2,northcentralus,southcentralus,westcentralus,northeurope,westeurope,\
    japaneast,japanwest,brazilsouth,australiasoutheast,australiaeast,westindia,\
    southindia,centralindia,canadacentral,canadaeast,uksouth,ukwest,koreacentral,\
    koreasouth'.split(",")
    for index in range(len(alllocation)):
        alllocation[index] = alllocation[index].strip()
    location = location.lower().replace(" ", "")
    if location in alllocation:
        return location


def file_exists(filename, session):
    return session.cmd_status_output("ls " + filename)[0] == 0


def deprovision(instance):
    instance.session.cmd_output(
        "sudo /usr/bin/cp -a ~/.ssh /root/;sudo chown -R root:root \
/root/.ssh")
    instance.session.close()
    instance.vm.vm_username = "root"
    instance.session.connect()
    instance.session.cmd_output("systemctl stop waagent")
    instance.session.cmd_output(
        "/usr/bin/mv /var/lib/waagent /tmp/waagent-bak")
    instance.session.cmd_output("userdel -rf {}".format(instance.username))
    if instance.session.cmd_status_output('id {}'.format(instance.username))[0] == 0:
        instance.log.debug("Fail to delete user! Retry...")
        time.sleep(1)
        instance.session.cmd_output("ps aux|grep {}".format(instance.username))
        instance.session.cmd_output("userdel -rf {}".format(instance.username))
    instance.session.cmd_output("rm -f /var/log/waagent.log")
    instance.session.cmd_output("touch /tmp/deprovisioned")


def recreate_vm(instance, tag, timeout=300, **kwargs):
    osdisk_uri = instance.vm.properties["storageProfile"]["osDisk"]["vhd"][
        "uri"]
    cloud = Setup(instance.params, instance.name)
    cloud.vm.vm_name = instance.vm.vm_name + "-" + tag
    cloud.vm.image = osdisk_uri
    cloud.vm.os_disk_name = instance.vm.vm_name + "_os" + \
        time.strftime("%m%d%H%M%S", time.localtime())
    for key in kwargs:
        if key not in dir(cloud.vm):
            instance.log.debug(
                "No such property in AzureVM class: {}".format(key))
        value = kwargs.get(key)
        if value not in [True, False, None]:
            value = "\"{}\"".format(value)
        exec("cloud.vm.{0} = {1}".format(key, value))
    cloud.vm.show()
    if cloud.vm.exists():
        cloud.vm.delete(wait=True)
    session = None
    wait = kwargs.get("wait", True)
    try:
        cloud.vm.create(wait=wait)
        session = cloud.init_session()
        if kwargs.get("connect", True) is True:
            session.connect(timeout=timeout)
    except Exception:
        raise
    finally:
        return (cloud.vm, session)


class WalaConfig(object):
    def __init__(self, session, path="/etc/waagent.conf"):
        self.session = session
        self.path = path

    def modify_value(self, key, value, sepr="="):
        status, output = self.session.cmd_status_output(
            "grep -n \'^{0}\' {1}".format(key, self.path))
        if len(output) > 0:
            # if waagent.conf not exist
            if status != 0:
                return status, output
            # key and value exist
            else:
                lineno = output.split(":")[0]
                status, output = self.session.cmd_status_output(
                    "sed -i '{0}d' {1}".format(lineno, self.path))
                if status != 0:
                    return status, output
        status, output = self.session.cmd_status_output(
            "echo \'{0}{1}{2}\' >> {3}".format(key, sepr, value, self.path))
        if status != 0:
            return status, output
        return 0, "Successfully update value"

    def verify_value(self, key, value, sepr="="):
        verify_cmd = "grep -R \'^{0}{1}{2}\' {3}".format(
            key, sepr, value, self.path)
        status, output = self.session.cmd_status_output(verify_cmd)
        if status != 0:
            return status, output
        return 0, ""
