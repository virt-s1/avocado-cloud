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
    nutanix_json = kwargs.get('azure_json', False)
    debug = kwargs.get('debug', True)
    stdout = kwargs.get('stdout', True)
    ignore_status = kwargs.get('ignore_status', False)
    error_debug = kwargs.get('error_debug', True)
    #    timeout = kwargs.get('timeout', None)
    if nutanix_json:
        cmd += " --json"
    if debug:
        logging.info("command-----------: %s", cmd)
    if timeout:
        try:
            timeout = int(timeout)
        except ValueError:
            logging.error("Ignore the invalid timeout value: %s", timeout)
            timeout = None

    try:
        ret = process.run(cmd,
                          timeout=timeout,
                          verbose=debug,
                          ignore_status=ignore_status,
                          shell=True)
    except Exception as e:
        logging.info(str(e))
        raise
    if debug:
        logging.info("status: %s", ret.exit_status)
        logging.info("stderr: %s", ret.stderr.strip())
    if stdout:
        logging.info("stdout: %s", ret.stdout.strip())
    if nutanix_json and not ret.exit_status:
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

def file_exists(filename, session):
    return session.cmd_status_output("ls " + filename)[0] == 0
