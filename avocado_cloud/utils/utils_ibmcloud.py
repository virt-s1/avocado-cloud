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


class IbmcloudCmdError(Exception):
    def __init__(self, msg):
        super(IbmcloudCmdError, self).__init__(msg)
        self.msg = msg

    def __str__(self):
        return "\n{}".format(self.msg)

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
    #try:
    ret = process.run(cmd,
                      timeout=timeout,
                      verbose=debug,
                      ignore_status=ignore_status,
                      shell=True)
    # except Exception as e:
    #     logging.info(str(e))
    #     raise   
    # Question here, when exception happens, why no string in e?            
    '''
    if ret.exit_status != 0:
        raise IbmCloudCmdError(str(ret))
    '''
    return ret