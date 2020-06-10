'''
This module is used for debug code without install avocado_cloud to it's
target place
'''
import sys
import os


def get_avocado_cloud_path(separator="avocado-cloud"):
    filename = os.path.realpath(__file__)
    targetpath = filename.split(separator)[0] + separator
    return targetpath


sys.path.insert(1, get_avocado_cloud_path())
