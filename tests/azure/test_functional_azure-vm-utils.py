import os
import re
import time
import yaml
from avocado import Test
from avocado import main
from avocado_cloud.app import Setup
from avocado_cloud.app.azure import AzureAccount
from avocado_cloud.app.azure import AzureNIC
from avocado_cloud.app.azure import AzurePublicIP
from avocado_cloud.app.azure import AzureNicIpConfig
from avocado_cloud.app.azure import AzureImage
from distutils.version import LooseVersion
from avocado_cloud.utils import utils_azure


import requests
from avocado_cloud.utils.utils_azure import command


BASEPATH = os.path.abspath(__file__ + "/../../../")


class D(dict):
    # Don't raise exception if cannot get key value
    def __missing__(self, key):
        self[key] = D()
        return self[key]


class Azure_vm_utilsTest(Test):
    def setUp(self):
        account = AzureAccount(self.params)
        account.login()
        self.project = self.params.get("rhel_ver", "*/VM/*")
        self.case_short_name = re.findall(r"Test.(.*)", self.name.name)[0]
#        if self.case_short_name == "test_cloudinit_verify_customized_file_in_authorizedkeysfile":
#            self.cancel("BZ#1862967 has not been fixed yet. Skip.")
        self.pwd = os.path.abspath(os.path.dirname(__file__))
        if LooseVersion(self.project) < LooseVersion('9.7.0'):
              self.cancel(
                  "Skip case because RHEL-{} doesn't support this feature".format(self.project)
              )
        if LooseVersion(self.project) < LooseVersion('10.1'):
              self.cancel(
                  "Skip case because RHEL-{} doesn't support this feature".format(self.project)
              )
        publicip = AzurePublicIP(self.params, name=self.vm.vm_name )
        return
     
    @property
    def _postfix(self):
        from datetime import datetime
        return datetime.strftime(datetime.now(), "%Y%m%d%H%M%S")

    def test_selftest_without_imds_symlink_validation(self):
        """
        :avocado: tags=tier1,azure-vm-utils
        1. Upload the selftest.py
        2. Run the selftest.py
        3. Check the result
        """
        try:
            command("scp -i /root/.ssh/id_rsa /root/azure-vm-utils/selftest/selftest.py  azureuser@%s:/home/azureuser") \
                    % (self.vm.public_ip))
            command("ssh -i ./id_rsa azureuser@%s -- sudo /home/azureuser/selftest.py --skip-imds-validation --skip-symlink-validation > result.txt 2>&1") \
                    % (self.vm.public_ip))
            ret = command("tail -n 1 /root/azure-vm-utils/result.txt | awk '{print $NF}'")
        except:
            return False
        if len(ret.stdout):
            self.log.info("ret.stdout")
            if ret.stdout = "success!"
                return True
        return False
      
