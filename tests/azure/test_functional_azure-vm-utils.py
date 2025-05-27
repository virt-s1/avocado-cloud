import os
import re
import time
import yaml
import json
from avocado import Test
from avocado import main
from avocado_cloud.app import Setup
# from avocado_cloud.app.azure import AzureAccount
# from avocado_cloud.app.azure import AzureNIC
from avocado_cloud.app.azure import AzurePublicIP
from avocado_cloud.app.azure import AzureNicIpConfig
# from avocado_cloud.app.azure import AzureImage
from distutils.version import LooseVersion
from avocado_cloud.utils import utils_azure

# import requests
from avocado_cloud.utils.utils_azure import command

BASEPATH = os.path.abspath(__file__ + "/../../../")

class Azure_vm_utilsTest(Test):

    def _postfix(self):
        from datetime import datetime
        return datetime.strftime(datetime.now(), "%Y%m%d%H%M%S")

    def setUp(self):
        #self.casestatus = False
        self.cloud = Setup(self.params, self.name)
        self.vm = self.cloud.vm  # Access the VM created during setup
        authentication = "publickey"
        self.session = self.cloud.init_vm(authentication=authentication)
        if self.vm.exists():
            self.vm.delete(wait=True)
        file_path = '/root/azure-vm-utils/result.txt'
        if os.path.exists(file_path):
            os.remove(file_path)

        key = "/root/.ssh/id_rsa.pub"
        self.vm.ssh_key_value = "{}".format(key)
        self.vm.authentication_type = "ssh"
        #self.vm.vm_name += "-utils"
        # self.vm.os_disk_name += "-new"

        #osdisk = self.vm.properties["storageProfile"]["osDisk"]["vhd"]["uri"]
        #self.vm.delete()
        #self.vm.image = osdisk
        
        self.publicip_name = self.vm.vm_name + "PublicIP"
        self.vm.os_disk_name += "-utils"
        # self.vm.subnet += "-utils"

        self.vm.create(wait=True)
        self.session.connect(authentication="publickey")
        self.assertEqual(self.vm.vm_username,
                         self.session.cmd_output("whoami"),
                         "Fail to login with publickey")
        self.assertIn(
            "%s ALL=(ALL) NOPASSWD:ALL" % self.vm.vm_username,
            self.session.cmd_output(
                "sudo cat /etc/sudoers.d/90-cloud-init-users"),
            "No sudo privilege")
        
    @property
    def _postfix(self):
        from datetime import datetime
        return datetime.strftime(datetime.now(), "%Y%m%d%H%M%S")
        
    def test_selftest_without_imds_symlink_validation(self):
        """
        :avocado: tags=tier1,azure_vm_utils
        """
        try:   
            #publicip_name = self.vm.vm_name + "PublicIP"
            publicip_name = self.publicip_name
            cmd = ' az network public-ip show   --name {} --resource-group "{}"  --query "ipAddress"   --output tsv'.format(publicip_name, self.vm.resource_group)
            ret = command(cmd)
            public_ip = ret.stdout.strip()
            self.log.info("public_ip: %s", public_ip)

            # Upload the selftest.py to the remote VM
            upload_command = 'scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i /root/.ssh/id_rsa /root/azure-vm-utils/selftest/selftest.py azureuser@{}:/home/azureuser'.format(public_ip)
            command(upload_command)

            check_command = 'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i /root/.ssh/id_rsa azureuser@{} -- ls /home/azureuser/selftest.py;ls /home/azureuser;rpm -qa azure-vm-utils* '.format(public_ip)
            check_res = command(check_command)
            self.log.info("check_result: %s", check_res)
            
            # Run the selftest.py script on the VM
            run_command = 'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i /root/.ssh/id_rsa azureuser@{} -- sudo /home/azureuser/selftest.py --skip-imds-validation --skip-symlink-validation > /root/azure-vm-utils/result.txt 2>&1'.format(public_ip)
            command(run_command)
            
            # Get the last line of the result
            result_command = "tail -n 1 /root/azure-vm-utils/result.txt | awk '{print $NF}'"
            ret = command(result_command)
            
            
            # Check if the result was successful
            if ret.stdout.strip() == "success!":
                self.log.info("Self-test completed successfully.")
                self.vm.delete(wait=False)
                #self.casestatus = True
                return True
            else:
                self.log.error("Self-test failed: {}".format(ret.stdout))
                self.vm.delete(wait=False)
                return False
        
        except Exception as e:
            self.log.error("An error occurred: {}".format(str(e)))
            return False

    def tearDown(self):
        self.vm.delete(wait=False)
        # del_cmd = ' az disk delete --name {} --resource-group "{}" --yes '.format(self.vm.os_disk_name, self.vm.resource_group)
        # command(del_cmd)

# if __name__ == "__main__":
#     main()
