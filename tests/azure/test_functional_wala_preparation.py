import os
from avocado import Test
from avocado import main
from avocado_cloud.app import Setup
from avocado_cloud.app.azure import AzureAccount
from avocado_cloud.utils.utils_azure import command


class WALAPreparation(Test):
    def setUp(self):
        self.casestatus = False
        account = AzureAccount(self.params)
        account.login()
        self.pwd = os.path.abspath(os.path.dirname(__file__))
        cloud = Setup(self.params, self.name)
        self.vm = cloud.vm
        pre_delete = False
        pre_stop = False
        self.session = cloud.init_vm(pre_delete=pre_delete, pre_stop=pre_stop)
        self.package = self.params.get("package", "*/Other/*")

    def test_wala_00_preparation(self):
        """
        Prepare environment for running wala cases
        """
        # # Login with root
        self.session.cmd_output("sudo /usr/bin/cp -a /home/{0}/.ssh /root/;"
                                "sudo chown -R root:root /root/.ssh".format(
                                    self.vm.vm_username))
        self.session.close()
        origin_username = self.vm.vm_username
        self.vm.vm_username = "root"
        self.session.connect(authentication="publickey")
        # Copy and install cloud-init package into guest
        self.session.copy_files_to(local_path="%s/../../%s" %
                                   (self.pwd, self.package),
                                   remote_path="/tmp/%s" % self.package)
        if self.session.cmd_status_output("sudo rpm -q WALinuxAgent")[0] == 0:
            self.session.cmd_output("sudo rpm -e WALinuxAgent")
        # If fail to install cloud-init, enable reverse proxy in host and set
        # proxy in guest yum repo
        if self.session.cmd_status_output(
                "rpm -ivh /tmp/%s > /dev/null" % self.package)[0] != 0:
            command("systemctl start squid")
            if command("netstat -tln|grep 3128").exit_status != 0:
                self.fail("Fail to enable squid in host")
            self.session.cmd_output("rm -f /etc/yum.repos.d/*")
            self.session.cmd_output("yum clean all")
            import re
            x_version = re.findall("el(\d+).*", self.package)[0]
            BASEREPO = """
[rhel-base]
name=rhel-base
baseurl=http://download.eng.pek2.redhat.com/rel-eng/latest-RHEL-%s/compose/BaseOS/x86_64/os/
enabled=1
gpgcheck=0
proxy=http://127.0.0.1:8080/

EOF
"""
            APPSTREAMREPO = """
[rhel-appstream]
name=rhel-appstream
baseurl=http://download.eng.pek2.redhat.com/rel-eng/latest-RHEL-%s/compose/AppStream/x86_64/os/
enabled=1
gpgcheck=0
proxy=http://127.0.0.1:8080/
EOF
"""
            self.session.cmd_output(
                "cat << EOF > /etc/yum.repos.d/rhel.repo%s" %
                (BASEREPO % x_version))
            if x_version > 7:
                self.session.cmd_output(
                    "cat << EOF >> /etc/yum.repos.d/rhel.repo%s" %
                    (APPSTREAMREPO % x_version))
            command("ssh -o UserKnownHostsFile=/dev/null -o \
StrictHostKeyChecking=no -R 8080:127.0.0.1:3128 root@%s \"yum -y \
install /tmp/%s\"" % (self.vm.public_ip, self.package)).exit_status
        self.assertEqual(
            self.session.cmd_status_output("rpm -q WALinuxAgent")[0], 0,
            "Fail to install %s package" % self.package)
        # Install cloud-utils-growpart gdisk packages for auto_extend_os_disk
        # case
        self.session.cmd_output("rm -f /etc/yum.repos.d/rhel.repo")
        # Deprovision image
        self.session.copy_files_to(
            local_path="%s/../../scripts/deprovision_wala.sh" % self.pwd,
            remote_path="/tmp/deprovision_wala.sh")
        self.session.cmd_output(
            "/bin/bash /tmp/deprovision_wala.sh deprovision {0}".format(
                origin_username))
        ret, output = self.session.cmd_status_output(
            "/bin/bash /tmp/deprovision_wala.sh verify {0}".format(
                origin_username))
        self.assertEqual(ret, 0, "Deprovision VM failed.\n{0}".format(output))
        self.session.close()
        # Delete VM
        osdisk = self.vm.properties["storageProfile"]["osDisk"]["vhd"][
            "uri"].split('/')[-1]
        self.vm.delete()
        self.vm.image = osdisk
        with open("%s/../../osdisk" % self.pwd, 'w') as f:
            f.write(osdisk)
        self.casestatus = True

    def tearDown(self):
        self.vm.delete()


if __name__ == "__main__":
    main()
