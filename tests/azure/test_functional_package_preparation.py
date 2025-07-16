import os
import requests
from avocado import Test
from avocado import main
from avocado_cloud.app import Setup
from avocado_cloud.app.azure import AzureAccount
from avocado_cloud.utils.utils_azure import command


class PackagePreparation(Test):
    def setUp(self):
        self.casestatus = False
        account = AzureAccount(self.params)
        account.login()
        self.pwd = os.path.abspath(os.path.dirname(__file__))
        cloud = Setup(self.params, self.name)
        self.vm = cloud.vm
        self.session = cloud.init_vm(pre_delete=True)
        self.packages = self.params.get("packages", "*/Other/*")
        self.package_list = self.packages.split(',')
        self.log.debug("Package list: {}".format(self.package_list))
        self.with_wala = self.params.get("with_wala", "*/others/*", False)
        self.project = self.params.get("rhel_ver", "*/VM/*")

    def test_package_00_preparation(self):
        """
        Prepare environment for running cases
        """
        # Login with root
        self.session.cmd_output("sudo /usr/bin/cp -a /home/{0}/.ssh /root/;\
sudo chown -R root:root /root/.ssh".format(self.vm.vm_username))
        self.session.close()
        origin_username = self.vm.vm_username
        self.vm.vm_username = "root"
        self.session.connect(authentication="publickey")
        # Copy and install package into guest
        self.session.cmd_output("rm -rf /tmp/*")
        self.session.copy_files_to(local_path="%s/../../*.rpm" % (self.pwd),
                                   remote_path="/tmp")
        command("systemctl start squid")
        self.assertEqual(
            command("netstat -tln|grep 3128").exit_status, 0,
            "Fail to enable squid in host")
        self.session.cmd_output("rm -f /etc/yum.repos.d/*")
        self.session.cmd_output("yum clean all", timeout=300)
        import re
        x_match = re.findall("el([0-9]+).*", self.package_list[0])
        if x_match:
            x_version = int(x_match[0])
        else:
            if self.project:
                x_version = self.project.split('.')[0]
            else:
                # Currently the latest major release is 8. Need to be updated for
                # future major releases
                x_version = 9
        label = "BaseOS" if x_version > 7 else "Server"
        # Validate these repos one by one and select the available one
        base_url_list = [ "http://download-node-02.eng.bos.redhat.com/rhel-{}/rel-eng/RHEL-{}/latest-RHEL-{}/compose/{}/x86_64/os/".format(x_version, x_version, self.project, {}),
                          "http://download-node-02.eng.bos.redhat.com/rhel-{}/rel-eng/updates/RHEL-{}/latest-RHEL-{}/compose/{}/x86_64/os/".format(x_version, x_version, self.project, {}),
                          "http://download-node-02.eng.bos.redhat.com/rhel-{}/nightly/RHEL-{}/latest-RHEL-{}/compose/{}/x86_64/os/".format(x_version, x_version, self.project, {}),
                        ]
        for base_url in base_url_list:
            if requests.get(base_url.format(label)).ok:
                break
        BASEREPO = """
[rhel-base]
name=rhel-base
baseurl={}
enabled=1
gpgcheck=0
proxy=http://127.0.0.1:8080/

EOF
""".format(base_url.format(label))
        APPSTREAMREPO = """
[rhel-appstream]
name=rhel-appstream
baseurl={}
enabled=1
gpgcheck=0
proxy=http://127.0.0.1:8080/

EOF
""".format(base_url.format("AppStream"))
        pulpcore_url = "http://download.eng.bos.redhat.com/brewroot/repos/pulpcore-3.4-rhel-{}-build/latest/x86_64/".format(x_version)
        PULPCOREREPO = """
[pulpcore-3.4]
name=pulpcore-3.4
baseurl={}
enabled=1
gpgcheck=0
proxy=http://127.0.0.1:8080/

EOF
""".format(pulpcore_url)
        self.session.cmd_output("cat << EOF > /etc/yum.repos.d/rhel.repo%s" %
                                (BASEREPO))
        # WALA doesn't use pulpcore repo to avoid the RHEL-8.0 systemd update issue
        if "WALinuxAgent" not in self.packages and requests.get(pulpcore_url).ok:
            self.session.cmd_output("cat << EOF >> /etc/yum.repos.d/rhel.repo%s" %
                                    (PULPCOREREPO))
        if x_version > 7:
            self.session.cmd_output(
                "cat << EOF >> /etc/yum.repos.d/rhel.repo%s" % (APPSTREAMREPO))
        # If not kernel, remove old package
        pkgname_list = [pn.rsplit('-', 2)[0] for pn in self.package_list]
        self.log.debug("Package name list: {}".format(pkgname_list))
        if "kernel" not in pkgname_list:
            [
                self.session.cmd_output("rpm -e {}".format(pkgname), timeout=300)
                for pkgname in pkgname_list
            ]
        # Install package
        _yum_install = "ssh -o UserKnownHostsFile=/dev/null -o \
StrictHostKeyChecking=no -R 8080:127.0.0.1:3128 root@%s \
\"yum -y --skip-broken install {}\"" % self.vm.public_ip
        self.session.cmd_output("yum clean all", timeout=300)
        if "kernel" in self.packages:
            # Delete debuginfo package in case no enough space in /boot
            self.session.cmd_output("yum erase -y kernel-debug* $(rpm -qa|grep kernel|grep -v $(uname -r)|tr \"'\\n'\" \"' '\")||true", timeout=180)
            self.session.cmd_output("df -h")
        if self.session.cmd_status_output("rpm -ivh --force /tmp/*.rpm",
                                          timeout=300)[0] != 0:
#             command("ssh -o UserKnownHostsFile=/dev/null -o \
# StrictHostKeyChecking=no -R 8080:127.0.0.1:3128 root@%s \
# \"yum -y install /tmp/*.rpm\"" % self.vm.public_ip,
#                     timeout=300)
            command(_yum_install.format("/tmp/*.rpm"), timeout=300)
        # Install cloud-init cloud-utils-growpart gdisk(RHEL-8,9) for
        # cloud-init related packages
        if x_version > 7:
            cloudinit_pkgs = [
                'cloud-init', 'python3-jsonpatch', 'cloud-utils-growpart',
                'python3-jsonschema', 'python3-httpretty', 'python3-pyserial',
                'python3-prettytable', 'python3-configobj', 'python3-distro',
                'python3-jsonschema-specifications'
            ]
        else:
            cloudinit_pkgs = [
                'cloud-init', 'python-jsonpatch', 'cloud-utils-growpart',
                'python-jsonschema', 'python-httpretty', 'pyserial',
                'python-prettytable', 
                'python3-jsonpatch', 'python3-jsonschema', 'python3-httpretty',
                'python3-prettytable'
            ]
        for cloudinit_pkg in cloudinit_pkgs:
            if cloudinit_pkg in self.packages:
                # RHEL-10 removes gdisk
                dep_list = ["cloud-init", "cloud-utils-growpart"]
                if x_version < 10:
                    dep_list.append('gdisk')
                for pkg in dep_list:
                    if self.session.cmd_status_output(
                            "rpm -q %s" % pkg)[0] != 0:
#                         command("ssh -o UserKnownHostsFile=/dev/null -o \
# StrictHostKeyChecking=no -R 8080:127.0.0.1:3128 root@%s \"yum -y install %s\""
#                                 % (self.vm.public_ip, pkg))
                        command(_yum_install.format(pkg))
                break
        # If WALinuxAgent, remove cloud-init
        if self.packages.startswith("WALinuxAgent"):
            self.session.cmd_output("yum erase -y cloud-init", timeout=180)
        # Install other necessary packages
        _other_pkgs = "tar net-tools bind-utils dracut-fips dracut-fips-aesni \
tcpdump"
        command(_yum_install.format(_other_pkgs))
        # Delete rhel.repo
        self.session.cmd_output("rm -f /etc/yum.repos.d/rhel.repo")
        # Verify packages are installed
        for pkg in self.package_list:
            self.assertEqual(
                self.session.cmd_status_output("rpm -q {}".format(
                    pkg[:-4]))[0], 0,
                "Package {} is not installed.".format(pkg))
        # Install RHUI package in case LISAv2 need to yum install packages.
        self.session.cmd_output(
            "rpm -e rhui-azure-rhel{0}; yum -y --config='https://rhelimage.blob.core.windows.net/repositories/rhui-microsoft-azure-rhel{0}.config' install 'rhui-azure-rhel{0}'".format(x_version)
        )
        # Enable IPv6 init in ifcfg-eth0 for IPv6 case
        self.session.cmd_output(
            "sed -i 's/^IPV6INIT.*$/IPV6INIT=yes/g' /etc/sysconfig/network-scripts/ifcfg-eth0")
        # Deprovision image
        # If cloud-init related packages:
        if (list(set(pkgname_list).intersection(set(cloudinit_pkgs)))):
            if self.with_wala:
                depro_type = "cloudinit_wala"
            else:
                depro_type = "cloudinit"
        elif "WALinuxAgent" in pkgname_list:
            depro_type = "wala"
        elif "kernel" in pkgname_list:
            depro_type = "kernel"
        elif "azure-vm-utils" in pkgname_list:
            depro_type = "azure-vm-utils"
        else:
            self.fail("Not supported package(s): {}".format(pkgname_list))
        script = "deprovision_package.sh"
        self.session.copy_files_to(local_path="{0}/../../scripts/{1}".format(
            self.pwd, script),
                                   remote_path="/tmp")
        import time
        time.sleep(100)                           
        ret, output = self.session.cmd_status_output(
            "/bin/bash /tmp/{} all {} {}".format(script, depro_type,
                                                 origin_username))
        self.assertEqual(ret, 0, "Deprovision VM failed.\n{0}".format(output))
        self.session.cmd_output("rm -f /root/.bash_history")
        self.session.cmd_output("export HISTSIZE=0")
        self.session.close()
        # Get OS disk name
        osdisk = self.vm.properties["storageProfile"]["osDisk"]["vhd"][
            "uri"].split('/')[-1]
        self.log.debug("OS disk: {}".format(osdisk))
        self.vm.image = osdisk
        with open("%s/../../osdisk" % self.pwd, 'w') as f:
            f.write(osdisk)

    def tearDown(self):
        self.vm.delete(wait=True)


if __name__ == "__main__":
    main()
