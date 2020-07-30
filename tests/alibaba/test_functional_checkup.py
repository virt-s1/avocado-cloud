from avocado import Test
from avocado_cloud.app import Setup
from avocado_cloud.utils import utils_misc
from avocado.utils import process
import re
import os
import time


class GeneralTest(Test):
    def setUp(self):
        self.cloud = Setup(self.params, self.name)
        self.vm = self.cloud.vm
        self.session = self.cloud.init_vm(pre_delete=False, pre_stop=False)
        self.rhel_ver = self.params.get('rhel_ver', '*/VM/*', '')
        self.pwd = os.path.abspath(os.path.dirname(__file__))
        self.dest_dir = "/tmp/"

    def test_validation(self):
        self.log.info("Validation test")
        # Login instnace, get CPU, memory, cpu flags, boot time. Save these
        # data and copy to host
        guest_path = self.session.cmd_output("echo $HOME") + "/workspace"
        guest_logpath = guest_path + "/log"
        host_logpath = os.path.dirname(self.job.logfile) + "/validation_data"
        self.session.cmd_output("mkdir -p {0}".format(guest_logpath))
        if "no lspci" in self.session.cmd_output("which lspci"):
            self.session.copy_files_to(
                local_path="{0}/../../data/openstack/pciutils*".format(
                    self.pwd),
                remote_path=guest_path)
            self.session.cmd_output(
                "sudo rpm -ivh {0}/pciutils*".format(guest_path))
        flavor = self.vm.flavor
        self.session.copy_files_to(
            local_path="{0}/../../scripts/test_validation_*.sh".format(
                self.pwd),
            remote_path=guest_path)
        self.log.info("Flavor: %s" % flavor)
        # Cleanup $HOME/workspace/log
        self.session.cmd_output("rm -rf {0}".format(guest_logpath))
        # Collect cpu/memory/cpu flags
        self.session.cmd_output(
            "bash {0}/test_validation_resource_information.sh "
            "{1}".format(guest_path, flavor),
            timeout=180)
        # If RHEL-7 and future versions, collect bootup time
        if int(self.rhel_ver.split('.')[0]) >= 7:
            # Collect bootup time after created
            self.session.cmd_output("bash {0}/test_validation_boot_time.sh "
                                    "{1} create".format(guest_path, flavor))
            # Reboot VM and then collect bootup time after rebooting
            self.session.send_line("sudo reboot")
            time.sleep(10)
            self.session.connect()
            self.session.cmd_output(
                "bash {0}/test_validation_boot_time.sh,timeout=120 "
                "{1} reboot".format(guest_path, flavor))
        # Copy dmesg.log to workspace
        self.session.cmd_output("cp /var/log/dmesg {0}/dmesg_{1}.log".format(
            guest_logpath, flavor))
        # Copy logs to host
        process.run(cmd="mkdir -p " + host_logpath,
                    timeout=20,
                    verbose=False,
                    ignore_status=False,
                    shell=True)
        self.log.debug("Copying logs to host...")
        self.session.copy_files_from(
            local_path=host_logpath,
            remote_path="{0}/*.log".format(guest_logpath))
        self.log.info("Copy logs to {0} successfully.".format(host_logpath))
        # Cleanup scripts and logs
        self.session.cmd_output("rm -rf " + guest_path)

    def test_check_boot_message(self):
        self.log.info("Check the boot messages with no errors")
        if self.rhel_ver.split('.')[0] == '8':
            data_file = "journalctl.el8.lst"
        elif self.rhel_ver.split('.')[0] == '7':
            data_file = "var.log.message.el7.lst"
        elif self.rhel_ver.split('.')[0] == '6':
            data_file = "var.log.message.el6.lst"
        else:
            self.fail("RHEL version is unknown: %s" % self.rhel_ver)
        self.session.copy_data_to_guest(self.cloud.cloud_provider, data_file)
        if float(self.rhel_ver) >= 8.0:
            cmd = "sudo journalctl -b | grep -iE '(error|fail)' \
| grep -vFf '%s'" % os.path.join(self.dest_dir, data_file)
        else:
            cmd = "sudo cat /var/log/messages | grep -iE '(error|fail)' \
| grep -vFf '%s'" % os.path.join(self.dest_dir, data_file)
        output = self.session.cmd_output(cmd)
        self.assertEqual(
            "", output,
            "There're error logs in /var/log/messages:\n%s" % output)

    # RHBZ#1006883
    def test_check_fstab(self):
        fs_spec = ""
        output = self.session.cmd_output("cat /etc/fstab")
        for line in output.splitlines():
            li = line.strip()
            if not li.startswith("#") and li:
                if li.split()[1] == '/':
                    fs_spec = li.split()[0]
        self.assertTrue(
            re.match(r"UUID=\w{8}-\w{4}-\w{4}-\w{4}-\w{8}", fs_spec),
            "rootfs in /etc/fstab is not present by UUID -> %s" % fs_spec)

    # RHBZ#1673094
    def test_check_partitions(self):
        output = self.session.cmd_output("sudo lsblk")
        count = 0
        for line in output.splitlines():
            if re.search("vda", line):
                count = count + 1
        expected_partitions = 2
        if self.vm.arch == "ppc64le":
            expected_partitions = 3
        if self.vm.arch == "aarch64":
            expected_partitions = 3
        self.assertEqual(expected_partitions, count,
                         "More than one partition exists:\n %s" % output)

    # RHBZ#1032169
    def test_check_bash_prompt(self):
        output = self.session.cmd_output("echo $PS1")
        self.assertEqual(output, r"[\u@\h \W]\$",
                         "Bash prompt is not OK -> %s" % output)

    # RHBZ#970820 cloud-init
    # RHBZ#993027 heat-cfntools
    # ovirt-guest-agent-common
    # cloud-utils-growpart
    def test_check_installed_packages(self):
        packages_el8 = ['cloud-init', 'cloud-utils-growpart']
        packages_el7 = [
            'cloud-init', 'heat-cfntools', 'ovirt-guest-agent-common',
            'cloud-utils-growpart'
        ]
        packages_el6 = [
            'cloud-init', 'heat-cfntools', 'rhevm-guest-agent-common',
            'cloud-utils-growpart'
        ]
        packages = []
        if self.vm.image_name[17] == '8':
            packages = packages_el8
        if self.vm.image_name[17] == '7':
            packages = packages_el7
        if self.vm.image_name[17] == '6':
            packages = packages_el6
        cmd = "rpm -qa --qf '%{NAME}\\n'"
        output = self.session.cmd_output(cmd)
        for package in packages:
            self.assertIn(package, output, "Missing package -> %s" % package)

    # RHBZ#1028889
    def test_check_redhat_release(self):
        output = self.session.cmd_output("cat /etc/redhat-release")
        match = re.search(r"\d\.?\d+", output).group(0)
        self.assertEqual(
            self.rhel_ver, match,
            "Release version mismatch in /etc/redhat-release -> %s" % output)
        if self.rhel_ver.split('.')[0] == '8':
            output = self.session.cmd_output("rpm -q redhat-release")
            match = re.search(r"redhat-release-(\d\.?\d+)", output).group(1)
        if self.rhel_ver.split('.')[0] == '7':
            output = self.session.cmd_output("rpm -q redhat-release-server")
            match = re.search(r"redhat-release-server-(\d\.?\d+)",
                              output).group(1)
        if self.rhel_ver.split('.')[0] == '6':
            output = self.session.cmd_output("rpm -q redhat-release-server")
            match = re.search(r"redhat-release-server-6Server-(\d\.?\d+)",
                              output).group(1)

        self.assertEqual(
            self.rhel_ver, match,
            "Release version mismatch on redhat-release-server -> %s" % output)

    # RHBZ#1045242
    def test_check_size_of_rootfs(self):
        fs_size = 0
        output = self.session.cmd_output("df -h")
        for line in output.splitlines():
            if line.split()[5] == '/':
                fs_size = float(
                    utils_misc.normalize_data_size(line.split()[1],
                                                   order_magnitude='G'))
        vm_size = float(
            utils_misc.normalize_data_size(self.vm.size, order_magnitude='G'))
        self.assertTrue(
            vm_size * 0.9 <= fs_size <= vm_size,
            "Size of rootfs is lower than 90%% of disk size -> %s" % fs_size)

    # RHBZ#1032175
    def test_check_password_hash_for_root(self):
        sp_pwdp = ""
        output = self.session.cmd_output("sudo cat /etc/shadow")
        for line in output.splitlines():
            if line.split(':')[0] == "root":
                sp_pwdp = line.split(':')[1]
        self.assertEqual(
            "!!", sp_pwdp,
            "Encrypted password for root in /etc/shadow is bad -> %s" %
            sp_pwdp)

    def test_check_selinux_status(self):
        self.assertEqual(self.session.cmd_output("getenforce"), "Enforcing",
                         "SELinux is not enforcing")
        output = self.session.cmd_output(
            "cat /etc/selinux/config|grep SELINUX=")
        keyword = ""
        for line in output.splitlines():
            if '#' not in line:
                keyword = line.split('=')[1]
        self.assertEqual(keyword, "enforcing", "SELinux is not enforcing")

    def test_check_selinux_contexts(self):
        self.log.info(
            "Check all files confiled by SELinux has the correct contexts")
        selinux_now = self.dest_dir + "selinux.now"
        if self.rhel_ver.split('.')[0] == '8':
            data_file = "selinux.el8.lst"
        elif self.rhel_ver.split('.')[0] == '7':
            data_file = "selinux.el7.lst"
        elif self.rhel_ver.split('.')[0] == '6':
            data_file = "selinux.el6.lst"
        else:
            self.fail("RHEL version is unknown: %s" % self.rhel_ver)
        self.session.copy_data_to_guest(self.cloud.cloud_provider, data_file)
        self.session.cmd_output("rm -f {0}".format(selinux_now))
        cmd = "sudo restorecon -R -v -n / -e /mnt -e /proc -e /sys \
-e /tmp -e /var/tmp -e /run >{0}".format(selinux_now)
        self.session.cmd_output(cmd, timeout=60)
        self.session.cmd_output("grep -vxFf {0} {1} > /tmp/cmp".format(
            os.path.join(self.dest_dir, data_file), selinux_now))
        output = self.session.cmd_output("cat /tmp/cmp")
        self.assertEqual(
            "", output,
            "Found extra SELinux contexts have been modified:\n%s" % output)

    def test_check_files_controlled_by_rpm(self):
        self.log.info(
            "Check all files on the disk is controlled by rpm packages")
        utils_script = "rogue.sh"
        if self.rhel_ver.split('.')[0] == '8':
            data_file = "rogue.el8.lst"
        elif self.rhel_ver.split('.')[0] == '7':
            data_file = "rogue.el7.lst"
        elif self.rhel_ver.split('.')[0] == '6':
            data_file = "rogue.el6.lst"
        else:
            self.fail("RHEL version is unknown: %s" % self.rhel_ver)
        self.session.copy_scripts_to_guest(utils_script)
        self.session.copy_data_to_guest(self.cloud.cloud_provider, data_file)
        self.session.cmd_output("sudo sh -c 'chmod 755 %s && %s'" %
                                (os.path.join(self.dest_dir, utils_script),
                                 os.path.join(self.dest_dir, utils_script)),
                                timeout=720)
        output = self.session.cmd_output("grep -vxFf %s %s" % (os.path.join(
            self.dest_dir, data_file), os.path.join(self.dest_dir, "rogue")))
        self.assertEqual(
            "", output,
            "Found extra files not controlled by rpm:\n%s" % output)

    def test_check_file_content_integrity(self):
        self.log.info("Check file content integrity by rpm -Va")
        if self.rhel_ver.split('.')[0] == '8':
            data_file = "rpm_va.el8.lst"
        elif self.rhel_ver.split('.')[0] == '7':
            data_file = "rpm_va.el7.lst"
        elif self.rhel_ver.split('.')[0] == '6':
            data_file = "rpm_va.el6.lst"
        else:
            self.fail("RHEL version is unknown: %s" % self.rhel_ver)
        self.session.cmd_output("sudo prelink -amR")
        self.session.copy_data_to_guest(self.cloud.cloud_provider, data_file)

        # Workaround for block issue BZ1658092
        # cmd = "sudo rpm -Va | grep -vxFf {0} | grep -Ev \
        # '/boot/initramfs|/boot/System.map'"
        self.log.info('WORKAROUND: block issue BZ1658092, \
will not check kernel-devel package.')
        cmd = "sudo rpm -V `rpm -qa | grep -v kernel-devel` | grep -Ev \
'/boot/initramfs|/boot/System.map' | grep -vxFf {0}"

        output = self.session.cmd_output(cmd.format(
            os.path.join(self.dest_dir, data_file)),
                                         timeout=240)
        self.assertEqual("", output,
                         "Found extra files has been modified:\n%s" % output)
        # Continue to compare every single file under local
        # "data/vendor/file_cmp"
        root_path = os.path.dirname(os.path.dirname(self.pwd))
        src_dir = os.path.join(os.path.join(root_path, "data"),
                               self.cloud.cloud_provider)
        if os.path.isdir(os.path.join(src_dir, "file_cmp")):
            for f in os.listdir(os.path.join(src_dir, "file_cmp")):
                m = re.match(r"^(%.*%)(.*)\.el(\d)$", f)
                if m:
                    f_name = m.group(2)
                    f_ver = m.group(3)
                    f_name_l = m.group(1).replace('%', '/') + f_name
                    if self.rhel_ver.split('.')[0] != f_ver:
                        continue
                else:
                    m = re.match(r"^(%.*%)(.*)$", f)
                    f_name = m.group(2)
                    f_name_l = f.replace('%', '/')
                self.session.copy_files_to(
                    os.path.join(os.path.join(src_dir, "file_cmp"), f),
                    "/tmp/" + f_name)
                cmd = "grep -xv '^[[:space:]][[:space:]]*$' %s | diff \
-wB - %s" % (f_name_l, "/tmp/" + f_name)
                output = self.session.cmd_output(cmd)
                self.assertEqual(
                    "", output,
                    "Found %s has been modified:\n%s" % (f_name, output))

    # RHBZ#1144155
    def test_check_boot_cmdline_parameters(self):
        root_path = os.path.dirname(os.path.dirname(self.pwd))
        src_dir = os.path.join(os.path.join(root_path, "data"),
                               self.cloud.cloud_provider)
        data_file = "cmdline_params.lst"
        lines = filter(None,
                       (line.rstrip()
                        for line in open(os.path.join(src_dir, data_file))))
        output = self.session.cmd_output("cat /proc/cmdline")
        for line in lines:
            self.assertIn(line, output, "%s is not in boot parameters" % line)

    # RHBZ#1033780
    def test_check_product_certificate(self):
        output_tmp = self.session.cmd_output(
            "rpm -qf /etc/pki/product-default/230.pem")
        htb = rhel = False
        if output_tmp.startswith("redhat-release"):
            htb = True

        if self.vm.arch == "x86_64" and self.rhel_ver.split('.')[0] != '8':
            output = self.session.cmd_output(
                "rpm -qf /etc/pki/product-default/69.pem")
            if output.startswith("redhat-release"):
                rhel = True

        if self.vm.arch == "x86_64" and self.rhel_ver.split('.')[0] == '8':
            output = self.session.cmd_output(
                "rpm -qf /etc/pki/product-default/479.pem")
            if output.startswith("redhat-release"):
                rhel = True

        if self.vm.arch == "ppc64le":
            output = self.session.cmd_output(
                "rpm -qf /etc/pki/product-default/279.pem")
            if output.startswith("redhat-release"):
                rhel = True

        if htb and not rhel:
            self.error(
                "69.pem/279.pem is not found but 230.pem is found, if current "
                "phase is snapshot, probably it's OK due to the HTB program")
        if not htb and not rhel:
            self.fail("Product certificate is not found")

    def test_check_package_signature(self):
        data_file = "rpm_sign.lst"
        self.session.copy_data_to_guest(self.cloud.cloud_provider, data_file)
        cmd = "rpm -qa --qf '%{name}-%{version}-%{release}.%{arch} \
(%{SIGPGP:pgpsig})\n'|grep -v 'Key ID'"

        output = self.session.cmd_output(
            cmd + "|grep -vFf %s" % os.path.join(self.dest_dir, data_file))

        # cheshi, newline characters are not supported in aexpect, so need a
        # workaroud here
        if output.find('|grep -vFf /tmp/rpm_sign.lst') != -1:
            output = "".join(output.splitlines(True)[1:])

        self.assertEqual(
            "", output,
            "There're packages that are not signed.\n {0}".format(output))

    def test_check_hostname(self):
        output = self.session.cmd_output("hostname").split('.')[0]
        self.assertEqual(output, self.vm.vm_name.replace('_', '-'),
                         "The hostname is wrong")

    # RHBZ#974554
    def test_check_services_status(self):
        status, _ = self.session.cmd_status_output("service tuned status")
        self.assertEqual(0, status, "Tuned service abnormal")
        output = ""
        if self.vm.image_name[17] == '8' or self.vm.image_name[17] == '7':
            output = self.session.cmd_output("cat /etc/tuned/active_profile")
        if self.vm.image_name[17] == '6':
            output = self.session.cmd_output(
                "cat /etc/tune-profiles/active-profile")
        self.assertEqual("virtual-guest", output, "Tuned service abnormal")

    # RHBZ#983611
    def test_check_network_cfg(self):
        flag = False
        output = self.session.cmd_output("cat /etc/sysconfig/network")
        for line in output.splitlines():
            if line == "NOZEROCONF=yes":
                flag = True
        if self.rhel_ver.split('.')[0] == '6':
            self.assertTrue(flag,
                            "NOZEROCONF=yes not in /etc/sysconfig/network")

    # RHBZ#1011013
    def test_check_persistent_dhclient(self):
        flag = False
        output = self.session.cmd_output(
            "ps -ef | grep dhclient | grep -v grep")
        for i in output.split()[7:]:
            if i == "-1":
                flag = True
        self.assertFalse(
            flag,
            "Found '-1     Try to get a lease once.' in dhclient args -> %s" %
            output)

    def test_check_virt_what(self):
        self.log.info("Check the virt-what")
        if self.vm.flavor == 'ecs.ebmg5s.24xlarge':
            self.cancel("Alibaba baremetal, skip this case.")
        virt_type = self.params.get('virt', '*/{0}/*'.format(self.vm.flavor),
                                    'kvm')
        self.assertIn(virt_type, self.session.cmd_output("sudo virt-what"),
                      "virt-what result is not %s" % virt_type)

    def test_check_pv_drivers(self):
        self.log.info("Check pv drivers in VM")
        virt_type = self.params.get('virt', '*/{0}/*'.format(self.vm.flavor),
                                    'kvm')
        if virt_type == 'xen':
            module_list = ["xen_blkfront", "xen_netfront"]
            output = self.session.cmd_output("lsmod|grep 'xen'")
        elif virt_type == 'kvm':
            module_list = ["virtio_net", "virtio_blk"]
            output = self.session.cmd_output("lsmod|grep 'virtio'")
        else:
            self.fail("Virt is not xen or kvm: %s" % virt_type)
        for module in module_list:
            self.assertIn(module, output, "%s module doesn't exist" % module)

    def test_check_subscription_manager(self):
        pass

    def test_vm_check(self):
        """Test case for avocado framework.

        case_name:
            Get VM Check results. (Just collection)

        description:
            Gathering basic information from the instance.

        bugzilla_id:
            n/a

        polarion_id:
            n/a

        maintainer:
            cheshi@redhat.com

        case_priority:
            0

        case_component:
            checkup

        key_steps:
            1. Deliver vm_check.sh to the instance
            2. Run vm_check.sh to collect information
            3. Deliver the test results to local

        pass_criteria:
            n/a
        """
        self.log.info("VM Check")

        guest_path = self.session.cmd_output("echo $HOME") + "/workspace"
        guest_logpath = guest_path + "/log"
        host_logpath = os.path.dirname(self.job.logfile) + "/validation_data"
        self.session.cmd_output("mkdir -p {0}".format(guest_logpath))

        flavor = self.vm.flavor
        self.session.copy_files_to(
            local_path="{0}/../../scripts/vm_check.sh".format(self.pwd),
            remote_path=guest_path)
        self.log.info("Flavor: %s" % flavor)

        # Cleanup $HOME/workspace/log
        self.session.cmd_output("rm -rf {0}/*".format(guest_logpath))

        # Run vm_check.sh
        self.session.cmd_output("bash {0}/vm_check.sh".format(guest_path),
                                timeout=300)

        # Tar logs
        # self.session.cmd_output(
        #     "cd {0} && tar -zcf vm_check_results_{1}.tar.gz .".format(
        #         guest_logpath, flavor))

        # Copy logs to host
        process.run(cmd="mkdir -p " + host_logpath,
                    timeout=20,
                    verbose=False,
                    ignore_status=False,
                    shell=True)
        self.log.debug("Copying logs to host...")
        self.session.copy_files_from(local_path=host_logpath,
                                     remote_path="{0}/*".format(guest_logpath),
                                     timeout=600)
        self.log.info("Copy logs to {0} successfully.".format(host_logpath))

        # Cleanup scripts and logs
        self.session.cmd_output("rm -rf " + guest_path)

    def test_collect_metadata(self):
        """Test case for avocado framework.

        case_name:
            Collect metadata from cloud provider. (Just collection)

        description:
            Gathering the metadata from cloud providers's metadata server
            inside instance.

        bugzilla_id:
            n/a

        polarion_id:
            n/a

        maintainer:
            cheshi@redhat.com

        case_priority:
            0

        case_component:
            checkup

        key_steps:
            1. Deliver traverse_metadata.sh to the instance
            2. Run traverse_metadata.sh to collect information
            3. Deliver the test results to local

        pass_criteria:
            n/a
        """
        self.log.info("Collect Metadata")

        guest_path = self.session.cmd_output("echo $HOME") + "/workspace"
        guest_logpath = guest_path + "/log"
        host_logpath = os.path.dirname(self.job.logfile) + "/validation_data"
        self.session.cmd_output("mkdir -p {0}".format(guest_logpath))

        flavor = self.vm.flavor
        self.session.copy_files_to(
            local_path="{0}/../../scripts/traverse_metadata.sh".format(
                self.pwd),
            remote_path=guest_path)
        self.log.info("Flavor: %s" % flavor)

        # Cleanup $HOME/workspace/log
        self.session.cmd_output("rm -rf {0}/*".format(guest_logpath))

        # Run traverse_metadata.sh
        self.session.cmd_output("bash {0}/traverse_metadata.sh \
> {1}/traverse_metadata_{2}_$(date +%Y%m%d%H%M%S).log".format(
            guest_path, guest_logpath, flavor))

        # Copy logs to host
        process.run(cmd="mkdir -p " + host_logpath,
                    timeout=20,
                    verbose=False,
                    ignore_status=False,
                    shell=True)
        self.log.debug("Copying logs to host...")
        self.session.copy_files_from(local_path=host_logpath,
                                     remote_path="{0}/*".format(guest_logpath))
        self.log.info("Copy logs to {0} successfully.".format(host_logpath))

        # Cleanup scripts and logs
        self.session.cmd_output("rm -rf " + guest_path)

    def tearDown(self):
        self.session.close()
