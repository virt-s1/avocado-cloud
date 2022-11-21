from avocado import Test
from avocado_cloud.app import Setup
from avocado_cloud.utils import utils_misc
from avocado_cloud.utils import utils_alibaba
from avocado.utils import process
import re
import os
import time


class GeneralTest(Test):
    def setUp(self):
        self.cloud = Setup(self.params, self.name)
        self.vm = self.cloud.vm
        self.session = self.cloud.init_vm(pre_delete=False, pre_stop=False)
        self.rhel_ver = str(self.params.get('rhel_ver', '*/VM/*', ''))
        self.image_name = str(self.params.get('name', '*/Image/*'))
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
        """Test case for avocado framework.

        case_name:
            [Aliyun]GeneralTest.test_check_boot_message
        description:
            Check the boot messages.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]GeneralTest.test_check_boot_message"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Lookup contents from `/var/log/messages` for RHEL7 and lower.
            2. Get boot message by `journalctl` for RHEL8 and higher.
            3. Check if there is `error` or `fail` keyword in the boot message.
            4. Excepts the entries from the whitelist.
        pass_criteria:
            No `error` or `fail` keywords in boot messages except the whitelisted ones.
        """

        self.log.info("Check the boot messages with no errors")
        if self.rhel_ver.split('.')[0] == '9':
            data_file = "journalctl.el9.lst"
        elif self.rhel_ver.split('.')[0] == '8':
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

    def test_check_calltrace(self):
        self.log.info("Check the boot messages without call trace.")
        if float(self.rhel_ver) >= 8.0:
            cmd = "sudo journalctl -b | grep -B 3 -A 10 'Call Trace:'"
        else:
            cmd = "sudo cat /var/log/messages | grep -B 3 -A 10 'Call Trace:'"
        output = self.session.cmd_output(cmd)
        self.assertEqual("", output,
                         "There're call trace in system logs:\n%s" % output)

    # RHBZ#1006883
    def test_check_fstab(self):
        """Test case for avocado framework.

        case_name:
            [Aliyun]GeneralTest.test_check_fstab
        description:
            Check if rootfs in /etc/fstab is presented by UUID.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]GeneralTest.test_check_fstab"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Get the rootfs line from `/etc/fstab`.
            2. Check if the device is presented by UUID.
        pass_criteria:
            The rootfs in /etc/fstab should be presented by UUID.
        """

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
        """Test case for avocado framework.

        case_name:
            [Aliyun]GeneralTest.test_check_bash_prompt
        description:
            Check the bash prompt.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]GeneralTest.test_check_bash_prompt"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Check the value of `$PS1`.
        pass_criteria:
            `$PS1` should be `[\u@\h \W]\$`.
        """

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
        """Test case for avocado framework.

        case_name:
            [Aliyun]GeneralTest.test_check_redhat_release
        description:
            Check the version of `redhat-release-server` package.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]GeneralTest.test_check_redhat_release"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Get the version of `redhat-release-server` package.
            2. Compare with the system release version in `/etc/redhat-release`.
        pass_criteria:
            Release version and the redhat-release-server package should be matched.
        """

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
        """Test case for avocado framework.

        case_name:
            [Aliyun]GeneralTest.test_check_selinux_status
        description:
            Check the selinux status.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]GeneralTest.test_check_selinux_status"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Check the SELinux status by `getenforce`.
            2. Check the configuration in file `/etc/selinux/config`.
        pass_criteria:
            SELinux should be `Enforcing` and set as default.
        """

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
        """Test case for avocado framework.

        case_name:
            [Aliyun]GeneralTest.test_check_selinux_contexts
        description:
            Check the selinux contexts of all system files.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]GeneralTest.test_check_selinux_contexts"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Use `restorecon` command to check system files.
            2. Except the entries in whitelist selinux.el9.lst.
        pass_criteria:
            Selinux contexts of the system files should not be changed except the whitelisted ones.
        """

        self.log.info(
            "Check all files confiled by SELinux has the correct contexts")
        selinux_now = self.dest_dir + "selinux.now"
        if self.rhel_ver.split('.')[0] == '9':
            data_file = "selinux.el9.lst"
        elif self.rhel_ver.split('.')[0] == '8':
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
        """Test case for avocado framework.

        case_name:
            [Aliyun]GeneralTest.test_check_files_controlled_by_rpm
        description:
            Check if all system files are controlled by rpm.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]GeneralTest.test_check_files_controlled_by_rpm"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Query files that doesn't belong to any package.
            2. Except the entries in whitelist rogue.el*.lst.
        pass_criteria:
            All system files are controlled by rpm except the whitelisted ones.
        """

        self.log.info(
            "Check all files on the disk is controlled by rpm packages")
        utils_script = "rogue.sh"
        if self.rhel_ver.split('.')[0] == '9':
            data_file = "rogue.el9.lst"
        elif self.rhel_ver.split('.')[0] == '8':
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

    def test_check_file_content_integrity_by_rpm(self):
        """Test case for avocado framework.

        case_name:
            [Aliyun]GeneralTest.test_check_file_content_integrity_by_rpm
        description:
            Check the file content integrity by `rpm -v` command.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]GeneralTest.test_check_file_content_integrity_by_rpm"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Query all the packages installed.
            2. Verify each package by `rpm -v`
            3. Except the entries in whitelist rpm_va.el*.lst
        pass_criteria:
            All packages should be intact excepted the ones from the whitelist.
        """

        self.log.info("Check file content integrity by rpm -Va")
        if self.rhel_ver.split('.')[0] == '9':
            data_file = "rpm_va.el9.lst"
        elif self.rhel_ver.split('.')[0] == '8':
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

    def test_check_file_content_integrity_by_diff(self):
        """Test case for avocado framework.

        case_name:
            [Aliyun]GeneralTest.test_check_file_content_integrity_by_diff
        description:
            Check the file content integrity by `diff` command.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]GeneralTest.test_check_file_content_integrity_by_diff"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Get the templates from file_cmp.el*;
            2. Compare specific template with the files in VM.
        pass_criteria:
            All files should be intact and match with the templates.
        """

        # Compare every single file under local "data/vendor/file_cmp"
        root_path = os.path.dirname(os.path.dirname(self.pwd))
        src_dir = os.path.join(os.path.join(root_path, 'data'),
                               self.cloud.cloud_provider)

        # Determine the best file_cmp matches
        # Example: 'file_cmp.el8.3' is better than 'file_cmp.el8'
        if os.path.isdir(os.path.join(src_dir, 'file_cmp.el' + self.rhel_ver)):
            file_cmp = os.path.join(src_dir, 'file_cmp.el' + self.rhel_ver)
        elif os.path.isdir(
                os.path.join(src_dir,
                             'file_cmp.el' + self.rhel_ver.split('.')[0])):
            file_cmp = os.path.join(
                src_dir, 'file_cmp.el' + self.rhel_ver.split('.')[0])
        else:
            self.error('Can not found file_cmp matches.')
        self.log.info('Selected file_cmp as {0}'.format(file_cmp))

        # Deliver files and check
        for f in os.listdir(file_cmp):
            m = re.match(r"^(%.*%)(.*)$", f)
            if m:
                f_name = m.group(2)
                f_name_l = f.replace('%', '/')
            else:
                self.error('Failed to parse file {0}.'.format(f))

            self.session.copy_files_to(os.path.join(file_cmp, f),
                                       '/tmp/' + f_name)

            cmd = "grep -xv '^[[:space:]][[:space:]]*$' %s | diff \
-wB - %s" % (f_name_l, '/tmp/' + f_name)
            output = self.session.cmd_output(cmd)
            self.assertEqual(
                '', output,
                'Found %s has been modified:\n%s' % (f_name, output))

    # RHBZ#1144155
    def test_check_boot_cmdline_parameters(self):
        """Test case for avocado framework.

        case_name:
            [Aliyun]GeneralTest.test_check_boot_cmdline_parameters
        description:
            Check parameters in boot cmdline.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]GeneralTest.test_check_boot_cmdline_parameters"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Check if all entries from cmdline_params.lst exist in cmdline.
        pass_criteria:
            All entries from cmdline_params.lst should be exist in cmdline.
        """

        root_path = os.path.dirname(os.path.dirname(self.pwd))
        src_dir = os.path.join(os.path.join(root_path, "data"),
                               self.cloud.cloud_provider)
        if self.rhel_ver.split('.')[0] == '9':
            if self.vm.arch == "x86_64":
                data_file = "cmdline_params.el9.lst"
            elif self.vm.arch == "aarch64":
                data_file = "cmdline_params.el9.arm64.lst"
        else:
            data_file = "cmdline_params.lst"

        lines = filter(None,
                       (line.rstrip()
                        for line in open(os.path.join(src_dir, data_file))))
        output = self.session.cmd_output("cat /proc/cmdline")
        self.log.info('The output of /proc/cmdline: {0}'.format(output))
        for line in lines:
            self.assertIn(line, output, "%s is not in boot parameters" % line)

    # RHBZ#1033780
    def test_check_product_certificate(self):
        """Test case for avocado framework.

        case_name:
            [Aliyun]GeneralTest.test_check_product_certificate
        description:
            Check the product certificates in the system.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]GeneralTest.test_check_product_certificate"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Query product certificates.
            2. Check if the mandatory certificate exists.
        pass_criteria:
            Proper product certificates should be installed.
        """

        output_tmp = self.session.cmd_output(
            "rpm -qf /etc/pki/product-default/230.pem")
        htb = rhel = False
        if output_tmp.startswith("redhat-release"):
            htb = True

        if self.vm.arch == "x86_64" and self.rhel_ver.split('.')[0] == '9':
            output = self.session.cmd_output(
                "rpm -qf /etc/pki/product-default/479.pem")
            if output.startswith("redhat-release"):
                rhel = True

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

        if self.vm.arch == "aarch64":
            output = self.session.cmd_output(
                "rpm -qf /etc/pki/product-default/419.pem")
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
        """Test case for avocado framework.

        case_name:
            [Aliyun]GeneralTest.test_check_package_signature
        description:
            Check the package signature.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]GeneralTest.test_check_package_signature"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Check each package's signature.
            2. Find the ones without signature.
            3. Except the entries in signature.
        pass_criteria:
            Except entries in rpm_sign.lst all packages has been signed.
        """

        data_file = "rpm_sign.lst"
        self.session.copy_data_to_guest(self.cloud.cloud_provider, data_file)
        cmd = "rpm -qa --qf '%{name}-%{version}-%{release}.%{arch} (%{SIGPGP:pgpsig})'|grep -v 'Key ID'"

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
        """Test case for avocado framework.

        case_name:
            [Aliyun]GeneralTest.test_check_hostname
        description:
            Check that the hostname is set correctly.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]GeneralTest.test_check_hostname"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Set a hostname while creating instance via Aliyun SDK.
            2. Check the hostname inside VM.
        pass_criteria:
            The hostname should be set correctly.
        """

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
        """Test case for avocado framework.

        case_name:
            [Aliyun]GeneralTest.test_check_virt_what
        description:
            Check the virtualization platform.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]GeneralTest.test_check_virt_what"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Call `virt-what` to show the platform
            2. Compare with the definition
        pass_criteria:
            The virtualization platform matches the definition.
        """

        self.log.info("Check the virt-what")
        if 'ecs.ebm' in self.vm.flavor:
            self.cancel("Alibaba baremetal, skip this case.")
        virt_type = self.params.get('virt', '*/{0}/*'.format(self.vm.flavor),
                                    'kvm')
        self.assertIn(virt_type, self.session.cmd_output("sudo virt-what"),
                      "virt-what result is not %s" % virt_type)

    def test_check_pv_drivers(self):
        """Test case for avocado framework.

        case_name:
            [Aliyun]GeneralTest.test_check_pv_drivers
        description:
            Check the PV drivers for the instance.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]GeneralTest.test_check_pv_drivers"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. virtio_net should be exist.
            2. at least one of virtio_blk and nvme should be exist.
        pass_criteria:
            The PV drivers should be exist in the instance.
        """

        self.log.info('Check pv drivers in VM')

        cmd = 'lsmod | grep -w virtio_net'
        utils_alibaba.run_cmd(self, cmd, expect_ret=0)

        cmd = 'lsmod | grep -w -e virtio_blk -e nvme'
        utils_alibaba.run_cmd(self, cmd, expect_ret=0)

    def test_check_subscription_manager(self):
        pass

    def test_collect_information_for_create(self):
        """Test case for avocado framework.

        case_name:
            [Aliyun]GeneralTest.test_collect_information_for_create
        description:
            Collect basic information and logs after creating VM.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]GeneralTest.test_collect_information_for_create"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Create a new VM;
            2. Deliver vm_check.sh to the instance;
            3. Run vm_check.sh to collect information;
            4. Deliver the test results to local;
        pass_criteria:
            The logs can be delivered successfully.
        """

        utils_alibaba.collect_information(self, 'create')

    def test_collect_information_for_reboot(self):
        """Test case for avocado framework.

        case_name:
            [Aliyun]GeneralTest.test_collect_information_for_reboot
        description:
            Collect basic information and logs after rebooting VM.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]GeneralTest.test_collect_information_for_reboot"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Reboot the instance;
            2. Deliver vm_check.sh to the instance;
            3. Run vm_check.sh to collect information;
            4. Deliver the test results to local;
        pass_criteria:
            The logs can be delivered successfully.
        """

        utils_alibaba.collect_information(self, 'reboot')

    def test_collect_information_for_restart(self):
        """Test case for avocado framework.

        case_name:
            [Aliyun]GeneralTest.test_collect_information_for_restart
        description:
            Collect basic information and logs after restarting VM.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]GeneralTest.test_collect_information_for_restart"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Stop and start the instance;
            2. Deliver vm_check.sh to the instance;
            3. Run vm_check.sh to collect information;
            4. Deliver the test results to local;
        pass_criteria:
            The logs can be delivered successfully.
        """

        utils_alibaba.collect_information(self, 'restart')

    def test_collect_metadata(self):
        """Test case for avocado framework.

        case_name:
            [Aliyun]GeneralTest.test_collect_metadata
        description:
            Gathering the metadata from cloud providers's metadata server inside instance.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]GeneralTest.test_collect_metadata"
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
            The metadata can be delivered successfully.
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

    def test_check_cpu_count(self):
        """Test case for avocado framework.

        case_name:
            [Aliyun]GeneralTest.test_check_cpu_count
        description:
            Check the CPU count inside the VM.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]GeneralTest.test_check_cpu_count"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Collect and compare the CPU count.
        pass_criteria:
            CPU number inside the VM equals to guest CPU # in SPEC.
        """

        guest_cpu = int(
            self.session.cmd_output(
                "lscpu | grep ^CPU.s.: | awk '{print $2}'"))
        expected_cpu = self.vm.cpu

        self.assertEqual(
            guest_cpu, expected_cpu,
            'CPU count is not as expect Real: {0}; Expected: {1}'.format(
                guest_cpu, expected_cpu))

    def test_check_mem_size(self):
        """Test case for avocado framework.

        case_name:
            [Aliyun]GeneralTest.test_check_mem_size
        description:
            Check the memory size inside the instance.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]GeneralTest.test_check_mem_size"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Collect and compare the Memory Size.
            2. Consider the parts taken by kdump service.
        pass_criteria:
            Memory Size is as expect in SPEC.
        """

        guest_mem = int(
            self.session.cmd_output("free -m | grep ^Mem: | awk '{print $2}'"))
        expected_mem = self.vm.memory * 1024

        self.assertAlmostEqual(
            first=guest_mem,
            second=expected_mem,
            delta=expected_mem * 0.25,
            msg="Memory Size is not as expect Real: {0}; Expected: {1}".format(
                guest_mem, expected_mem))

    def test_kdump_function(self):
        """Test case for avocado framework.

        case_name:
            [Aliyun]GeneralTest.test_kdump_function
        description:
            Check kdump function works well on Aliyun platform.
            Kdump works on Aliyun platform with RHEL Images. 
            From RHEL8.7 there is a feature request
            "Bug 2088457 - (Alibaba 8.7features) - backport support for pvpanic:
            add crash loaded event", \
            kdump event shows in Aliyun console.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RHELVIRT/workitems?query=title:"[Aliyun]GeneralTest.test_kdump_function"
        maintainer:
            linl@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Start an instance (e.g., c6.xlarge) with RHEL image on Aliyun.
            2. Check the kdump service is enabled and active.
            3. From RHEL8.7, check if there is kernel paremeter \
               "crash_kexec_post_notifiers=1" loaded via command \
               "dmesg | grep command". \
               This parameter should be set by default in RHEL8.7 images \
               to support GUEST_CRASHLOADED event.
            4. Trigger a crash via "echo c > /proc/sysrq-trigger" in instance. \
               Instance crashes and reboot.
            5. There is vmcore generated in /var/crash. \
               From RHEL8.7, Check if there is message about the panic in Aliyun console event (Manually).
        pass_criteria:
            System can enter to the second kernel and then reboot,\
            and crash core can be gernerated.
            From RHEL8.7, there is kdump event shows in Aliyun console.
        """

        self.log.info("Checking kdump status")

        if self.rhel_ver.split('.')[0] == '6':
            check_cmd = 'sudo service kdump status'
        else:
            check_cmd = 'systemctl status kdump.service'
        
        kdump_running = False
        
        for i in range(10):
            output = self.session.cmd_output(check_cmd)
            self.log.debug("%s" % output)
            if 'Active: active' in output:
                self.log.info('kdump service is running.')
                kdump_running = True
                break
            else:
                if 'Active: inactive' in output:
                    self.log.error('kdump service is inactive!')
                    break
                if 'Kdump is unsupported' in output:
                    self.log.error('kdump service is unsupported!')
                    break
                self.log.info('Wait for another 20s (max = 200s)')
                time.sleep(20)

        if not kdump_running:
            self.fail('kdump service is not running at last.')

        self.log.info("Check kdump function")
        utils_alibaba.run_cmd(self,
                        r'cat /proc/sys/kernel/sysrq',
                        expect_ret=0,
                        msg='Check the default sysrq value')
        self.log.info("Before system crash")
        utils_alibaba.run_cmd(self,
                        r'find /var/crash',
                        expect_ret=0,
                        msg='list /var/crash')
        self.log.info("Crashing via ssh")
        trigger_cmd = "bash -c 'echo c > /proc/sysrq-trigger'"
        self.log.debug("Send command '%s' " % trigger_cmd)
        self.session.session.sendline("'%s'" % trigger_cmd)
        try:
            status, output = self.session.cmd_status_output(trigger_cmd)
            self.log.info("trigger ret: %s, output: %s" % (status, output))
        except Exception as err:
            self.log.info("Error to read output as expected! %s" % err)
        time.sleep(30)
        self.session.connect()
        self.log.info("After system crash")
        utils_alibaba.run_cmd(self,
                        r'find /var/crash',
                        expect_ret=0,
                        msg='list /var/crash after crash')
        cmd = 'cat /var/crash/1*/vmcore-dmesg.txt|tail -50'
        utils_alibaba.run_cmd(self, cmd, expect_ret=0, expect_kw='write_sysrq_trigger')

    def test_kexec_fastboot_systemctl(self):
        """
        case_name:
            [Aliyun]GeneralTest.test_kexec_fastboot_systemctl
        case_tags:
            kdump
        case_status:
            Approved
        title:
            [Aliyun]GeneralTest.test_kexec_fastboot_systemctl
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RHELVIRT/workitems?query=title:"[Aliyun]GeneralTest.test_kexec_fastboot_systemctl"
        importance:
            Critical
        subsystem_team:
            sst_virtualization_cloud
        automation_drop_down:
            Automated
        linked_work_items:
            polarion-VIRT-99338
        automation_field:
            https://github.com/virt-s1/avocado-cloud/tree/master/tests/alibaba/test_functional_checkup.py
        setup_teardown:
            n/a
        environment:
            n/a
        component:
            kernel
        bug_id:
            1758323, 1841578
        is_customer_case:
            False
        testplan:
            https://polarion.engineering.redhat.com/polarion/#/project/RHELVIRT/wiki/Alibaba/Aliyun%20RHEL%20guest%20Test%20Plan
        test_type:
            Functional
        test_level:
            Component
        maintainer:
            linl@redhat.com
        description:
            Test fastboot kernel via systemctl kexec.
        key_steps:
            1. Start an instance (e.g., c6.xlarge) with RHEL image on Aliyun.
            2. Check the kdump service is enabled and active.
            3. Load each kernel with command "sudo kexec -l /boot/vmlinuz-$version --initrd=/boot/initramfs-$version.img --reuse-cmdline"
            4. Fastboot via command "systemctl kexec".
        expected_result:
            Kernel is loaded successfully without panic or crash.
        debug_want:
            n/a

        """

        self.log.info("Checking kdump status")

        if self.rhel_ver.split('.')[0] == '6':
            check_cmd = 'sudo service kdump status'
        else:
            check_cmd = 'systemctl status kdump.service'

        kdump_running = False

        for i in range(10):
            output = self.session.cmd_output(check_cmd)
            self.log.debug("%s" % output)
            if 'Active: active' in output:
                self.log.info('kdump service is running.')
                kdump_running = True
                break
            else:
                if 'Active: inactive' in output:
                    self.log.error('kdump service is inactive!')
                    break
                if 'Kdump is unsupported' in output:
                    self.log.error('kdump service is unsupported!')
                    break
                self.log.info('Wait for another 20s (max = 200s)')
                time.sleep(20)

        if not kdump_running:
            self.cancel('Cancel test as kdump is not running.')

        self.log.info("Test fastboot via systemctl kexec")
        self.session.connect()
        utils_alibaba.run_cmd(self,'uname -r', cancel_not_kw='el7,el6', msg='Not full support earlier than el8, skip!')
        cmd = 'sudo rpm -qa|grep -e "kernel-[0-9]"'
        output = utils_alibaba.run_cmd(self, cmd, msg='Get kernel version')
        kernels_list = output.split('\n')
        for kernel in kernels_list:
            kernel_vmlinuz = "/boot/" + kernel.replace('kernel','vmlinuz')
            kernel_initramfs = "/boot/" + kernel.replace('kernel','initramfs') + ".img"
            cmd = "sudo kexec -l %s --initrd=%s --reuse-cmdline" % (kernel_vmlinuz, kernel_initramfs)
            utils_alibaba.run_cmd(self, cmd, msg='Switch kernel', expect_ret=0)
            cmd = "sudo systemctl kexec"
            self.log.info("CMD: %s", cmd)
            self.session.session.sendline("%s" % cmd)
            time.sleep(10)
            self.session.connect()
            utils_alibaba.run_cmd(self, 'uname -r', msg='check kernel', expect_ret=0, expect_kw=kernel[7:])

    def test_kexec_fastboot_kexec_e(self):
        """Test case for avocado framework.

        case_name:
            [Aliyun]GeneralTest.test_kexec_fastboot_kexec_e
        case_tags:
            kdump
        case_status:
            Approved
        title:
            [Aliyun]GeneralTest.test_kexec_fastboot_systemctl
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RHELVIRT/workitems?query=title:"[Aliyun]GeneralTest.test_kexec_fastboot_kexec_e"
        importance:
            Critical
        subsystem_team:
            sst_virtualization_cloud
        automation_drop_down:
            Automated
        linked_work_items:
            polarion-VIRT-99338
        automation_field:
            https://github.com/virt-s1/avocado-cloud/tree/master/tests/alibaba/test_functional_checkup.py
        setup_teardown:
            n/a
        environment:
            n/a
        component:
            kernel
        bug_id:
            1758323, 1841578
        is_customer_case:
            False
        testplan:
            https://polarion.engineering.redhat.com/polarion/#/project/RHELVIRT/wiki/Alibaba/Aliyun%20RHEL%20guest%20Test%20Plan
        test_type:
            Functional
        test_level:
            Component
        maintainer:
            linl@redhat.com
        description:
            Test fastboot kernel via systemctl kexec.
        key_steps:
            1. Start an instance (e.g., c6.xlarge) with RHEL image on Aliyun.
            2. Check the kdump service is enabled and active.
            3. Load each kernel with command "sudo kexec -l /boot/vmlinuz-$version --initrd=/boot/initramfs-$version.img --reuse-cmdline"
            4. Fastboot via command "kexec -e".
        expected_result:
            Kernel can be loaded via kexec, and system will reboot into the loaded kernel via kexec -e without calling shutdown(8).
        debug_want:
            n/a

        """

        self.log.info("Checking kdump status")

        if self.rhel_ver.split('.')[0] == '6':
            check_cmd = 'sudo service kdump status'
        else:
            check_cmd = 'systemctl status kdump.service'

        kdump_running = False

        for i in range(10):
            output = self.session.cmd_output(check_cmd)
            self.log.debug("%s" % output)
            if 'Active: active' in output:
                self.log.info('kdump service is running.')
                kdump_running = True
                break
            else:
                if 'Active: inactive' in output:
                    self.log.error('kdump service is inactive!')
                    break
                if 'Kdump is unsupported' in output:
                    self.log.error('kdump service is unsupported!')
                    break
                self.log.info('Wait for another 20s (max = 200s)')
                time.sleep(20)

        if not kdump_running:
            self.cancel('Cancel test as kdump is not running.')

        self.log.info("Test fastboot via systemctl kexec")
        self.session.connect()
        utils_alibaba.run_cmd(self,'uname -r', cancel_not_kw='el7,el6', msg='Not full support earlier than el8, skip!')
        cmd = 'sudo rpm -qa|grep -e "kernel-[0-9]"'
        output = utils_alibaba.run_cmd(self, cmd, msg='Get kernel version')
        kernels_list = output.split('\n')
        for kernel in kernels_list:
            kernel_vmlinuz = "/boot/" + kernel.replace('kernel','vmlinuz')
            kernel_initramfs = "/boot/" + kernel.replace('kernel','initramfs') + ".img"
            cmd = "sudo kexec -l %s --initrd=%s --reuse-cmdline" % (kernel_vmlinuz, kernel_initramfs)
            utils_alibaba.run_cmd(self, cmd, msg='Switch kernel', expect_ret=0)
            cmd = "sudo kexec -e"
            self.log.info("CMD: %s", cmd)
            self.session.session.sendline("%s" % cmd)
            time.sleep(10)
            self.session.connect()
            utils_alibaba.run_cmd(self, 'uname -r', msg='check kernel', expect_ret=0, expect_kw=kernel[7:])

    def test_check_image_id(self):
        """Check the image label in Alibaba private image.

        case_name:
            [Aliyun]GeneralTest.test_check_image_id
        description:
            Check the image label in Alibaba private image
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]GeneralTest.test_check_image_id"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Get the image labels from /etc/image-id
            2. Get the image labels from configure
            3. Check each label from /etc/image-id
        pass_criteria:
            All the labels from /etc/image-id should exist in the configured
            image name.
        """

        self.log.info("Check the /etc/image-id is correct.")

        # Get TargetName
        # cat /etc/image-id
        # image_id="redhat_8_3_x64_20G_alibase_20201211.qcow2"
        cmd = 'sudo cat /etc/image-id | cut -d\'"\' -f2'
        target_name = self.session.cmd_output(cmd)

        # Cancel this case if not provided
        if 'No such file or directory' in target_name:
            self.cancel('/etc/image-id is not provided, skip this case.')
        else:
            self.log.debug(
                'Got TargetName "{}" from /etc/image-id'.format(target_name))

        # Get ImageName
        image_name = self.image_name
        self.log.debug('Got ImageName "{}"'.format(image_name))

        # Cancel this case if not Alibaba private image
        if not image_name.startswith(('redhat_', 'rhel_')):
            self.cancel('Not Alibaba private image, skip this case.')

        # Get comparsion labels
        # Ex. "redhat_8_3_x64_20G_alibase_20201211_copied.qcow2"
        inside = target_name.replace('.', '_').split('_')
        outside = image_name.replace('.', '_').split('_')
        self.log.debug(
            'Image Labels:\nInside: {}\nOutside: {}'.format(inside, outside))

        # Compare image labels
        for label in inside:
            if label in ('qcow2', 'raw', 'vhd'):
                continue
            if label in outside:
                self.log.debug(
                    'Inside label "{}" exists in outside labels.'.format(label))
            else:
                self.log.debug(
                    'Inside label "{}" doesn\'t exist in outside labels.'.format(label))
                self.fail('The image labels are mismatched.')

        self.log.info('The image labels are matched.')

    def test_check_yum_repoinfo(self):
        """Check the yum repoinfo for RHUI repos.

        case_name:
            [Aliyun]GeneralTest.test_check_yum_repoinfo
        description:
            Check the yum repoinfo for RHUI repos.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]GeneralTest.test_check_yum_repoinfo"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. yum repoinfo, Repo-pkgs is not zero.
        pass_criteria:
            All commands succeed.
        """

        utils_alibaba.run_cmd(self,
                              'sudo yum repoinfo',
                              expect_ret=0,
                              expect_not_kw='Repo-pkgs          : 0',
                              timeout=1200,
                              msg='try to get repo info')

    def test_yum_package_install(self):
        """Check the yum package installation.

        case_name:
            [Aliyun]GeneralTest.test_yum_package_install
        description:
            Check the yum package installation.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]GeneralTest.test_yum_package_install"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. yum clean all
            2. yum repolist
            3. yum check-update
            4. yum search zsh
            5. yum -y install zsh
            6. sudo rpm -e zsh
        pass_criteria:
            All commands succeed.
        """

        utils_alibaba.run_cmd(
            self, "sudo yum clean all", expect_ret=0, timeout=180)
        utils_alibaba.run_cmd(
            self, "sudo yum repolist", expect_ret=0, timeout=1200)
        utils_alibaba.run_cmd(
            self, "sudo yum check-update", timeout=1200)
        utils_alibaba.run_cmd(self,
                              "sudo yum search zsh",
                              expect_ret=0,
                              timeout=180)
        utils_alibaba.run_cmd(self,
                              "sudo yum -y install zsh",
                              expect_ret=0,
                              timeout=180)
        utils_alibaba.run_cmd(self,
                              r"sudo rpm -q --queryformat '%{NAME}' zsh",
                              expect_ret=0)
        utils_alibaba.run_cmd(self, "sudo rpm -e zsh", expect_ret=0)

    def test_check_vulnerabilities(self):
        """ Check vulnerabilities for RHEL on Aliyun.

        case_name:
            [Aliyun]GeneralTest.test_check_vulnerabilities
        description:
            Check vulnerabilities for RHEL on Aliyun.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]GeneralTest.test_check_vulnerabilities"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Launch an instance on Aliyun.
            2. Get microcode version via command "rpm -qa | grep microcode".
            3. Check the current vulnerabilities via command "grep ^ /sys/devices/system/cpu/vulnerabilities/*".
        pass_criteria:
            There is no unexpected vulnerabilities in system.
            Whitelisted all the vulnerabilities from RHEL7.9 and RHEL8.3 before July 2021.
        """

        # Print microcode version
        utils_alibaba.run_cmd(self, 'rpm -qa|grep microcode',
                              msg='Get microcode version')

        # Print vulnerabilities
        check_cmd = 'grep ^ /sys/devices/system/cpu/vulnerabilities/* | sed "s#^.*vulnerabilities/##"'
        utils_alibaba.run_cmd(self, check_cmd, expect_ret=0)

        # Apply whitelist and perform checking
        data_file = 'vulnerabilities.el{}.lst'.format(self.rhel_ver)
        if not utils_alibaba.is_data_file_exist(self.cloud.cloud_provider, data_file):
            data_file = 'vulnerabilities.el{}.lst'.format(
                self.rhel_ver.split('.')[0])
        if not utils_alibaba.is_data_file_exist(self.cloud.cloud_provider, data_file):
            self.error('Data file can not be found.')
        self.session.copy_data_to_guest(self.cloud.cloud_provider, data_file)

        check_cmd += ' | grep -v "Not affected" | grep -vxFf {}'.format(
            os.path.join(self.dest_dir, data_file))
        utils_alibaba.run_cmd(self, check_cmd, expect_output='')

    def test_check_rhui_crt(self):
        """ Check /etc/pki/rhui/product/content.crt exists in image and the end date doesn't expired.

        case_name:
            [Aliyun]GeneralTest.test_check_rhui_crt
        description:
            Check the rhui crt file /etc/pki/rhui/product/content.crt exists in image and the end date doesn't expired.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RHELVIRT/workitems?query=title:"[Aliyun]GeneralTest.test_check_rhui_crt"
        maintainer:
            linl@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Launch an instance on Aliyun.
            2. Get rhui crt information via command " rct cat-cert /etc/pki/rhui/product/content.crt".
            3. Check the End Date of rhui crt.
        pass_criteria:
            The rhui crt End Date should be later than current date (Later than product support phase).
        """

        utils_alibaba.run_cmd(self,
                        r'sudo rct cat-cert /etc/pki/rhui/product/content.crt',
                        expect_ret=0,
                        msg='Check the rhui crt information.')
        cmd = "timestamp=$(sudo rct cat-cert /etc/pki/rhui/product/content.crt|grep 'End Date'|awk '{print $3}');date -d $timestamp +%s"
        end_date = utils_alibaba.run_cmd(self, cmd, msg='get rhui cert end date')
        cmd = 'sudo date +%s'
        now_date = utils_alibaba.run_cmd(self, cmd, msg='get now date')
        self.assertTrue(int(end_date) > int(now_date), "RHUI cert has expired")

    def test_check_boot_time_create(self):
        """ Check the boot time after instance first launch.

        case_name:
            [Aliyun]GeneralTest.test_check_boot_time_create
        description:
            Check the boot time after instance first launch (create instance).
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]GeneralTest.test_check_boot_time_create"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Launch an instance on Aliyun.
            2. Get boot time by 'systemd-analyze'
            3. Compare the time with experienced max time
        pass_criteria:
            The actual boot time is no more than the experienced max time.
        """
        
        if 'ecs.ebm' in self.vm.flavor:
            if self.vm.boot_mode == 'uefi':
                max_boot_time = 240
            else:
                max_boot_time = 80
        else:
            # kvm-based VMs
            max_boot_time = 40

        boot_time_sec = utils_alibaba.getboottime(self)
        utils_alibaba.compare_nums(self, num1=boot_time_sec, num2=max_boot_time,
                                   ratio=0, msg="Compare with experienced max_boot_time")

    def test_check_boot_time_reboot(self):
        """ Check the boot time after instance reboot.

        case_name:
            [Aliyun]GeneralTest.test_check_boot_time_reboot
        description:
            Check the boot time after instance reboot.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]GeneralTest.test_check_boot_time_reboot"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Reboot an instance on Aliyun.
            2. Get boot time by 'systemd-analyze'
            3. Compare the time with experienced max time
        pass_criteria:
            The actual boot time is no more than the experienced max time.
        """
        if 'ecs.ebm' in self.vm.flavor:
            if self.vm.boot_mode == 'uefi':
                max_boot_time = 240
            else:
                max_boot_time = 80
        else:
            # kvm-based VMs
            max_boot_time = 40

        boot_time_sec = utils_alibaba.getboottime(self)
        utils_alibaba.compare_nums(self, num1=boot_time_sec, num2=max_boot_time,
                                   ratio=0, msg="Compare with experienced max_boot_time")

    def tearDown(self):
        self.session.close()
