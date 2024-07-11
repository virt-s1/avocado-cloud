import time
import re
from avocado import Test
from avocado import main
from avocado_cloud.app import Setup
from avocado_cloud.app.azure import AzureAccount, AzureNIC, AzurePublicIP, AzureNicIpConfig
from distutils.version import LooseVersion
from avocado_cloud.utils.utils_azure import WalaConfig
from avocado_cloud.utils import utils_azure


class NetworkTest(Test):
    """
    :avocado: tags=wala,network
    """

    def setUp(self):
        account = AzureAccount(self.params)
        account.login()
        self.case_short_name = re.findall(r"Test.(.*)", self.name.name)[0]
        self.project = self.params.get("rhel_ver", "*/VM/*")
        if self.case_short_name == "test_connectivity_check" and \
            LooseVersion(self.project) >= LooseVersion("8.0"):
                self.cancel("RHEL-8 doesn't have network service. Skip.")
        if self.case_short_name == "test_verify_dhclient_not_in_waagent_cgroup" and \
            LooseVersion(self.project) >= LooseVersion("10.0"):
                self.cancel("RHEL-10 doesn't have dhclient. Skip")
        cloud = Setup(self.params, self.name)
        self.vm = cloud.vm
        if self.case_short_name == "test_provision_vm_with_multiple_nics":
            self.vm.vm_name += "2nics"
            if self.vm.exists():
                self.vm.delete()
            publicip_name = self.vm.vm_name + "publicip"
            publicip = AzurePublicIP(self.params, name=publicip_name)
            if not publicip.exists():
                publicip.create()
            nic_name_list = []
            for n in range(0, 2):
                nic_name = "{}nic{}".format(self.vm.vm_name, n)
                subnet = self.vm.subnet if n == 0 else self.vm.subnet + str(n)
                n_publicip = publicip_name if n == 0 else None
                nic = AzureNIC(self.params,
                               name=nic_name,
                               subnet=subnet,
                               vnet=self.vm.vnet_name,
                               publicip=n_publicip)
                if not nic.exists():
                    nic.create()
                nic_name_list.append(nic_name)
            self.vm.nics = ' '.join(nic_name_list)
            self.session = cloud.init_session()
            return
        if self.case_short_name == "test_provision_vm_with_sriov_nic":
            self.vm.vm_name += "sriov"
            if self.vm.exists():
                self.vm.delete()
            publicip_name = self.vm.vm_name + "publicip"
            publicip = AzurePublicIP(self.params, name=publicip_name)
            if not publicip.exists():
                publicip.create()
            self.vm.nics = "{}nic".format(self.vm.vm_name)
            nic = AzureNIC(self.params,
                           name=self.vm.nics,
                           subnet=self.vm.subnet,
                           vnet=self.vm.vnet_name,
                           publicip=publicip_name,
                           sriov=True)
            if not nic.exists():
                nic.create()
            self.session = cloud.init_session()
            self.vm.size = "Standard_D3_v2"
            return
        if self.name.name.endswith("test_provision_vm_with_ipv6"):
            self.vm.vm_name += "ipv6"
            # if self.vm.exists():
            #     self.vm.delete()
            publicip_name = self.vm.vm_name + "publicip"
            publicip = AzurePublicIP(self.params,
                                     name=publicip_name)
            if not publicip.exists():
                publicip.create()
            self.vm.nics = "{}nic".format(self.vm.vm_name)
            nic = AzureNIC(self.params,
                           name=self.vm.nics,
                           subnet=self.vm.subnet,
                           vnet=self.vm.vnet_name,
                           publicip=publicip_name)
            if not nic.exists():
                nic.create()
            ipv6_config = AzureNicIpConfig(self.params,
                                           name=self.vm.nics+"ipv6",
                                           nic_name=self.vm.nics,
                                           ip_version="IPv6")
            if not ipv6_config.exists():
                ipv6_config.create()
            self.session = cloud.init_session()
            return
        self.session = cloud.init_vm()
        self.session.cmd_output("sudo su -")
        self.username = self.vm.vm_username

        # Should disable auto update to verify the function in the current version
        if self.case_short_name in [
                "test_change_hostname_check_dns", "test_nmcli_change_hostname",
                "test_kill_exthandler_change_hostname",
                "test_change_hostname_several_times"
        ]:
            self.session.cmd_output("sudo /usr/bin/cp /etc/waagent.conf{,-bak}")
            walaconfig = WalaConfig(self.session)
            walaconfig.modify_value("AutoUpdate.Enabled", "n")
            status, output = walaconfig.verify_value("AutoUpdate.Enabled", "n")
            self.assertEqual(status, 0, output)
            del status, output
            self.session.cmd_output("systemctl restart waagent;sleep 10")

    def test_connectivity_check(self):
        """
        :avocado: tags=tier2
        Check network service connectivity
        """
        self.log.info("Network services connectivity check")
        network_status = """\
Currently active devices:
lo eth0\
"""
        self.assertIn(network_status,
                      self.session.cmd_output("service network status"),
                      "Network service status check failed")
        self.assertIn("RUNNING", self.session.cmd_output("ifconfig eth0"),
                      "Eth0 status is wrong.")

    def test_check_dns(self):
        """
        :avocado: tags=tier1
        Check DNS
        """
        self.log.info("Check DNS")
        if self.project.split('.')[0] < 9:
            self.assertIn(".internal.cloudapp.net",
                        self.session.cmd_output("hostname -f"),
                        "Cannot get whole FQDN")
        else:
            self.log.info("For RHEL-{}, skip checking hostname -f".format(self.project))
        self.assertNotIn(
            "NXDOMAIN",
            self.session.cmd_output("nslookup {0}".format(self.vm.vm_name)),
            "Fail to publish hostname to DNS")

    def test_change_hostname_check_dns(self):
        """
        :avocado: tags=tier1
        Check if change hostname can change DNS
        """
        self.log.info("Check if change hostname can change DNS")
        # Change hostname
        old_hostname = self.vm.vm_name
        new_hostname = self.vm.vm_name + "new"
        if LooseVersion(self.project) < LooseVersion("7.0"):
            self.session.cmd_output("hostname {0}".format(new_hostname))
        else:
            self.session.cmd_output(
                "hostnamectl set-hostname {0}".format(new_hostname))
        time.sleep(40)
        self.assertNotIn(
            "NXDOMAIN",
            self.session.cmd_output("nslookup {0}".format(new_hostname)),
            "New hostname {0} is not in DNS list".format(new_hostname))
        self.assertIn(
            "NXDOMAIN",
            self.session.cmd_output("nslookup {0}".format(old_hostname)),
            "Old hostname {0} should not be in DNS list".format(old_hostname))

    def test_nmcli_change_hostname(self):
        """
        :avocado: tags=tier2
        Check if change hostname can change DNS
        """
        self.log.info("Check if change hostname can change DNS")
        # Change hostname
        old_hostname = self.vm.vm_name
        new_hostname = self.vm.vm_name + "new"
        self.session.cmd_output("nmcli gen hostname {0}".format(new_hostname))
        time.sleep(10)
        # Loop check DNS
        for retry in range(1, 11):
            if "NXDOMAIN" not in self.session.cmd_output("nslookup {0}".format(new_hostname)) and \
               "NXDOMAIN" in self.session.cmd_output("nslookup {0}".format(old_hostname)):
               break
            self.log.debug("Wait for 10s and retry...({}/10)".format(retry))
            time.sleep(10)
        else:
            self.assertNotIn(
                "NXDOMAIN",
                self.session.cmd_output("nslookup {0}".format(new_hostname)),
                "New hostname {0} is not in DNS list".format(new_hostname))
            self.assertIn(
                "NXDOMAIN",
                self.session.cmd_output("nslookup {0}".format(old_hostname)),
                "Old hostname {0} should not be in DNS list".format(old_hostname))

    def _get_pid(self, process_key):
        pid = self.session.cmd_output(
            "ps aux|grep -E '({0})'|grep -v grep|tr -s ' '".format(
                process_key))
        if pid == "":
            return None
        else:
            pid = pid.split(' ')[1]
            self.log.info("PID: {0}".format(pid))
            return pid

    def test_kill_exthandler_change_hostname(self):
        """
        :avocado: tags=tier2
        Kill exthandler and change hostname, check DNS
        """
        self.log.info("Kill exthandler and change hostname, check DNS")
        # Kill -run-exthandlers process
        self.session.cmd_output("kill -9 {0}".format(
            self._get_pid("run-exthandlers")))
        if self._get_pid("run-exthandlers"):
            self.session.cmd_output("kill -9 {0}".format(
                self._get_pid("run-exthandlers")))
        # Change hostname
        old_hostname = self.vm.vm_name
        new_hostname = self.vm.vm_name + "new"
        if LooseVersion(self.project) < LooseVersion("7.0"):
            self.session.cmd_output("hostname {0}".format(new_hostname))
        else:
            self.session.cmd_output(
                "hostnamectl set-hostname {0}".format(new_hostname))
        # Wait for the -run-exthandlers process running
        for retry in range(0, 10):
            time.sleep(10)
            if self._get_pid("run-exthandlers"):
                break
            self.log.debug("Waiting for run-exthandlers start...({}/10)".format(retry+1))
        else:
            self.error("Fail to start waagent -run-exthandlers process")
        # Sleep 15s to wait for waagent publishing hostname
        time.sleep(15)
        # Check DNS
        self.assertNotIn(
            "NXDOMAIN",
            self.session.cmd_output("nslookup {0}".format(new_hostname)),
            "New hostname {0} is not in DNS list".format(new_hostname))
        self.assertIn(
            "NXDOMAIN",
            self.session.cmd_output("nslookup {0}".format(old_hostname)),
            "New hostname {0} should not be in DNS list".format(old_hostname))

    def test_change_hostname_several_times(self):
        """
        :avocado: tags=tier2
        Change hostname several times and check DNS
        """
        self.log.info("Change hostname several times and check DNS")
        old_hostname = self.vm.vm_name
        for num in range(1, 6):
            new_hostname = self.vm.vm_name + str(num)
            if LooseVersion(self.project) < LooseVersion("7.0"):
                self.session.cmd_output("hostname {0}".format(new_hostname))
            else:
                self.session.cmd_output(
                    "hostnamectl set-hostname {0}".format(new_hostname))
            time.sleep(10)
            # Check DNS
            max_retry = 10
            for retry in range(1, max_retry + 1):
                if "NXDOMAIN" not in self.session.cmd_output(
                        "nslookup {0}".format(new_hostname)) and \
                   "NXDOMAIN" in self.session.cmd_output(
                        "nslookup {0}".format(old_hostname)):
                    break
                self.log.debug(
                    "Wait for hostname published... retry {}/{}".format(
                        retry, max_retry))
                time.sleep(5)
            else:
                if "NXDOMAIN" in self.session.cmd_output("nslookup {}".format(new_hostname)):
                    self.log.info("WALA published hostname: " + self.session.cmd_output("cat /var/lib/waagent/published_hostname"))
                    self.log.info("VM hostname: " + self.session.cmd_output("hostname"))
                    self.log.info("Logs:\n" + self.session.cmd_output("tail -100 /var/log/waagent.log"))
                    self.fail("New hostname {} is not in DNS list".format(new_hostname))
                self.assertNotIn(
                    "NXDOMAIN",
                    self.session.cmd_output(
                        "nslookup {0}".format(new_hostname)),
                    "New hostname {0} is not in DNS list".format(new_hostname))
                self.assertIn(
                    "NXDOMAIN",
                    self.session.cmd_output(
                        "nslookup {0}".format(old_hostname)),
                    "New hostname {0} should not be in DNS list".format(
                        old_hostname))
            old_hostname = new_hostname

    def test_provision_vm_with_multiple_nics(self):
        """
        :avocado: tags=tier2
        RHEL-171393	WALA-TC: [Network] Provision VM with multiple NICs
        1. Create a VM with 2 NICs
        2. Check if can provision and connect to the VM successfully
        """
        self.log.info(
            "RHEL-171393	WALA-TC: [Network] Provision VM with multiple NICs")
        self.vm.create()
        self.session.connect(timeout=60)
        vm_ip_list = self.session.cmd_output(
            "ip addr|grep -Po 'inet \\K.*(?=/)'|grep -v '127.0.0.1'").split(
                '\n').sort()
        azure_ip_list = self.vm.properties.get("privateIps").split(',').sort()
        self.assertEqual(
            vm_ip_list, azure_ip_list, "The private IP addresses are wrong.\n"
            "Expect: {}\nReal: {}".format(azure_ip_list, vm_ip_list))

    def test_provision_vm_with_sriov_nic(self):
        """
        :avocado: tags=tier2
        RHEL-171394	WALA-TC: [Network] Provision VM with SR-IOV NIC
        1. Create a VM with 1 SRIOV NIC
        2. Check if can provision and connect to the VM successfully
        """
        self.log.info(
            "RHEL-171394	WALA-TC: [Network] Provision VM with SR-IOV NIC")
        self.vm.create()
        self.session.connect(timeout=60)
        vm_ip = self.session.cmd_output(
            "ip addr|grep -Po 'inet \\K.*(?=/)'|grep -v '127.0.0.1'")
        azure_ip = self.vm.properties.get("privateIps")
        self.assertEqual(
            vm_ip, azure_ip, "The private IP addresses are wrong.\n"
            "Expect: {}\nReal: {}".format(azure_ip, vm_ip))

    def test_provision_vm_with_ipv6(self):
        """
        :avocado: tags=tier2
        RHEL-176199	WALA-TC: [Network] Provision VM with IPv6 address
        1. Create a VM with NIC in IPv6 subnet
        2. Check if can provision and connect to the VM successfully
        3. Restart the VM. Check if this NIC is up and can get ip address
        """
        self.log.info(
            "RHEL-176199 WALA-TC: [Network] Provision VM with IPv6 address")
        # 1. Create a VM with NIC in IPv6 subnet
        self.vm.create()
        self.vm.show()
        self.session.connect(timeout=60)
        self.session.cmd_output("sudo su -")
        # 2. Verify can get IPv6 IP
        # Set IPV6INIT=yes in ifcfg-eth0
        eth0_cfg = "/etc/sysconfig/network-scripts/ifcfg-eth0"
        self.session.cmd_output("sed -i 's/^IPV6INIT=.*/IPV6INIT=yes/;t;$a IPV6INIT=yes' {}".format(eth0_cfg))
        self.session.cmd_output("systemctl restart NetworkManager")
        time.sleep(5)
        azure_ip = self.vm.properties.get("privateIps").split(',')[1]
        vm_ip = self.session.cmd_output(
            "ip addr|grep global|grep -Po 'inet6 \\K.*(?=/)'")
        self.assertEqual(
            vm_ip, azure_ip, "The private IPv6 address is wrong.\n"
            "Expect: {}\nReal: {}".format(azure_ip, vm_ip))
        self.assertEqual(0, self.session.cmd_status_output("ping6 ace:cab:deca::fe -c 1")[0],
                         "Cannot ping6 though vnet")
        # 3. Restart VM
        self.session.close()
        self.vm.reboot()
        time.sleep(10)
        self.session.connect(timeout=60)
        vm_ip_list = self.session.cmd_output(
            "ip addr|grep global|grep -Po 'inet6 \\K.*(?=/)'")
        self.assertEqual(
            vm_ip_list, azure_ip, "The private IPv6 address is wrong after restart.\n"
            "Expect: {}\nReal: {}".format(azure_ip, vm_ip_list))
        time.sleep(10)
        self.assertEqual(0, self.session.cmd_status_output("ping6 ace:cab:deca::fe -c 1")[0],
                         "Cannot ping6 though vnet after restart")

    def test_provision_vm_without_ifcfg(self):
        """
        :avocado: tags=tier2
        RHEL-183385	WALA-TC: [Network] Provision VM without ifcfg file for primary NIC
        1. Create a VM, remove ifcfg-eth0 file
        2. Delete the VM and recreate. Verify if can provision successfully.
        """
        self.log.info(
            'RHEL-183385 WALA-TC: [Network] Provision VM without ifcfg file for primary NIC'
        )
        # Remove ifcfg-eth0 file
        self.session.cmd_output("rm -f /etc/sysconfig/network-scripts/ifcfg-eth0")
        # Delete and recreate the VM
        utils_azure.deprovision(self)
        try:
            self.vm_1, session_1 = utils_azure.recreate_vm(self, "noifcfg")
        except:
            self.fail("#RHEL-40966:Fail to provision VM without ifcfg-eth0")
        self.assertTrue(
            session_1.connect(), "Fail to connect to VM without ifcfg file for primary NIC")

    def test_verify_dhclient_not_in_waagent_cgroup(self):
        """
        :avocado: tags=tier3
        VIRT-83220	WALA-TC: [Network] dhclient is not managed by waagent cgroup
        1. Boot up a VM, ensure NetworkManager uses dhclient as dhcp client. dhclient process exists.
        2. Verify dhclient is not in the waagent CGroup
        """
        self.log.info(
            "VIRT-83220	WALA-TC: [Network] dhclient is not managed by waagent cgroup"
        )
        # 1. Verify dhclient process exists. If not, enable it.
        if self.session.cmd_status_output("ps aux|grep [d]hclient")[0] != 0:
            nm_conf = "/etc/NetworkManager/NetworkManager.conf"
            self.session.cmd_output("cp {} /tmp/".format(nm_conf))
            self.session.cmd_output("sed -i '/\[main\]/a dhcp = dhclient' /etc/NetworkManager/NetworkManager.conf")
            self.session.cmd_output("systemctl restart NetworkManager")
            self.assertEqual(0, self.session.cmd_status_output("ps aux|grep [d]hclient")[0],
                "Cannot start dhclient process.")
        # 2. Verify dhclient is not managered by waagent CGroup
        self.assertNotIn("dhclient", self.session.cmd_output("systemctl status waagent|grep -v '\['"),
            "Should not have dhclient in waagent status output")



    def tearDown(self):
        if self.case_short_name in [
                "test_change_hostname_check_dns", "test_nmcli_change_hostname",
                "test_kill_exthandler_change_hostname",
                "test_change_hostname_several_times"
        ]:
            self.session.cmd_output("hostnamectl set-hostname {}".format(
                self.vm.vm_name))
            self.session.cmd_output(
                "/usr/bin/cp /etc/waagent.conf-bak /etc/waagent.conf")
            self.session.cmd_output("systemctl restart waagent;sleep 10")
        elif self.case_short_name == "test_verify_dhclient_not_in_waagent_cgroup":
            self.session.cmd_output("/usr/bin/cp /tmp/NetworkManager.conf /etc/NetworkManager/")
        elif self.case_short_name in [
                "test_provision_vm_with_multiple_nics",
                "test_provision_vm_with_sriov_nic",
                "test_provision_vm_with_ipv6",
        ]:
            self.vm.delete(wait=False)
        elif self.case_short_name == "test_provision_vm_without_ifcfg":
            self.vm.delete(wait=True)
            self.vm_1.delete(wait=False)


'''
class NetworkTest(Test):

    def setUp(self):
        args = []
        prep = Setup(self.params)
        if not prep.selected_case(self.name):
            self.skip()
        prep.get_vm_params()
        self.project = prep.project
        if "test_nmcli_change_hostname" in self.name.name and \
                self.project < 7.0:
            self.skip("RHEL-7 only")
        prep.login()
        self.wala_version = prep.wala_version
        self.conf_file = prep.conf_file
        self.host_pubkey_file = prep.host_pubkey_file
        self.vm = prep.vm
        self.vm_params = prep.vm_params
        if "test_check_dns" in self.name.name:
            self.assertTrue(prep.vm_delete(),
                            "Fail to delete VM before creating.")
        self.assertTrue(prep.vm_create(args=args), "Setup Failed.")

    def test_endpoint_check(self):
        """
        Check the endpoints of the VM
        """
        self.log.info("Check the endpoints of the VM")
        # Check rpcbind
        if "0.0.0.0:111" not in self.session.cmd_output("netstat -antp"):
            self.session.cmd_output("service rpcbind start")
            time.sleep(3)
        self.assertIn("0.0.0.0:111", self.session.cmd_output("netstat -antp"),
                      "rpcbind is not started and listened to 0.0.0.0")
        # install nmap
        if "no nmap" in self.session.cmd_output("which nmap", timeout=5):
            self.session.cmd_output("rpm -ivh /root/RHEL*.rpm")
            self.session.cmd_output("yum -y install nmap")
        # Stop firewall
        if LooseVersion(self.project) < LooseVersion("7.0"):
            self.session.cmd_output("service iptables save")
            self.session.cmd_output("service iptables stop")
        else:
            self.session.cmd_output("systemctl stop firewalld")
        time.sleep(20)
        # Check endpoint
        import re
        inside = re.sub(r'\s+', ' ', 
            self.session.cmd_output("nmap 127.0.0.1 -p 22,111|grep tcp"))
        self.assertIn("22/tcp open ssh", inside,
                      "port 22 is not opened inside")
        self.assertIn("111/tcp open rpcbind", inside,
                      "port 111 is not opened inside")
        outside = re.sub(r'\s+', ' ',
            utils_misc.host_command("nmap %s -p %d,111|grep tcp" %
                                    (self.vm_params["DNSName"],
                                    self.vm_params["PublicPort"])))
        self.assertIn("%d/tcp open" % self.vm_params["PublicPort"], outside,
                      "ssh port should be opened outside")
        self.assertIn("111/tcp filtered", outside,
                      "port 111 shouldn't be opened outside")

    def test_check_dhclient(self):
        """
        Check dhclient status
        """
        self.log.info("Check dhclient status")
        # Check dhclient status
        old_pid = self.vm.get_pid("dhclient")
        self.assertIsNotNone(old_pid,
                             "The dhclient process is not running")
        # Restart waagent check dhclient pid
        self.vm.waagent_service_restart()
        self.assertEqual(self.vm.get_pid("dhclient"), old_pid,
                         "After restarting waagent service, dhclient pid \
should not be changed")
        if LooseVersion(self.project) < LooseVersion("8.0"):
            # Restart network check dhclient pid
            self.session.cmd_output("service network restart",
                                    ignore_status=True)
            time.sleep(5)
            self.vm.verify_alive()
            self.assertNotEqual(self.vm.get_pid("dhclient"), old_pid,
                                "After restarting network service, dhclient \
pid is not changed")
        # else:
        #     # Restart NetworkManager check dhclient pid (RHEL-8 only)
        #     self.session.cmd_output("systemctl restart NetworkManager")
        #     time.sleep(5)
        #     self.assertNotEqual(self.vm.get_pid("dhclient"), old_pid,
        #                        "After restarting NetworkManager, dhclient \
        # pid should be changed")

    def tearDown(self):
        self.log.info("Teardown.")
        if "test_endpoint_check" in self.name.name:
            if LooseVersion(self.project) < LooseVersion("7.0"):
                self.session.cmd_output("service iptables start")
            else:
                self.session.cmd_output("systemctl start firewalld")
        elif "change_hostname" in self.name.name:
            if LooseVersion(self.project) < LooseVersion("7.0"):
                self.session.cmd_output(
                    "hostname {0}".format(self.vm_params["VMName"]))
            else:
                self.session.cmd_output(
                    "hostnamectl set-hostname {0}".format(
                        self.vm_params["VMName"]))
        # Clean ssh sessions
        utils_misc.host_command("ps aux|grep '[s]sh -o UserKnownHostsFile'|\
awk '{print $2}'|xargs kill -9", ignore_status=True)
'''

if __name__ == "__main__":
    main()
