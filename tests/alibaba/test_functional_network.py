from avocado import Test
from avocado_cloud.app import Setup
import os
import time


class NetworkTest(Test):
    def setUp(self):
        self.cloud = Setup(self.params, self.name)
        self.vm = self.cloud.vm
        self.pwd = os.path.abspath(os.path.dirname(__file__))
        pre_delete = False
        pre_stop = False
        if self.name.name.endswith("test_coldplug_nics"):
            pre_stop = True
        if not self.vm.nic_count or self.vm.nic_count < 2:
            self.cancel("No nic count. Skip this case.")
        self.session = self.cloud.init_vm(pre_delete=pre_delete,
                                          pre_stop=pre_stop)
        if self.name.name.endswith("test_hotplug_nics") or \
            self.name.name.endswith("test_coldplug_nics") or \
            self.name.name.endswith("test_assign_unassign_secondary_private_ips"):
                self.cloud.init_nics(self.vm.nic_count)
                self.primary_nic_id = self.cloud.primary_nic_id

    def test_hotplug_nics(self):
        """Test case for avocado framework.

        case_name:
            [Aliyun]NetworkTest.test_hotplug_nics
        description:
            Test case for hotplug NICs.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]NetworkTest.test_hotplug_nics"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Start VM. Attach max NICs and check all can get IP;
            2. Add one more NIC. Should not be added;
            3. Detach all NICs. Device should be removed inside guest;
        pass_criteria:
            All the functionality works well.
        """

        # Notice: Some of instance types are not support Hot Plug NIC
        # https://help.aliyun.com/document_detail/25378.html

        unsupport_instance_types = [
            'ecs.t6-c1m1.large',
            'ecs.t6-c1m2.large',
            'ecs.t6-c1m4.large',
            'ecs.t6-c2m1.large',
            'ecs.t6-c4m1.large',
            'ecs.t5-lc2m1.nano',
            'ecs.t5-c1m1.large',
            'ecs.t5-c1m2.large',
            'ecs.t5-c1m4.large',
            'ecs.t5-lc1m1.small',
            'ecs.t5-lc1m2.large',
            'ecs.t5-lc1m2.small',
            'ecs.t5-lc1m4.large',
            'ecs.s6-c1m1.small',
            'ecs.s6-c1m2.large',
            'ecs.s6-c1m2.small',
            'ecs.s6-c1m4.large',
            'ecs.s6-c1m4.small',
            'ecs.n4.small',
            'ecs.n4.large',
            'ecs.mn4.small',
            'ecs.mn4.large',
            'ecs.e4.small',
            'ecs.e4.large',
        ]

        if self.vm.flavor in unsupport_instance_types:
            self.cancel('Unsupport instance type ({}), skip this case.'.format(
                self.vm.flavor))

        # 1. Attach max NICs and check all can get IP
        count = self.vm.nic_count - 1
        self.log.info("Step 1: Attach %s NICs." % count)
        self.vm.attach_nics(count, wait=True)
        self.assertEqual(len(self.vm.query_nics()), count + 1,
                         "Total NICs number is not %d" % (count + 1))

        guest_path = self.session.cmd_output("echo $HOME") + "/workspace"
        self.session.cmd_output("mkdir -p {0}".format(guest_path))

        self.session.copy_files_to(
            local_path="{0}/../../scripts/aliyun_enable_nics.sh".format(
                self.pwd),
            remote_path=guest_path)

        self.log.info("NIC Count: %s" % count)
        self.session.cmd_output("bash {0}/aliyun_enable_nics.sh {1}".format(
            guest_path, count),
            timeout=180)

        self.session.cmd_output('ip addr', timeout=30)
        time.sleep(60)  # waiting for dhcp works
        self.session.cmd_output('ip addr', timeout=30)

        time.sleep(10)
        outside_ips = [
            str(self.vm.get_private_ip_address(nic))
            for nic in self.vm.query_nics()
        ]
        inside_ips = self.session.cmd_output("ip addr")
        for outside_ip in outside_ips:
            self.assertIn(
                outside_ip, inside_ips, "Some of NICs are not available. "
                "Outside IP: %s Inside IPs:\n %s" % (outside_ip, inside_ips))

        # 2. Add 1 more NIC. Should not be added
        self.log.info("Step 2: Add 1 more NIC, should not be added.")
        self.vm.attach_nics(1)
        self.assertEqual(
            len(self.vm.query_nics()), count + 1,
            "NICs number should not greater than %d" % (count + 1))

        # 3. Detach all NICs. NICs should be removed inside guest
        self.log.info("Step 3: Detach all NICs")

        self.session.copy_files_to(
            local_path="{0}/../../scripts/aliyun_disable_nics.sh".format(
                self.pwd),
            remote_path=guest_path)

        self.log.info("NIC Count: %s" % count)
        self.session.cmd_output("bash {0}/aliyun_disable_nics.sh {1}".format(
            guest_path, count),
            timeout=180)

        nic_ids = [
            self.vm.get_nic_id(nic) for nic in self.vm.query_nics()
            if self.vm.get_nic_id(nic) != self.primary_nic_id
        ]
        self.vm.detach_nics(nic_ids, wait=True)
        self.assertEqual(len(self.vm.query_nics()), 1,
                         "Fail to remove all NICs outside guest")
        time.sleep(5)
        self.assertEqual(
            self.session.cmd_output(
                "ip addr | grep -e 'eth.*mtu' -e 'ens.*mtu' | wc -l"), "1",
            "Fail to remove all NICs inside guest")

        self.log.info("Detach all NICs successfully")

    def test_coldplug_nics(self):
        """Test case for avocado framework.

        case_name:
            [Aliyun]NetworkTest.test_coldplug_nics
        description:
            Test case for coldplug NICs.
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]NetworkTest.test_coldplug_nics"
        maintainer:
            cheshi@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Stop VM. Attach max NICs. Start VM and check all can get IP;
            2. Stop VM. Add 1 more NIC. Should not be added;
            3. Stop VM. Detach all NICs. Device should be removed inside guest;
        pass_criteria:
            All the functionality works well.
        """

        # Set timeout for Alibaba baremetal
        if 'ecs.ebm' in self.vm.flavor:
            connect_timeout = 600
        else:
            connect_timeout = 120

        # 1. Attach max NICs and check all can get IP
        count = self.vm.nic_count - 1
        self.log.info("Step 1: Attach %s NICs." % count)
        self.vm.attach_nics(count, wait=True)
        self.assertEqual(len(self.vm.query_nics()), count + 1,
                         "Total NICs number is not %d" % (count + 1))
        self.vm.start(wait=True)
        self.session.connect(timeout=connect_timeout)

        guest_path = self.session.cmd_output("echo $HOME") + "/workspace"
        self.session.cmd_output("mkdir -p {0}".format(guest_path))

        self.session.copy_files_to(
            local_path="{0}/../../scripts/aliyun_enable_nics.sh".format(
                self.pwd),
            remote_path=guest_path)

        self.log.info("NIC Count: %s" % count)
        self.session.cmd_output("bash {0}/aliyun_enable_nics.sh {1}".format(
            guest_path, count),
            timeout=180)

        time.sleep(10)
        self.session.cmd_output('ip addr', timeout=30)

        outside_ips = [
            self.vm.get_private_ip_address(nic)
            for nic in self.vm.query_nics()
        ]
        inside_ips = self.session.cmd_output("ip addr")
        for outside_ip in outside_ips:
            self.assertIn(
                outside_ip, inside_ips,
                "Some of NICs are not available. Inside IPs: %s" % inside_ips)

        # 2. Add 1 more NIC. Should not be added
        self.log.info("Step 2: Add 1 more NIC, should not be added.")
        self.vm.stop(wait=True)
        self.assertTrue(self.vm.is_stopped(), "Fail to stop VM")
        self.vm.attach_nics(1)
        self.assertEqual(
            len(self.vm.query_nics()), count + 1,
            "NICs number should not greater than %d" % (count + 1))

        # 3. Detach all NICs. NICs should be removed inside guest
        self.log.info("Step 3: Detach all NICs.")
        nic_ids = [
            self.vm.get_nic_id(nic) for nic in self.vm.query_nics()
            if self.vm.get_nic_id(nic) != self.primary_nic_id
        ]
        self.vm.detach_nics(nic_ids, wait=True)
        self.assertEqual(len(self.vm.query_nics()), 1,
                         "Fail to remove all NICs outside guest")
        self.vm.start(wait=True)
        self.assertTrue(self.vm.is_started(), "Fail to start VM")
        self.session.connect(timeout=connect_timeout)
        guest_cmd = "ip addr | grep -e 'eth.*mtu' -e 'ens.*mtu' | wc -l"

        self.assertEqual(self.session.cmd_output(guest_cmd), "1",
                         "Fail to remove all NICs inside guest")
        self.log.info("Detach all NICs successfully")

    def test_assign_unassign_secondary_private_ips(self):
        """Test case for assign and unassign secondary private ip addresses.

        case_name:
            [Aliyun]NetworkTest.test_assign_unassign_secondary_private_ips
        description:
            Test case for assign and unassign secondary private ip addresses
        bugzilla_id:
            n/a
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/\
            RedHatEnterpriseLinux7/workitems?query=title:\
            "[Aliyun]NetworkTest.test_assign_unassign_secondary_private_ips"
        maintainer:
            yoguo@redhat.com
        case_priority:
            0
        case_component:
            checkup
        key_steps:
            1. Assign multiple secondary private ip addresses for primary NIC;
            2. Install the NetworkManger-cloud-setup package and edit the nm-cloud-setup service
            # systemctl edit nm-cloud-setup.service
            [Service]
            Environment=NM_CLOUD_SETUP_ALIYUN=yes
            3. systemctl daemon-reload
            4. Start the nm-cloud-setup service (systemctl start nm-cloud-setup.service)
            5. Check all the ip addresses by 'ip addr show'
            6. Unassign all the secondary private ip addresses
            7. Start the nm-cloud-setup service (systemctl start nm-cloud-setup.service)
            8. Check all the ip addresses by 'ip addr show'(Only primary ip exists)
        pass_criteria:
            All the functionality works well.
        """
        # Assign multiple secondary private ips
        secondary_private_ip_count = 3
        ret = self.vm.assign_secondary_private_ips(self.primary_nic_id, secondary_private_ip_count)
        private_ip_list = ret.get("AssignedPrivateIpAddressesSet").get("PrivateIpSet").get("PrivateIpAddress")
        self.assertEqual(len(private_ip_list), secondary_private_ip_count,
                         "Fail to assign all secondary private ip addresses")

        # Unassign multiple secondary private ips
        self.vm.unassign_secondary_private_ips(self.primary_nic_id, private_ip_list)
        time.sleep(5)

        private_ip_list = []
        for nic in self.vm.query_nics():
            for private_ip_set in nic.get("PrivateIpSets").get("PrivateIpSet"):
                if not private_ip_set.get("Primary"):
                    private_ip_list.append(private_ip_set.get("PrivateIpAddress"))
        self.assertEqual(len(private_ip_list), 0,
                         "Fail to unassign all secondary private ip addresses")

    def tearDown(self):
        if self.name.name.endswith("test_hotplug_nics") or \
           self.name.name.endswith("test_coldplug_nics"):
            guest_cmd = """
primary_nic=$(ifconfig | grep "flags=.*\<UP\>" | cut -d: -f1 | \
grep -e eth -e ens | head -n 1)
device_name=$(echo $primary_nic | tr -d '[:digit:]')
ls /etc/sysconfig/network-scripts/ifcfg-${device_name}* | \
grep -v ${primary_nic} | xargs sudo rm -f
"""
            self.session.cmd_output(guest_cmd, timeout=180)
        self.session.close()
