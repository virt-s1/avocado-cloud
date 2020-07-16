from avocado import Test
from avocado_cloud.app.aws import aws
from avocado_cloud.app.aws import NetworkInterface
import time
import decimal
import re
from avocado_cloud.utils import utils_lib


class NetworkTest(Test):
    '''
    :avocado: tags=network,acceptance,fulltest
    '''
    def _compare_num(self, num1, num2, expect_ratio, msg=None):
        act_ratio = 100 - decimal.Decimal(num1) / decimal.Decimal(num2) * 100
        self.assertGreaterEqual(
            expect_ratio,
            act_ratio,
            msg="%s perf result diff ratio over expect %s, actual %s" %
            (msg, expect_ratio, act_ratio))
        self.log.info(
            "%s perf result diff ratio is within expect %s, actual %s" %
            (msg, expect_ratio, act_ratio))

    def _iperf3_test(self):
        '''
        Run iperf3 test between two vms, for now, we only use iperf3 to make
        sure there is no exceptions during test. About detail performance
        evaluatation, we are doing it in other thread. Plan to import
        performance evaluatation later.
        '''
        iperf3_install = "sudo yum install -y iperf3"
        iperf3_server = "sudo iperf3 -s"
        self.log.info("vm2 iperf server private ip is %s" %
                      self.vm2.priviate_ip)
        iperf3_client = "sudo iperf3 -P 10 -c %s " % self.vm2.priviate_ip

        self.log.info("Install iperf3 on vm1 and vm2")
        output = self.session1.cmd_output(iperf3_install,
                                          timeout=self.ssh_wait_timeout)
        self.log.info("Installation output vm1 %s %s" %
                      (self.vm1.instance_id, output))
        output = self.session2.cmd_output(iperf3_install,
                                          timeout=self.ssh_wait_timeout)
        self.log.info("Installation output vm2 %s %s" %
                      (self.vm2.instance_id, output))

        self.log.info("Start iperf3 server on vm2 %s" % self.vm2.instance_id)
        # output = self.session2.cmd_output(
        #    iperf3_server, timeout=self.ssh_wait_timeout)
        self.log.info("CMD: %s" % iperf3_server)
        self.session2.session.sendline(iperf3_server)
        time.sleep(10)
        # if output == None:
        #    self.fail("Failed to start iperf3 server on vm2!")
        # else:
        #    self.log.info("Start iperf3 server on vm2 successfully!")

        self.log.info("Start iperf3 test on vm1 %s" % self.vm1.instance_id)
        self.log.info("CMD: %s" % iperf3_client)
        status, output = self.session1.cmd_status_output(
            iperf3_client, timeout=self.ssh_wait_timeout)
        if status == 0:
            self.log.info(
                "Start iperf3 test on vm1 successfully! \n Result: %s " %
                output)
        else:
            self.fail("Failed to run iperf3 test on vm1! \n Result: %s " %
                      output)
        for line in output.split("\n"):
            if 'sender' in line and 'SUM' in line:
                sender_ipv4 = line.split(' ')[line.split(' ').index('sec') + 5]
            elif 'receiver' in line and 'SUM' in line:
                receiver_ipv4 = line.split(' ')[line.split(' ').index('sec') +
                                                5]
        # read expected perf result from official annonce
        # 0 means moderate and will not check whether it is expected.
        # if it is lower than 30%, consider it as fail.
        expect_perf = self.params.get('net_perf', "*/instance_types/*")
        expect_ratio = 30
        if expect_perf == 0:
            self.log.info(
                "Network performance is moderate, no need to compare result!")
        else:
            self._compare_num(sender_ipv4,
                              expect_perf,
                              expect_ratio,
                              msg="Sender")
            self._compare_num(receiver_ipv4,
                              expect_perf,
                              expect_ratio,
                              msg="Receiver")

        return output

    def setUp(self):
        self.session = None
        self.session1 = None
        self.session2 = None
        self.vm = None
        self.vm1 = None
        self.vm2 = None
        self.snap = None

        self.ssh_wait_timeout = None
        aws.init_test(self, instance_index=0)
        self.vm1 = self.vm
        self.session1 = self.session
        if self.name.name.endswith("test_iperf_ipv4"):
            self.log.info("2 Nodes needed!")
            aws.init_test(self, instance_index=1)
            self.vm2 = self.vm
            self.session2 = self.session
        else:
            self.log.info("1 Node needed!")

    def test_mtu_min_set(self):
        '''
        :avocado: tags=test_mtu_min_set,fast_check
        polarion_id: RHEL-111097
        ena mtu range: 128~9216
        ixgbevf mtu range: 68~9710
        vif mtu range: 68~65535
        '''
        self.session1.connect(timeout=self.ssh_wait_timeout)
        self.session = self.session1
        aws.check_session(self)
        cmd = "sudo ethtool -i eth0"
        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        if 'ena' in output:
            self.log.info('ena found!')
            mtu_range = [0, 127, 128, 4500, 9216, 9217]
            mtu_min = 128
            mtu_max = 9216
        elif 'ixgbe' in output:
            self.log.info('ixgbevf found!')
            mtu_range = [0, 67, 68, 4500, 9710, 9711]
            mtu_min = 68
            mtu_max = 9710
        elif 'vif' in output:
            self.log.info('vif found!')
            mtu_range = [0, 67, 68, 4500, 65535, 65536]
            mtu_min = 68
            mtu_max = 65535
        else:
            self.fail('Did not detect network type! %s' % output)

        self.log.info("Trying to change mtu to %s" % mtu_range)
        for mtu_size in mtu_range:
            mtu_cmd = "sudo ip link set dev eth0 mtu %s" % mtu_size
            mtu_check = "sudo ip link show dev eth0"
            self.log.info("CMD: %s" % mtu_cmd)
            status, output = self.session1.cmd_status_output(mtu_cmd)
            if mtu_size <= mtu_max and mtu_size >= mtu_min:
                self.assertEqual(status,
                                 0,
                                 msg='Change mtu size failed! %s' % output)
            elif mtu_size < mtu_min or mtu_size > mtu_max:
                self.assertGreater(
                    status,
                    0,
                    msg='Change mtu size successfully which should not! %s' %
                    output)

            status, output = self.session1.cmd_status_output(mtu_check)
            self.log.info("After set mtu size %s \n %s " % (mtu_size, output))

    def test_iperf_ipv4(self):
        '''
        :avocado: tags=test_iperf_ipv4
        polarion_id:
        For now, we only run iperf test and did not compare result with
        standard. If there is big gap, please manuall run inside the same
        placement group.
        '''
        self.session1.connect(timeout=self.ssh_wait_timeout)
        self.session = self.session1
        aws.check_session(self)
        perf_spec = self.params.get('net_perf', '*/instance_types/*')
        if int(perf_spec) > 40:
            self.cancel('Cancel case as iperf3 is not suitable for \
bandwidth higher than 40G')
        self._iperf3_test()

    def test_sriov_ixbgevf(self):
        '''
        :avocado: tags=test_sriov_ixbgevf,fast_check
        polarion_id: RHEL7-87119
        '''
        self.session1.connect(timeout=self.ssh_wait_timeout)
        if not self.name.name.endswith("test_cleanup"):
            self.session = self.session1
            aws.check_session(self)
        eth_cmd = "ethtool -i eth0"
        if self.params.get('ixgbevf', '*/instance_types/*') > 0:
            self.log.info("Configure shows this instance supports ixgbevf")
        else:
            utils_lib.run_cmd(self, eth_cmd, expect_ret=0, cancel_kw='ixgbevf')

        self.log.info("Trying to check sriov ixbgevf interface!")

        mod_cmd = "modinfo ixgbevf"

        self.log.info("Get eth0 module infomation: %s" % self.vm1.instance_id)
        status, output = self.session1.cmd_status_output(eth_cmd)
        if status > 0:
            self.fail("Failed to check eth0 status: cmd : %s output:%s" %
                      (eth_cmd, output))
        elif status == 0:
            if 'ixgbevf' in output:
                self.log.info("eth0 has ixgbevf loaded. cmd: %s result: %s" %
                              (eth_cmd, output))
            else:
                self.fail(
                    "eth0 does not have ixgbevf loaded. cmd : %s result:%s" %
                    (eth_cmd, output))
        self.log.info("Get ixgbevf module infomation: %s" %
                      self.vm1.instance_id)
        status, output = self.session1.cmd_status_output(mod_cmd)
        if status > 0:
            self.fail(
                "Failed to get ixgbevf module information: cmd : %s result:%s"
                % (eth_cmd, output))
        elif status == 0:
            self.log.info("Below is ixgbevf information. cmd: %s result: %s" %
                          (eth_cmd, output))

    def test_sriov_ena(self):
        '''
        :avocado: tags=test_sriov_ena,fast_check
        polarion_id: RHEL7-87117
        '''
        self.session1.connect(timeout=self.ssh_wait_timeout)
        self.session = self.session1
        aws.check_session(self)
        eth_cmd = "ethtool -i eth0"
        if self.params.get('ena', '*/instance_types/*') > 0:
            self.log.info("Configure shows this instance supports ena")
        else:
            utils_lib.run_cmd(self, eth_cmd, expect_ret=0, cancel_kw='ena')

        self.log.info("Trying to check sriov ena interface!")

        mod_cmd = "modinfo ena"

        self.log.info("Get eth0 module infomation: %s" % self.vm1.instance_id)
        status, output = self.session1.cmd_status_output(eth_cmd)
        if status > 0:
            self.fail("Failed to check eth0 status: cmd : %s output:%s" %
                      (eth_cmd, output))
        elif status == 0:
            if 'ena' in output:
                self.log.info("eth0 has ena loaded. cmd: %s result: %s" %
                              (eth_cmd, output))
            else:
                self.fail("eth0 does not have ena loaded. cmd : %s result:%s" %
                          (eth_cmd, output))
        self.log.info("Get ena module infomation: %s" % self.vm1.instance_id)
        status, output = self.session1.cmd_status_output(mod_cmd)
        if status > 0:
            self.fail(
                "Failed to get ena module information: cmd : %s result:%s" %
                (eth_cmd, output))
        elif status == 0:
            self.log.info("Below is ena information. cmd: %s result: %s" %
                          (eth_cmd, output))

    def test_sriov_ena_dmesg(self):
        '''
        :avocado: tags=test_sriov_ena_dmesg,fast_check
        polarion_id:
        '''
        self.session1.connect(timeout=self.ssh_wait_timeout)
        self.session = self.session1
        aws.check_session(self)
        cmd = "ethtool -i eth0"
        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        if "driver: ena" not in output:
            self.cancel("No ena driver found!")
        self.log.info("Trying to check sriov ena boot messages!")
        aws.check_dmesg(self, 'ena', match_word_exact=True)

    def test_sriov_ena_unload_load(self):
        '''
        :avocado: tags=test_sriov_ena_unload_load,fast_check
        polarion_id:
        '''
        self.log.info("Test unload and load ena module")
        self.session1.connect(timeout=self.ssh_wait_timeout)
        self.session = self.session1
        aws.check_session(self)
        cmd_string = 'modprobe -r ena;modprobe ena'
        cmd = 'sudo echo "%s" >/tmp/mod.sh' % cmd_string
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = 'sudo chmod 755 /tmp/mod.sh'
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = 'sudo su'
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = '/tmp/mod.sh'
        utils_lib.run_cmd(self, cmd, expect_ret=0)

        aws.check_dmesg(self, 'ena', match_word_exact=True)

    def test_xen_netfront_unload_load(self):
        '''
        :avocado: tags=test_xen_netfront_unload_load,fast_check
        polarion_id:
        '''
        self.log.info("Test unload and load xen_netfront module")
        self.session1.connect(timeout=self.ssh_wait_timeout)
        self.session = self.session1
        cmd = 'sudo ethtool -i eth0'
        output = utils_lib.run_cmd(self, cmd, msg='Check network driver!')
        if 'driver: vif' not in output:
            self.cancel('No xen_netfront used!')
        aws.check_session(self)
        cmd_string = 'modprobe -r xen_netfront;modprobe xen_netfront'
        cmd = 'sudo echo "%s" >/tmp/mod.sh' % cmd_string
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = 'sudo chmod 755 /tmp/mod.sh'
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = 'sudo su'
        utils_lib.run_cmd(self, cmd, expect_ret=0)
        cmd = '/tmp/mod.sh'
        utils_lib.run_cmd(self, cmd, expect_ret=0)

        aws.check_dmesg(self, 'ena', match_word_exact=True)

    def test_pci_reset(self):
        '''
        :avocado: tags=test_pci_reset
        polarion_id:
        '''
        self.session1.connect(timeout=self.ssh_wait_timeout)
        self.session = self.session1
        cmd = 'sudo lspci'
        utils_lib.run_cmd(self, cmd)
        self.cancel('Cancel this case as bug 1687330 which is TESTONLY!')
        cmd = 'sudo find /sys -name reset* -type f|grep pci'
        output = utils_lib.run_cmd(self, cmd)
        if 'reset' not in output:
            self.cancel("No pci support reset!")
        for pci_reset in output.split('\n'):
            cmd = 'sudo su'
            utils_lib.run_cmd(self, cmd)
            cmd = 'echo 1 > %s' % pci_reset
            utils_lib.run_cmd(self, cmd, expect_ret=0, timeout=120)
        aws.check_dmesg(self, 'fail')
        aws.check_dmesg(self, 'error')
        aws.check_dmesg(self, 'warn')
        cmd = 'dmesg'
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='Call Trace')

    def test_ethtool_C_coalesce(self):
        '''
        :avocado: tags=test_ethtool_C_coalesce,fast_check
        polarion_id:
        '''
        self.session1.connect(timeout=self.ssh_wait_timeout)
        self.session = self.session1
        aws.check_session(self)
        cmd = ' sudo  ethtool -c eth0'
        utils_lib.run_cmd(self, cmd, msg='Show current settings.')
        cmd = "ethtool -C eth0  rx-usecs 3"
        output = utils_lib.run_cmd(self, cmd)
        if "Operation not supported" in output:
            self.cancel("Operation not supported!")
        if "Operation not permitted" in output:
            self.cancel("Operation not permitted")
        self.log.info("Trying to change coalesce")
        coalesce_list = [
            'stats-block-usecs', 'sample-interval', 'pkt-rate-low',
            'pkt-rate-high', 'rx-usecs', 'rx-frames', 'rx-usecs-irq',
            'rx-frames-irq', 'tx-usecs', 'tx-frames', 'tx-usecs-irq',
            'tx-frames-irq', 'rx-usecs-low', 'rx-frame-low', 'tx-usecs-low',
            'tx-frame-low', 'rx-usecs-high', 'rx-frame-high', 'tx-usecs-high',
            'tx-frame-high'
        ]

        for coalesce in coalesce_list:
            cmd = 'sudo ethtool -C eth0 %s 2' % coalesce
            utils_lib.run_cmd(self, cmd, expect_ret=0)
            cmd = 'sudo  ethtool -c eth0'
            utils_lib.run_cmd(self, cmd, expect_kw="%s: 2" % coalesce)
        cmd = 'dmesg|tail -20'
        utils_lib.run_cmd(self, cmd)

    def test_ethtool_G(self):
        '''
        :avocado: tags=test_ethtool_G,fast_check
        polarion_id:
        bz#: 1722628
        '''
        self.session1.connect(timeout=self.ssh_wait_timeout)
        self.session = self.session1
        aws.check_session(self)
        utils_lib.run_cmd(self,
                    'ethtool -i eth0|grep driver',
                    msg='Check network is ENA',
                    cancel_kw='ena')
        utils_lib.run_cmd(self,
                    'ethtool -i eth0',
                    msg='Check ENA driver version',
                    cancel_not_kw='version: 2.0')
        self.log.info("Test change rx/tx ring setting.")
        cmd = "ethtool -g eth0"
        utils_lib.run_cmd(self, cmd, msg='Display setting before changing it.')
        cmd = "ethtool -g eth0|grep RX|head -1"
        output = utils_lib.run_cmd(self, cmd, msg='Get max rx set')
        rx_max = output.split('\t')[-1]
        lower_list = [1, 0, 25, 255]
        for i in lower_list:
            cmd = "sudo ethtool -G eth0 rx %s tx %s" % (i, i)
            utils_lib.run_cmd(self, cmd, msg='Change rx,tx setting to lower %s' % i)
            utils_lib.run_cmd(self,
                        "ethtool -g eth0",
                        msg='After changed %s' % i,
                        expect_kw='RX:\t\t256,TX:\t\t256')

        cmd = "sudo ethtool -G eth0 rx -1 tx -1"
        utils_lib.run_cmd(self, cmd, msg='Change rx,tx setting to lower -1')
        utils_lib.run_cmd(self,
                    "ethtool -g eth0",
                    msg='After changed -1',
                    expect_kw='RX:\t\t256,TX:\t\t256')
        cmd = "sudo ethtool -G eth0 rx 512 tx 512"
        utils_lib.run_cmd(self, cmd, msg='Change rx,tx setting to 512')
        utils_lib.run_cmd(self,
                    "ethtool -g eth0",
                    msg='After changed 512',
                    expect_kw='RX:\t\t512,TX:\t\t512')

        cmd = "sudo ethtool -G eth0 rx %s tx 1024" % rx_max
        utils_lib.run_cmd(self,
                    cmd,
                    msg='Change rx setting to %s, tx to 1024' % rx_max)
        utils_lib.run_cmd(self,
                    "ethtool -g eth0",
                    msg='After changed rx setting to %s, tx to 1024' % rx_max,
                    expect_kw='RX:\t\t%s,TX:\t\t1024' % rx_max)

        cmd = "sudo ethtool -G eth0 rx 10240 tx 1025"
        utils_lib.run_cmd(self, cmd, msg='Change rx setting to 10240,tx to 1025')
        utils_lib.run_cmd(self,
                    "ethtool -g eth0",
                    msg='After changed rx setting to %s,tx to 1025' % rx_max,
                    expect_kw='RX:\t\t%s,TX:\t\t1024' % rx_max)
        utils_lib.run_cmd(self, 'dmesg|tail -20')

    def test_ethtool_K_offload(self):
        '''
        :avocado: tags=test_ethtool_K_offload,fast_check
        polarion_id:
        '''
        self.session1.connect(timeout=self.ssh_wait_timeout)
        self.session = self.session1
        aws.check_session(self)
        cmd = ' sudo  ethtool -k eth0'
        utils_lib.run_cmd(self, cmd, msg='Show current settings.')
        cmd = 'sudo ethtool -i eth0'
        output = utils_lib.run_cmd(self, cmd, msg='Check network driver!')
        if 'driver: ena' in output:
            option_dict = {
                'tx': 'tx-checksumming',
                'sg': 'scatter-gather',
                'gso': 'generic-segmentation-offload',
                'gro': 'generic-receive-offload',
                'tx-nocache-copy': 'tx-nocache-copy',
                'rxhash': 'receive-hashing',
                'highdma': 'highdma'
            }
        elif 'driver: vif' in output:
            option_dict = {
                'sg': 'scatter-gather',
                'tso': 'tcp-segmentation-offload',
                'gso': 'generic-segmentation-offload',
                'gro': 'generic-receive-offload',
                'tx-nocache-copy': 'tx-nocache-copy'
            }
        else:
            option_dict = {
                'rx': 'rx-checksumming',
                'tx': 'tx-checksumming',
                'sg': 'scatter-gather',
                'tso': 'tcp-segmentation-offload',
                'gso': 'generic-segmentation-offload',
                'gro': 'generic-receive-offload',
                'tx-gre-segmentation': 'tx-gre-segmentation',
                'tx-nocache-copy': 'tx-nocache-copy',
                'tx-ipip-segmentation': 'tx-ipip-segmentation',
                'tx-sit-segmentation': 'tx-sit-segmentation',
                'tx-udp_tnl-segmentation': 'tx-udp_tnl-segmentation',
                'tx-gre-csum-segmentation': 'tx-gre-csum-segmentation',
                'tx-udp_tnl-csum-segmentation': 'tx-udp_tnl-csum-segmentation',
                'tx-gso-partial': 'tx-gso-partial'
            }

        for option in option_dict.keys():
            cmd = 'sudo ethtool -K eth0 %s off' % option
            utils_lib.run_cmd(self, cmd)
            cmd = 'sudo ethtool -k eth0'
            utils_lib.run_cmd(self, cmd, expect_kw="%s: off" % option_dict[option])
            cmd = 'sudo ethtool -K eth0 %s on' % option
            utils_lib.run_cmd(self, cmd, expect_ret=0)
            cmd = 'sudo ethtool -k eth0'
            utils_lib.run_cmd(self, cmd, expect_kw="%s: on" % option_dict[option])

        cmd = 'dmesg|tail -20'
        utils_lib.run_cmd(self, cmd)
        aws.check_dmesg(self, 'fail')
        aws.check_dmesg(self, 'error')
        aws.check_dmesg(self, 'warn')
        cmd = 'dmesg'
        utils_lib.run_cmd(self, cmd, expect_ret=0, expect_not_kw='Call Trace')

    def test_ethtool_s_msglvl(self):
        '''
        :avocado: tags=test_ethtool_s_msglvl,fast_check
        polarion_id:
        '''
        self.session1.connect(timeout=self.ssh_wait_timeout)
        self.session = self.session1
        aws.check_session(self)
        cmd = "ethtool eth0"
        output = utils_lib.run_cmd(self, cmd, expect_ret=0)
        if "Current message level" not in output:
            self.cancel("Operation not supported!")
        self.log.info("Trying to change msglvl")
        msglvl_list = [
            'drv', 'probe', 'link', 'timer', 'ifdown', 'ifup', 'rx_err',
            'tx_err', 'tx_queued', 'intr', 'tx_done', 'rx_status', 'pktdata',
            'hw', 'wol'
        ]
        cmd = 'sudo  ethtool -s eth0 msglvl 0'
        utils_lib.run_cmd(self, cmd, msg='Disable all msglvl for now!')
        for msglvl in msglvl_list:
            cmd = 'sudo ethtool -s eth0 msglvl %s on' % msglvl
            utils_lib.run_cmd(self, cmd, expect_ret=0)
            cmd = "sudo ethtool eth0"
            utils_lib.run_cmd(self, cmd, expect_kw=msglvl)

        for msglvl in msglvl_list:
            cmd = 'sudo ethtool -s eth0 msglvl %s off' % msglvl
            utils_lib.run_cmd(self, cmd, expect_ret=0)
            cmd = "sudo ethtool eth0|grep -v 'link modes'"
            utils_lib.run_cmd(self, cmd, expect_not_kw=msglvl)
        cmd = 'dmesg|tail -20'
        utils_lib.run_cmd(self, cmd)

    def test_ethtool_X(self):
        '''
        :avocado: tags=test_ethtool_X,fast_check
        polarion_id:
        '''
        self.session1.connect(timeout=self.ssh_wait_timeout)
        self.session = self.session1
        aws.check_session(self)
        self.log.info("Test change rxfh setting.")
        cmd = "ethtool -x eth0"
        utils_lib.run_cmd(self, cmd, msg='Display setting before changing it.')
        cmd = "ethtool -X eth0 default"
        output = utils_lib.run_cmd(self, cmd)
        if "Operation not supported" in output:
            self.cancel("Operation not supported!")
        self.log.info("As bug 1693098, will not check return value for now.")
        # utils_lib.run_cmd(self, cmd, expect_ret=0,msg='Try to set rxfh with \
        # -X option.')
        utils_lib.run_cmd(self, cmd, msg='Try to set rxfh with -X option.')
        cmd = "ethtool -x eth0"
        utils_lib.run_cmd(self, cmd, msg='Display setting after changed it.')

    def test_ethtool_P(self):
        '''
        :avocado: tags=test_ethtool_P,fast_check
        polarion_id:
        bug_id: 1704435
        Assertion: Can read mac address successfully
        '''
        self.session1.connect(timeout=self.ssh_wait_timeout)
        self.session = self.session1
        aws.check_session(self)
        cmd = "ethtool -P eth0"
        output = utils_lib.run_cmd(self,
                             cmd,
                             expect_not_kw='00:00:00:00:00:00',
                             msg='ethtool can read mac successfully')
        mac = ''.join(
            re.findall(
                '[0-9a-z]{2}:[0-9a-z]{2}:[0-9a-z]{2}:[0-9a-z]{2}:\
[0-9a-z]{2}:[0-9a-z]{2}', output))
        self.log.info("Get mac: %s" % mac)
        cmd = "ip addr show eth0"
        output = utils_lib.run_cmd(self,
                             cmd,
                             expect_kw=mac,
                             msg='compare with ip showed mac')

    def test_network_hotplug(self):
        '''
        :avocado: tags=test_network_hotplug,fast_check
        polarion_id: RHEL7-103904
        '''
        self.network = NetworkInterface(self.params)
        self.assertTrue(self.network.create(),
                        msg='network interface create failed!')
        self.session1.connect(timeout=self.ssh_wait_timeout)
        self.session = self.session1
        netdev_index = 1
        self.network.attach_to_instance(self.vm1.instance_id, netdev_index)
        for i in range(1, 4):
            time.sleep(5)
            self.log.info('Check network in guest, loop%s' % i)
            cmd = "lspci"
            output1 = utils_lib.run_cmd(self, cmd)
            cmd = "ifconfig"
            output1 = utils_lib.run_cmd(self, cmd)
            if 'eth%s' % netdev_index not in output1:
                self.log.info("Added nic not found")
        self.network.detach_from_instance(self.vm1.instance_id)
        time.sleep(5)
        cmd = "ifconfig"
        utils_lib.run_cmd(self, cmd)
        self.network.delete()
        self.assertIn('eth%d' % netdev_index,
                      output1,
                      msg='eth%d not found after attached nic' % netdev_index)
        cmd = 'dmesg'
        utils_lib.run_cmd(self, cmd, expect_not_kw='Call Trace')

    def tearDown(self):

        self.session = self.session1
        if self.session.session.is_responsive(
        ) is not None and self.vm1.is_started():
            if self.name.name.endswith("test_pci_reset"):
                cmd = 'sudo dmesg --clear'
                utils_lib.run_cmd(self, cmd, msg='Clear dmesg')
            aws.gcov_get(self)
            aws.get_memleaks(self)
            self.session.close()
        self.session1.close()
        if self.name.name.endswith("test_iperf_ipv4"):
            self.session2.close()
