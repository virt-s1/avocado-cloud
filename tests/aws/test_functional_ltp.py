from avocado import Test
from avocado_cloud.app.aws import aws
import time
from avocado_cloud.utils import utils_lib


class LTPRun(Test):
    '''
    :avocado: tags=ltp,acceptance,fulltest
    '''

    def setUp(self):
        self.session = None
        self.vm = None
        self.ssh_wait_timeout = None
        aws.init_test(self)

    def test_ltp_hugemmap(self):
        '''
        :avocado: tags=test_ltp_hugemmap
        polarion_id: RHEL7-88729
        BZ#: 1312331
        '''
        # some a1 instance has not enough memory to run this case, skip them
        black_list = ['a1.large', 'a1.xlarge', 'a1.medium']
        self.session.connect(timeout=self.ssh_wait_timeout)
        mini_mem = self.params.get('memory', '*/instance_types/*')
        if int(mini_mem) < 2:
            self.cancel('Cancel case as low memory')
        cmd = 'sudo lscpu'
        output = aws.run_cmd(self, cmd, expect_ret=0)
        if 'aarch64' in output and int(mini_mem) < 16:
            self.cancel('Cancel case as low memory')
        if self.vm.instance_type in black_list:
            self.cancel("Not enough memory in %s!" % black_list)
        elif self.vm.instance_type.startswith('a1'):
            utils_lib.ltp_run(self, case_name="hugemmap01", file_name="hugetlb")
        else:
            utils_lib.ltp_run(self, file_name="hugetlb")

    def test_ltp_cpuhotplug(self):
        '''
        :avocado: tags=test_ltp_cpuhotplug
        polarion_id: RHEL7-98752
        BZ#: 1464095
        '''
        # ltp will considering fail if more than 1 cpus cannot be offline
        # in bare metal instance
        # but in large metal instances, it is expected. So do not do it in
        # bare metal instances
        aws.run_cmd(self,
                    'lscpu',
                    expect_ret=0,
                    cancel_not_kw="Xen",
                    msg="Not run in xen instance as bug \
            1641510 which is very low priority")
        if 'metal' in self.vm.instance_type:
            self.cancel('Cancel test as bare metal needs 1+ cpus working \
at least which ltp not handle')
        else:
            utils_lib.ltp_run(self, case_name="cpuhotplug")

    def test_ltp_add_key02(self):
        '''
        :avocado: tags=test_ltp_add_key02
        polarion_id: RHEL7-98753
        '''
        utils_lib.ltp_run(self, case_name="add_key02")

    def test_ltp_quickhit(self):
        '''
        :avocado: tags=test_ltp_quickhit
        polarion_id:
        '''
        utils_lib.ltp_run(self,file_name="quickhit")

    def test_ltp_ipsec_icmp(self):
        '''
        :avocado: tags=test_ltp_ipsec_icmp
        polarion_id: RHEL7-98754
        '''
        utils_lib.ltp_run(self, case_name="icmp4-uni-vti11",
                      file_name='net_stress.ipsec_icmp')
        self.log.info("Try to remove ccm module after test.")
        try:
            cmd = 'sudo modprobe -r ccm'
            aws.run_cmd(self, cmd, expect_ret=0)
        except Exception as err:
            aws.handle_exception(self.vm, err)
            self.fail("Got exceptions during test!")

    def tearDown(self):
        if self.session.session.is_responsive(
        ) is not None and self.vm.is_started():
            aws.gcov_get(self)
            aws.get_memleaks(self)
            self.session.close()
