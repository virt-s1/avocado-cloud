from avocado import Test
from avocado_cloud.app.aws import aws
import time
from avocado_cloud.utils import utils_lib


class LTPRun(Test):
    '''
    :avocado: tags=ltp,acceptance,fulltest,fast_check,outposts
    '''

    def setUp(self):
        self.session = None
        self.vm = None
        self.ssh_wait_timeout = None
        aws.init_test(self)
        self.session.connect(timeout=self.ssh_wait_timeout)

    def test_ltp_hugemmap(self):
        '''
        :avocado: tags=test_ltp_hugemmap
        polarion_id: RHEL7-88729
        BZ#: 1312331
        '''
        # some a1 instance has not enough memory to run this case, skip them
        black_list = ['a1.large', 'a1.xlarge', 'a1.medium']
        mini_mem = self.params.get('memory', '*/instance_types/*')
        if int(mini_mem) < 2:
            self.cancel('Cancel case as low memory')
        output = utils_lib.run_cmd(self, 'sudo lscpu', expect_ret=0)
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
        case_name = "os_tests.tests.test_ltp.TestLTP.test_ltp_cpuhotplug"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_ltp_add_key02(self):
        '''
        :avocado: tags=test_ltp_add_key02
        polarion_id: RHEL7-98753
        BZ#: 1464851
        '''
        case_name = "os_tests.tests.test_ltp.TestLTP.test_ltp_add_key02"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_ltp_quickhit(self):
        '''
        :avocado: tags=test_ltp_quickhit
        polarion_id:
        '''
        case_name = "os_tests.tests.test_ltp.TestLTP.test_ltp_quickhit"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_ltp_ipsec_icmp(self):
        '''
        :avocado: tags=test_ltp_ipsec_icmp
        polarion_id: RHEL7-98754
        '''
        case_name = "os_tests.tests.test_ltp.TestLTP.test_ltp_ipsec_icmp"
        utils_lib.run_os_tests(self, case_name=case_name)

    def tearDown(self):
        aws.done_test(self)
        if self.vm.is_created:
            if self.session.session.is_responsive(
            ) is not None and self.vm.is_started():
                aws.gcov_get(self)
                aws.get_memleaks(self)
                self.session.close()
