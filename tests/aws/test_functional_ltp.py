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
        description:
            os-tests Test ltp hugemmap case in RHEL on AWS. Linked case RHEL7-88729.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]LTPRun.test_ltp_hugemmap"
        bugzilla_id: 
            1312331
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            LTP
        key_steps:
            1. Launch an instance on AWS.
            2. Download and install ltp tool from https://github.com/linux-test-project/ltp or download the built rpm package from 
            3. Run hugemmap test with command "$ sudo /opt/ltp/runltp -s hugemmap".
        pass_criteria: 
            System doesn't crash, panic or hang, and tests pass.
        '''
        case_name = "os_tests.tests.test_ltp.TestLTP.test_ltp_hugemmap"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_ltp_cpuhotplug(self):
        '''
        :avocado: tags=test_ltp_cpuhotplug
        description:
            os-tests Test ltp cpuhotplug case in RHEL on AWS. Linked case RHEL7-98752.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]LTPRun.test_ltp_cpuhotplug"
        bugzilla_id: 
            1464095
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            LTP
        key_steps:
            1. Launch an instance on AWS.
            2. Download and install ltp tool from https://github.com/linux-test-project/ltp or download the built rpm package from 
            3. Run ltp cpuhotplug test with command "$ sudo /opt/ltp/runltp -f cpuhotplug".
            4. Also can manual online/offline cpu via command "echo 0 > /sys/devices/system/cpu/cpuN/online".
        pass_criteria: 
            System doesn't crash, panic or hang, and tests pass.
        '''
        # ltp will considering fail if more than 1 cpus cannot be offline
        # in bare metal instance
        # but in large metal instances, it is expected. So do not do it in
        # bare metal instances
        case_name = "os_tests.tests.test_ltp.TestLTP.test_ltp_cpuhotplug"
        utils_lib.run_os_tests(self, case_name=case_name, timeout=600)

    def test_ltp_add_key02(self):
        '''
        :avocado: tags=test_ltp_add_key02
        description:
            os-tests Test ltp cpuhotplug case in RHEL on AWS. Linked case RHEL7-98753.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]LTPRun.test_ltp_add_key02"
        bugzilla_id: 
            1464851
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            LTP
        key_steps:
            1. Launch an instance on AWS.
            2. Download and install ltp tool from https://github.com/linux-test-project/ltp or download the built rpm package from 
            3. Run ltp syscalls test with command "$ sudo /opt/ltp/runltp -f syscalls".
            4. Run test "$ sudo /opt/ltp/runltp -f syscalls -s add_key02".
        pass_criteria: 
            System doesn't crash, panic or hang, and all tests pass.
        '''
        case_name = "os_tests.tests.test_ltp.TestLTP.test_ltp_add_key02"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_ltp_quickhit(self):
        '''
        :avocado: tags=test_ltp_quickhit
        description:
            os-tests Test ltp quickhit case for RHEL on AWS.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]LTPRun.test_ltp_quickhit"
        bugzilla_id: 
            n/a
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority: 
            0
        case_component: 
            LTP
        key_steps:
            1. Launch an instance on AWS.
            2. Download and install ltp tool from https://github.com/linux-test-project/ltp or download the built rpm package from 
            3. Run ltp quickhit test with command "$ sudo /opt/ltp/runltp -f quickhit".
        pass_criteria: 
            System doesn't crash, panic or hang, and tests pass.
        '''
        case_name = "os_tests.tests.test_ltp.TestLTP.test_ltp_quickhit"
        utils_lib.run_os_tests(self, case_name=case_name)

    def test_ltp_ipsec_icmp(self):
        '''
        :avocado: tags=test_ltp_ipsec_icmp
        description:
            os-tests Test ltp ipsec_icmp case in RHEL on AWS. Linked case RHEL7-98754.
        polarion_id:
            https://polarion.engineering.redhat.com/polarion/#/project/RedHatEnterpriseLinux7/workitems?query=title:"[AWS]LTPRun.test_ltp_ipsec_icmp"
        bugzilla_id: 
            1473593
        customer_case_id: 
            n/a
        maintainer: 
            xiliang
        case_priority:
            0
        case_component: 
            LTP
        key_steps:
            1. Launch an instance on AWS.
            2. Download and install ltp tool from https://github.com/linux-test-project/ltp or download the built rpm package from 
            3. Run ltp ipsec_icmp test with command "$ sudo /opt/ltp/runltp -f net_stress.ipsec_icmp -s icmp4-uni-vti11".
            4. Check if ccm module is loaded via command "lsmod | grep ccm".
            5. Remove ccm module via command "modprobe -r ccm".
        pass_criteria: 
            System doesn't crash, panic or hang, and tests pass.
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
