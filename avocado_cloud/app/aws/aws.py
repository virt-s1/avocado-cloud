import logging
import copy
import os
import re
import json
import time
import difflib
import commands
from avocado_cloud.app.aws import EC2Volume
from avocado_cloud.app.aws import EC2VM
from avocado_cloud.app import Setup
from avocado_cloud.utils import utils_lib

LOG = logging.getLogger('avocado.test')
logging.basicConfig(level=logging.DEBUG)


def init_test(test_ins, instance_index=0):
    '''
    Prepare VMs before start test.
    test_ins: Test class instance
    instamce_index: get specified instance
    '''
    cloud = Setup(test_ins.params, test_ins.name)
    test_ins.vm = cloud.vm
    test_ins.snap = None
    test_ins.kdump_status = False
    test_ins.cpu_count = 0
    test_ins.ssh_wait_timeout = set_ssh_wait_timeout(test_ins.vm)

    pre_delete = False
    pre_stop = False
    if test_ins.name.name.endswith(('test_check_firstlaunch_time')):
        pre_delete = True

    test_ins.log.info("Test tempdir: %s" % test_ins.teststmpdir)
    test_ins.vm.instance_id = get_exists_resource_id(
        test_ins.teststmpdir,
        test_ins.vm.instance_type,
        resource_index=instance_index)
    query_resource_blacklist(test_ins)
    if test_ins.vm.instance_id is not None:
        if test_ins.vm.reuse_init(test_ins.vm.instance_id):
            test_ins.log.info("Reuse existing instance %s!" %
                              test_ins.vm.instance_id)
            if pre_delete:
                test_ins.log.info("Test needs no reuse!")
                test_ins.vm.delete(wait=True)
                cleanup_stored(test_ins.teststmpdir,
                               test_ins.params,
                               resource_id=test_ins.vm.instance_id)
                test_ins.vm = None
        else:
            test_ins.log.info(
                "No match existing instance, will create new one!")
            cleanup_stored(test_ins.teststmpdir,
                           test_ins.params,
                           resource_id=test_ins.vm.instance_id)
            pre_delete = True
    if test_ins.name.name.endswith("test_start_vm"):
        pre_stop = True
    if test_ins.name.name.endswith("test_stop_vm_hibernate"):
        pre_delete = True
        test_ins.params['HibernationOptions'] = True
        test_ins.params['EbsEncrypted'] = True
        test_ins.params['EbsVolumeSize'] = 100
    else:
        test_ins.params['HibernationOptions'] = False
        test_ins.params['EbsEncrypted'] = False
        test_ins.params['EbsVolumeSize'] = 10
    if test_ins.vm is None:
        cloud = Setup(test_ins.params, test_ins.name)
        test_ins.vm = cloud.vm
        test_ins.snap = None
        test_ins.kdump_status = False
        test_ins.cpu_count = 0
        test_ins.ssh_wait_timeout = set_ssh_wait_timeout(test_ins.vm)
    test_ins.session = cloud.init_vm(pre_delete=pre_delete, pre_stop=pre_stop)
    # query_resource_blacklist(test_ins)
    test_ins.log.info("Instance id is %s" % test_ins.vm.instance_id)
    save_exists_resource_id(test_ins.teststmpdir, test_ins.vm)
    if test_ins.vm.is_stopped() and not pre_stop:
        if not test_ins.vm.start():
            save_resource_blacklist(test_ins.teststmpdir, test_ins.vm.instance_type)
            test_ins.vm.delete()
            cleanup_stored(test_ins.teststmpdir, test_ins.params, resource_id=test_ins.vm.instance_id)
            test_ins.fail("Cannot start instance")
    if not test_ins.name.name.endswith("test_cleanup") and not pre_stop:
        check_session(test_ins)

def done_test(test_ins):
    if not test_ins.vm.is_created:
        test_ins.log.info("Instance not created, save it to blacklist")
        save_resource_blacklist(test_ins.teststmpdir, test_ins.vm.instance_type)

def save_resource_blacklist(jobdir, resource_type):
    """For skippling test if it cannot make ssh connection

    Arguments:
        jobdir {string} -- [runtime temp dir]
        resource_type {string} -- [resource type]

    Returns:
        False -- saved failed
        True -- saved normally
    """
    save_file = 'resource.json'
    try:
        if os.path.exists("%s/%s" % (jobdir, save_file)):
            with open("%s/%s" % (jobdir, save_file)) as resource_file:
                res_dict = json.load(resource_file)
            if res_dict.has_key('black_list'):
                res_dict['black_list'].append(resource_type)
            elif not res_dict.has_key('black_list'):
                res_dict['black_list'] = [resource_type]
            else:
                LOG.info("%s already in black list!", resource_type)
        else:
            res_dict = {}
            res_dict['black_list'] = [resource_type]
        with open("%s/%s" % (jobdir, save_file), 'w') as resource_file:
            json.dump(res_dict, resource_file, indent=4)
        LOG.info("Resource type saved to blacklist! %s ", resource_type)
        LOG.info(json.dumps(res_dict, indent=4))
        return True

    except Exception as err:
        LOG.info(err)
        return False


def query_resource_blacklist(self):
    """check whether resource type in the black list

    Arguments:
        jobdir {string} -- [runtime temp dir]
        resource_type {string} -- [resource type]

    Returns:
        False -- not in the records
        True -- found in the list
    """
    save_file = 'resource.json'
    resource_type = self.params.get('instance_type')
    jobdir = self.teststmpdir
    if not os.path.exists("%s/%s" % (jobdir, save_file)):
        LOG.info("No %s found!", save_file)
        return False
    if self.name.name.endswith("test_cleanupall"):
        return False
    LOG.info("%s found, try to retrive blacklist!", save_file)
    with open("%s/%s" % (jobdir, save_file), 'r') as resource_file:
        res_dict = json.load(resource_file)
    if not res_dict.has_key('black_list'):
        LOG.info("No black list record found, continue!")
        return False
    if resource_type in res_dict['black_list']:
        LOG.info("%s is in blacklist", resource_type)
        if res_dict['black_list'].count(resource_type) > 4:
            LOG.info(
                "Max allowed time is 4, will not continue test this instance!")
            self.skipTest('%s in black list, skip test!' % resource_type)
            return True
        LOG.info("Max allowed time is 4, will continue test it!")
        if self.vm is not None:
            if self.vm.is_started():
                return check_session(self)

        return False
    LOG.info("No such types resource in black list, continue!")


def remove_resource_blacklist(self):
    """remove this resource type in the black list for counter decrease
    if this instance type is accessible again, reduce one time from list

    Returns:
        False -- not in the records
        True -- removed from the list
    """
    LOG.info("Try to remove one from blacklist if have already in as ssh \
session work")
    save_file = 'resource.json'
    resource_type = self.params.get('instance_type')
    jobdir = self.teststmpdir
    if not os.path.exists("%s/%s" % (jobdir, save_file)):
        LOG.info("No %s found!", save_file)
        return False
    if self.name.name.endswith("test_cleanupall"):
        return False
    LOG.info("%s found, try to retrive blacklist!", save_file)
    with open("%s/%s" % (jobdir, save_file), 'r') as resource_file:
        res_dict = json.load(resource_file)
    if not res_dict.has_key('black_list'):
        LOG.info("No black list record found, continue!")
        return False
    if resource_type in res_dict['black_list']:
        LOG.info("%s is in blacklist", resource_type)
        res_dict['black_list'].remove(resource_type)
        with open("%s/%s" % (jobdir, save_file), 'w') as resource_file:
            json.dump(res_dict, resource_file, indent=4)
            LOG.info("Resource type removed one from blacklist! %s ",
                     resource_type)
            LOG.info(json.dumps(res_dict, indent=4))
    return True


def check_session(self):
    """check whether session is working
    session is <class 'avocado_cloud.app.guest.GuestSession'>
    Not None after login failed, so try to test it via sending a command

    Arguments:
        self {Test instance} -- Test instance

    Returns:
        [True|False] -- [Active/Not work]
    """
    if self.vm.floating_ip is None or len(self.vm.floating_ip) < 2:
       self.fail("No public ip available!")
    self.log.info("func: check_session: timeout %s" % self.ssh_wait_timeout)
    if not self.session.connect(timeout=self.ssh_wait_timeout):
        self.log.error("session connect failed!")
    try:
        utils_lib.run_cmd(self,
                'uname -r',
                expect_ret=0,
                msg='Check whether session is working!')
        remove_resource_blacklist(self)
        return True
    except Exception as e:
        self.log.info("ssh not work, add instance type to blacklist")
        save_resource_blacklist(self.teststmpdir, self.vm.instance_type)
        if not handle_exception(self.vm, e):
            cleanup_stored(self.teststmpdir,
                           self.params,
                           resource_id=self.vm.res_id)
        self.fail('ssh session is not working, fail test')
        return False


def save_exists_resource_id(jobdir, resource):
    '''
    The info will be saved like below:
    vm = {'instance':{"t2-micro": ["instance1", "instance2"]},
    'volume':{"t2-large":["volume1"],'blacklist':['t2.micro']}
    :param jobdir: job runtime temp directory
    :param resource: resource instance
    '''
    save_file = 'resource.json'
    if os.path.exists("%s/%s" % (jobdir, save_file)):
        with open("%s/%s" % (jobdir, save_file), 'r') as resource_file:
            res_dict = json.load(resource_file)
        LOG.info(json.dumps(res_dict, indent=4))
        if res_dict.has_key(resource.res_name) and res_dict.get(
                resource.res_name).has_key(resource.res_type):
            if res_dict.get(resource.res_name).get(resource.res_type).count(
                    resource.res_id) > 0:
                LOG.info("Resource id already exists! %s", resource.res_id)
                return True
            else:
                LOG.info("Resource id is new! %s", resource.res_id)
                res_dict.get(resource.res_name)[resource.res_type].insert(
                    0, resource.res_id)
        elif not res_dict.has_key(resource.res_name):
            res_dict[resource.res_name] = {
                resource.res_type: [resource.res_id]
            }
        else:
            res_dict.get(
                resource.res_name)[resource.res_type] = [resource.res_id]
    else:
        res_dict = {resource.res_name: {resource.res_type: [resource.res_id]}}
    with open("%s/%s" % (jobdir, save_file), 'w') as resource_file:
        json.dump(res_dict, resource_file, indent=4)
    LOG.info("Resource id saved! %s ", resource.res_id)
    LOG.info(json.dumps(res_dict, indent=4))
    return True


def get_exists_resource_id(jobdir, resource_type, resource_index=0):
    '''
    :param jobdir: job runtime temp directory
    :param resource_type: which type of resource is required
    :param: resource_index specify which resource use if more than 1
                           resource_id saved.
    eg, sometimes we needs init 2 resources like network test/mutli disk test.
    '''
    save_file = 'resource.json'
    if not os.path.exists("%s/%s" % (jobdir, save_file)):
        LOG.info("No %s found", save_file)
        return None
    LOG.info("%s found, try to retrive resource id!", save_file)
    with open("%s/%s" % (jobdir, save_file), 'r') as resource_file:
        res_dict = json.load(resource_file)
    for i in res_dict.keys():
        if i == 'black_list':
            continue
        if res_dict[i].has_key(resource_type) and len(
                res_dict[i].get(resource_type)) > resource_index:
            LOG.info("previous stored id: %s",
                     res_dict[i].get(resource_type)[resource_index])
            return res_dict[i].get(resource_type)[resource_index]
    LOG.info("No such types resource saved!")
    return None


def cleanup_stored(jobdir, params, resource_id=None):
    '''
    usually use after all the test done and needs clean up all stored resources
    :params jobdir: job runtime temp directory
    :params params: job runtime params, like self.params
    :params resource_id: delete one specified resource
    '''
    save_file = 'resource.json'
    if not os.path.exists("%s/%s" % (jobdir, save_file)):
        LOG.info("No %s found", save_file)
        return False

    with open("%s/%s" % (jobdir, save_file), 'r') as resource_file:
        res_dict = json.load(resource_file)
    if len(res_dict.keys()) == 0:
        LOG.info("No resource recorded!")
        return True

    LOG.info("All saved resources!")
    LOG.info(json.dumps(res_dict, indent=4))
    for m_key in res_dict.keys():
        if m_key == 'black_list':
            continue
        if len(res_dict[m_key].keys()) == 0:
            res_dict.pop(m_key)
            continue
        for s_key in res_dict[m_key].keys():
            if len(res_dict[m_key][s_key]) == 0:
                res_dict[m_key].pop(s_key)
                continue
            tmp_list = copy.deepcopy(res_dict[m_key][s_key])
            for i in tmp_list:
                init_status = False
                if i is None:
                    continue
                if resource_id is not None and i != resource_id:
                    continue
                if m_key == 'volume':
                    resource = EC2Volume(params)
                    init_status = resource.reuse_init(i)
                    if resource.is_attached():
                        resource.detach_from_instance(force=True)
                        resource.delete(wait=True)
                elif m_key == 'instance':
                    resource = EC2VM(params)
                    init_status = resource.reuse_init(i, type_check=False)
                if init_status:
                    resource.delete(wait=True)
                else:
                    LOG.info("Please double check %s status", i)
                res_dict[m_key][s_key].remove(i)
    LOG.info(json.dumps(res_dict, indent=4))
    with open("%s/%s" % (jobdir, save_file), 'w') as resource_file:
        json.dump(res_dict, resource_file, indent=4)


def check_dmesg(self, log_keyword, match_word_exact=False):
    '''
    check dmesg log inside remote guest
    @params: self is Test class instance
    @log_keyword: which keywords to check, eg error, warn, fail
    @match_word_exact: is macthing word exactly
    '''
    self.session.cmd_output('\n')
    dmesg_compare = None
    dmesg_compare_url = self.params.get('dmesg_compare_url')
    baseline_dict = None
    if dmesg_compare_url:
        self.log.info("Compare dmesg log with %s " % dmesg_compare_url)
        status, dmesg_compare = commands.getstatusoutput("curl -s %s" %
                                                         dmesg_compare_url)
        self.assertEqual(status,
                         0,
                         msg="Failed to get dmesg log! %s" % dmesg_compare)
        try:
            baseline_dict = json.loads(dmesg_compare)
        except ValueError as err:
            self.log.info(err)
            self.log.info("Failed to load baseline file from %s" %
                          dmesg_compare_url)

    check_cmd = 'dmesg'
    if match_word_exact:
        check_cmd = 'dmesg|grep -iw %s' % log_keyword
    ret = False
    out = utils_lib.run_cmd(self,
                  check_cmd,
                  expect_ret=0,
                  msg='Get dmesg log from guest!')

    ret = (find_word(out, log_keyword, baseline_dict=baseline_dict) | ret)
    if ret and dmesg_compare_url is not None:
        self.fail("New %s in dmesg" % log_keyword)
    elif ret:
        self.fail("Found %s in dmesg!" % log_keyword)
    else:
        self.log.info("No %s in dmesg!" % log_keyword)


def find_word(output1, log_keyword, baseline_dict=None):
    """find words in content

    Arguments:
        output1 {[string]} -- [string to look]
        baseline_dict {[dict]} -- [baseline dict to compare]
        match_word_exact: is macthing word exactly

    Returns:
        [Bool] -- [True|False]
    """
    ret = False
    tmp_list = re.findall('.*%s.*\n' % log_keyword, output1, flags=re.I)
    if len(tmp_list) == 0:
        LOG.info("No %s found!", log_keyword)
        return ret
    else:
        LOG.info("%s found!", log_keyword)
    # compare 2 fail string, if similary over fail_rate, consider it as same.
    fail_rate = 60
    for line1 in tmp_list:
        find_it = False
        if baseline_dict is not None:
            for basekey in baseline_dict:
                seq = difflib.SequenceMatcher(
                    None, a=line1, b=baseline_dict[basekey]["content"])
                same_rate = seq.ratio() * 100
                if same_rate > fail_rate:
                    LOG.info(
                        "Compare result rate: %d same, maybe it is not a \
new one", same_rate)
                    LOG.info("Guest: %s Baseline: %s", line1,
                             baseline_dict[basekey]["content"])
                    LOG.info("Baseline analyze: %s Branch:%s " %
                             (baseline_dict[basekey]["analyze"],
                              baseline_dict[basekey]["branch"]))
                    find_it = True
                    break
        if not find_it and baseline_dict is not None:
            LOG.info("This is a new failure!\n%s", line1)
            LOG.info("%s: %s", log_keyword, line1)
            ret = True
        elif not find_it:
            LOG.info("%s: %s", log_keyword, line1)
            ret = True

    return ret


def compare_dmesg(dmesg1, dmesg2):
    """
    Compare 2 dmesg logs, check whether new fail/error/warning/call trace
    generated

    Arguments:
        dmesg1 {string} - - dmesg log
        dmesg2 {string} - - dmesg log

    Returns:
        True -- No new fail/error/warning/call trace found
        False -- New fail/error/warning/call trace found
    """
    ret = False
    key_list = ['fail', 'error', 'warning', 'call trace']
    fail_rate = 60
    for key in key_list:
        LOG.info('Check %s' % (key))
        for x in re.findall('.*%s.*\n' % key, dmesg2, flags=re.I):
            for y in re.findall('.*%s.*\n' % key, dmesg1, flags=re.I):
                seq = difflib.SequenceMatcher(None, a=x, b=y)
                same_rate = seq.ratio() * 100
                if same_rate > fail_rate:
                    LOG.info(
                        "Compare result rate: %d same, maybe it is not a \
new one", same_rate)
                    ret = True
                    break
                else:
                    ret = False
            if ret:
                continue
            else:
                LOG.info("New: %s" % x)
                return ret
    return ret


def handle_exception(vm, err):
    '''
    In case ssh connection not responsive, try to get console output to see
    whether it is panic or other messages.
    As ssh connection is not responsive, stop and start the vm again to avoid
    other cases blocking by this failure.
    @params: vm instance
    @params: err exceprtions
    '''
    LOG.info("Test exception: %s", err)
    LOG.info("Get console log as exception hit!")
    time.sleep(60)
    for i in range(10):
        time.sleep(60)
        status, output = vm.get_console_log()
        if output is not None:
            break
        else:
            LOG.info("No output, try to get log later, max 10min!")
    LOG.info("Console output: %s ", output)
    LOG.info("Restart instance as exception hit!")
    vm.stop()
    if not vm.start():
        LOG.info("Cannot start instance, terminate it now!")
        vm.delete()
        return False
    return True


def install_pkgs(session, pkg_name):
    '''
    :params session: ssh connection session
    :parmas pkg_name: packadge name to install
    '''
    LOG.info("Try to install %s", pkg_name)
    install_cmd = 'sudo yum install -y %s' % pkg_name
    try:
        status, output = session.cmd_status_output(install_cmd)
        if status == 0:
            LOG.info("Installed successfully!")
            return True
        else:
            LOG.error("Installed failure %s", output)
            return False
    except Exception as err:
        LOG.error(err)
        return False


def set_ssh_wait_timeout(vm):
    """timeout wait while making ssh connect, longer time in baremetal system

    Arguments:
        vm {class} -- [vm instance]

    Returns:
        [int] -- [timeout value]
    """
    if 'metal' in vm.instance_type:
        LOG.info("Instance is bare metal")
        ssh_wait_timeout = 600
    elif 'x1e.32xlarge' in vm.instance_type:
        LOG.info("This instance needs long time login!")
        ssh_wait_timeout = 600
    else:
        LOG.info("Instance is xen/kvm")
        ssh_wait_timeout = 180
    LOG.info("ssh makes connection timeout is set to %s", ssh_wait_timeout)
    return ssh_wait_timeout


def gcov_get(self):
    '''
    get lcov log from guest
    '''
    if not self.params.get('code_cover'):
        return True

    self.log.info('Collect code coverage report!')
    self.session.connect(timeout=self.ssh_wait_timeout)
    cmd = 'sudo rm -rf ec2_cov.info'
    utils_lib.run_cmd(self, cmd)
    utils_lib.run_cmd(self, 'sudo su')
    cmd = 'sudo lcov  -c -b /root/rpmbuild/BUILD/kernel*/linux-*/ -o \
ec2_cov.info'

    utils_lib.run_cmd(self, cmd, expect_ret=0)

    remote_path = "ec2_cov.info"
    local_path = "%s/lcov/%s_%s_ec2_cov.info" % (self.job.logdir,
                                                 self.name.uid, time.time())
    if not os.path.exists("%s/lcov" % self.job.logdir):
        os.mkdir("%s/lcov" % self.job.logdir)
    self.log.info("Copy %s from guest to %s, please wait" %
                  (remote_path, local_path))
    try:
        self.session.copy_files_from(remote_path, local_path, timeout=600)
    except Exception as err:
        self.log.info("Copy gcov log failed,but not fail case!%s" % err)


def get_memleaks(self):
    '''
        '''
    self.log.info("Check memory leaks")
    output = utils_lib.run_cmd(self, 'uname -a', expect_ret=0)
    if 'debug' not in output:
        self.log.info('Not in debug kernel')
        return False
    output = utils_lib.run_cmd(self, 'cat /proc/cmdline', expect_ret=0)
    if 'kmemleak=on' not in output:
        self.log.info('kmemleak is not on')
        return False
    utils_lib.run_cmd(self, 'sudo su', expect_ret=0)
    cmd = 'echo scan > /sys/kernel/debug/kmemleak'
    utils_lib.run_cmd(self, cmd, expect_ret=0, timeout=1800)

    cmd = 'cat /sys/kernel/debug/kmemleak'
    output = utils_lib.run_cmd(self, cmd, expect_ret=0, timeout=1800)
    if len(output) > 0:
        self.fail('Memory leak found!')


def check_cmd(self, cmd=None):
    '''
    check cmd exists status, if no, try to install it.
    '''
    cmd_check = "which %s" % cmd
    ret, output = self.session.cmd_status_output(cmd_check)
    if ret == 0:
        return True
    self.log.info("No %s found!" % cmd)
    arch = utils_lib.run_cmd(self, 'uname -p')
    pkg_find = "sudo yum provides %s" % cmd
    output = utils_lib.run_cmd(self, pkg_find, expect_ret=0)
    pkg_list = re.findall(".*%s" % arch, output)
    utils_lib.run_cmd(self, "sudo yum install -y %s" % pkg_list[0], expect_ret=0)


def get_debug_log(self):
    '''
    collect logs for debugging purpose in failure
    '''
    cmd_list = ['dmesg', 'sudo lsblk', 'sudo lspci']
    for cmd in cmd_list:
        utils_lib.run_cmd(self, cmd, msg='Get %s output as failure!' % cmd)


def get_drift(self):
    '''Get time drift

    Returns:
        [string] -- [offset]
    '''

    ntp_server = self.params.get('ntp_server')
    if ntp_server is None:
        ntp_server = 'de.ntp.org.cn'
    cmd = "ntpdate  -q %s" % ntp_server
    output = utils_lib.run_cmd(self, cmd, expect_ret=0)
    tmp_list = re.findall('offset [-0-9.]+', output)
    if tmp_list is None:
        self.fail("Failed to get offset!")
    offset = re.findall('[0-9.]+', tmp_list[0])[0]
    return offset
