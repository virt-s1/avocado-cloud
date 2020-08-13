import os
import re
import time
import logging
import decimal

LOG = logging.getLogger('avocado.test')
logging.basicConfig(level=logging.DEBUG)

def handle_ssh_exception(vm, err, is_get_console=False):
    '''
    In case ssh connection not responsive, try to get console output to see
    whether vm is panic or has useful messages.
    As ssh connection is not responsive, stop and start the vm again to avoid
    other cases blocking by this dead ssh session.

    Arguments:
    vm {vm instance} -- vm instance you are connecting
    err {string} -- exception got before run this function  
    is_get_console {bool} -- if your vm instance has get_console_log func,
    you may want save console output if ssh session not work
    '''
    LOG.info("Test exception: %s", err)
    if is_get_console:
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

def run_cmd(test_instance,
            cmd,
            expect_ret=None,
            expect_not_ret=None,
            expect_kw=None,
            expect_not_kw=None,
            expect_output=None,
            msg=None,
            cancel_kw=None,
            cancel_not_kw=None,
            timeout=60,
            is_get_console=True,
            session=None,
            vm=None):
    """run cmd with/without check return status/keywords and save log

    Arguments:
        test_instance {avocado Test instance} -- avocado test instance
        cmd {string} -- cmd to run
        expect_ret {int} -- expected return status
        expect_not_ret {int} -- unexpected return status
        expect_kw {string} -- string expected in output,seperate by ',' if
                              check multi words
        expect_not_kw {string} -- string not expected in output, seperate by
                                  ',' if check multi words
        expect_output {string} -- string exactly the same as output
        cancel_kw {string} -- cancel case if kw not found, seperate by ','
                              if check multi words
        cancel_not_kw {string} -- cancel case if kw found, seperate by ','
                              if check multi words
        msg {string} -- addtional info to mark cmd run.
        is_get_console {bool} -- if your vm instance has get_console_log func,
        you may want save console output if ssh session not work
        session {string} -- you can specify which session to use
        vm {string} -- you can specify which vm to use

    Keyword Arguments:
        check_ret {bool} -- [whether check return] (default: {False})
    """
    test_instance.log.info("CMD: %s", cmd)
    status = None
    output = None
    exception_hit = False
    if session == None:
        session = test_instance.session
    if vm == None:
        vm = test_instance.vm
    try:
        status, output = session.cmd_status_output(cmd, timeout=timeout)
    except Exception as err:
        test_instance.log.error("Run cmd failed as %s" % err)
        status = None
        exception_hit = True
    if exception_hit:
        try:
            test_instance.log.info("Try to close and reconnect")
            session.close()
            session.connect(timeout=test_instance.ssh_wait_timeout)
        except Exception as err:
            test_instance.log.error("")
            handle_ssh_exception(vm, err, is_get_console=is_get_console)
        test_instance.log.info("Test connection via uname, if still fail, restart vm")
        try:
            status, output = session.cmd_status_output('uname -r',
                                                            timeout=120)
            status, output = session.cmd_status_output(cmd,
                                                            timeout=timeout)
        except Exception as err:
            test_instance.log.error("")
            handle_ssh_exception(vm, err, is_get_console=is_get_console)

    if msg is not None:
        test_instance.log.info(msg)
    if expect_ret is not None:
        test_instance.assertEqual(status,
                         expect_ret,
                         msg='ret is %s, expected is %s, output %s' %
                         (status, expect_ret, output))
    if expect_not_ret is not None:
        test_instance.assertNotEqual(
            status,
            expect_not_ret,
            msg='ret is %s, expected not ret is %s, output %s' %
            (status, expect_not_ret, output))
    if expect_kw is not None:
        for key_word in expect_kw.split(','):
            test_instance.assertIn(key_word,
                          output,
                          msg='expcted %s not found in %s' %
                          (key_word, output))
    if expect_not_kw is not None:
        for key_word in expect_not_kw.split(','):
            test_instance.assertNotIn(key_word,
                             output,
                             msg='Unexpcted %s found in %s' %
                             (key_word, output))
    if expect_output is not None:
        test_instance.assertEqual(expect_output,
                         output,
                         msg='exactly expected %s, result %s' %
                         (expect_output, output))
    if cancel_kw is not None:
        cancel_yes = True
        for key_word in cancel_kw.split(','):
            if key_word in output:
                cancel_yes = False
        if cancel_yes:
            test_instance.cancel("None of %s found, cancel case" % cancel_kw)
    if cancel_not_kw is not None:
        for key_word in cancel_not_kw.split(','):
            if key_word in output:
                test_instance.cancel("%s found, cancel case" % key_word)
    test_instance.log.info("CMD out:%s" % output)
    return output

def ltp_check(test_instance):
    """
    Check whether ltp installed.
    Arguments:
        test_instance {avocado Test instance} -- avocado test instance
    """
    test_instance.log.info("TCheck ltp installation status from %s" %
                  test_instance.vm.instance_id)
    status, output = test_instance.session.cmd_status_output(
        'sudo ls -l /opt/ltp/runltp')
    if status == 0:
        test_instance.log.info("Fould /opt/ltp/runltp!")
        return True
    else:
        test_instance.log.info("/opt/ltp/runltp not found")
        return False

def ltp_install(test_instance):
    """
    Install ltp in target system.
    ltp_url is defined in configuration file.
    I use pre compiled pkgs for saving time in run.
    eg.
    ltp_url : https://github.com/liangxiao1/rpmbuild_specs/releases/download/ltp-master-20200514/ltp-master-20200514.x86_64.rpm
    or
    ltp_url : https://github.com/liangxiao1/rpmbuild_specs/releases/download/ltp-master-20200514/ltp-master-20200514.aarch64.rpm
    Arguments:
        test_instance {avocado Test instance} -- avocado test instance
    """
    ltp_url = test_instance.params.get('ltp_url')
    test_instance.log.info("Install ltp from %s", ltp_url)
    install_pkgs = 'sudo yum -y install %s' % ltp_url
    test_instance.log.info("Install ltp to %s" % test_instance.vm.instance_id)
    run_cmd(test_instance, install_pkgs)
    if not ltp_check(test_instance):
        test_instance.log.info('Install without dependences!')
        install_pkgs = 'sudo rpm -ivh %s --nodeps' % ltp_url
        run_cmd(test_instance, install_pkgs)

def ltp_run(test_instance, case_name=None, file_name=None):
    '''
    Run specify ltp test case.
    Arguments:
        test_instance {avocado Test instance} -- avocado test instance
    '''
    run_cmd(test_instance, 'sudo rm -rf /opt/ltp/results/*')
    if file_name is not None and case_name is not None:
        ltp_cmd = 'sudo /opt/ltp/runltp -f %s -s %s > ltplog 2>&1' % (
            file_name, case_name)
    elif file_name is None and case_name is not None:
        ltp_cmd = 'sudo /opt/ltp/runltp -s %s > ltplog 2>&1' % case_name
    elif file_name is not None and case_name is None:
        ltp_cmd = 'sudo /opt/ltp/runltp -f %s > ltplog 2>&1' % file_name
    if not ltp_check(test_instance):
        ltp_install(test_instance)
    if not ltp_check(test_instance):
        test_instance.fail("LTP is not installed!")
    test_instance.log.info("LTP cmd: %s" % ltp_cmd)
    test_instance.session.cmd_output('\n')
    run_cmd(test_instance, ltp_cmd, timeout=600)
    time.sleep(10)
    test_instance.session.connect(timeout=test_instance.ssh_wait_timeout)
    run_cmd(test_instance,
                'sudo cat /opt/ltp/results/*',
                expect_kw='Total Failures: 0')
    run_cmd(test_instance, 'uname -r', msg='Get instance kernel version')

def getboottime(test_instance,
            session=None,
            vm=None):
    '''
    Get system boot time via "systemd-analyze"
    Arguments:
        test_instance {avocado Test instance} -- avocado test instance
        session {string} -- you can specify which session to use
        vm {string} -- you can specify which vm to use
    '''
    if session == None:
        session = test_instance.session
    if vm == None:
        vm = test_instance.vm
    run_cmd(test_instance, "sudo which systemd-analyze", expect_ret=0, session=session, vm=vm)
    time_start = int(time.time())
    while True:
        output = run_cmd(test_instance, "sudo systemd-analyze", session=session, vm=vm)
        if 'Bootup is not yet finished' not in output:
            break
        time_end = int(time.time())
        run_cmd(test_instance, 'sudo systemctl list-jobs', session=session, vm=vm)
        if time_end - time_start > 60:
            test_instance.fail("Bootup is not yet finished after 60s")
        test_instance.log.info("Wait for bootup finish......")
        time.sleep(1)
    cmd = "sudo systemd-analyze blame > /tmp/blame.log"
    run_cmd(test_instance, cmd, expect_ret=0, session=session, vm=vm)
    run_cmd(test_instance, "cat /tmp/blame.log", expect_ret=0, session=session, vm=vm)
    output = run_cmd(test_instance, "sudo systemd-analyze", expect_ret=0, session=session, vm=vm)
    boot_time = re.findall("=.*s", output)[0]
    boot_time = boot_time.strip("=\n")
    boot_time_sec = re.findall('[0-9.]+s', boot_time)[0]
    boot_time_sec = boot_time_sec.strip('= s')
    if 'min' in boot_time:
        boot_time_min = re.findall('[0-9]+min', boot_time)[0]
        boot_time_min = boot_time_min.strip('min')
        boot_time_sec = int(boot_time_min) * 60 + decimal.Decimal(boot_time_sec).to_integral()
    test_instance.log.info(
        "Boot time is {}(s)".format(boot_time_sec))
    return boot_time_sec

def compare_nums(test_instance, num1=None, num2=None, ratio=0, msg='Compare 2 nums'):
    '''
    Compare num1 and num2.
    Arguments:
        test_instance {avocado Test instance} -- avocado test instance
        num1 {int} -- num1
        num2 {int} -- num2
        ratio {int} -- allow ratio
    Return:
        num1 < num2: return True
        (num1 - num2)/num2*100 > ratio: return False
        (num1 - num2)/num2*100 < ratio: return True
    '''
    num1 = float(num1)
    num2 = float(num2)
    ratio = float(ratio)
    test_instance.log.info(msg)
    if num1 < num2:
        test_instance.log.info("{} less than {}".format(num1, num2))
        return True
    if (num1 - num2)/num2*100 > ratio:
        test_instance.fail("{} vs {} over {}%".format(num1, num2, ratio))
    else:
        test_instance.log.info("{} vs {} less {}%, pass".format(num1, num2, ratio))

def is_arm(test_instance,
            session=None,
            vm=None, action=None):
    '''
    Check whether system is a arm system.
    Arguments:
        test_instance {avocado Test instance} -- avocado test instance
        session {string} -- you can specify which session to use
        vm {string} -- you can specify which vm to use
        action {string} -- cancel case if it is arm
    Return:
        arm: return True
        other: return False
    '''
    if session == None:
        session = test_instance.session
    if vm == None:
        vm = test_instance.vm
    output = run_cmd(test_instance, "lscpu", expect_ret=0, session=session, vm=vm)
    if 'aarch64' in output:
        test_instance.log.info("Arm detected.")
        if action == "cancel":
            test_instance.cancel("Cancel it in arm platform.")
        return True
    test_instance.log.info("Not an arm instance.")
    return False

def is_metal(test_instance,
            session=None,
            vm=None, action=None):
    '''
    Check whether system is a metal system.
    Arguments:
        test_instance {avocado Test instance} -- avocado test instance
        session {string} -- you can specify which session to use
        vm {string} -- you can specify which vm to use
        action {string} -- cancel case if it is metal
    Return:
        metal: return True
        other: return False
    '''
    if session == None:
        session = test_instance.session
    if vm == None:
        vm = test_instance.vm
    if 'metal' in test_instance.vm.instance_type:
        test_instance.log.info("Metal detected")
        if action == "cancel":
            test_instance.cancel("Cancel it in arm platform.")
        return True
    test_instance.log.info("Not a metal instance.")
    return False