import os
import re
import time
import logging

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
            is_get_console=True):
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

    Keyword Arguments:
        check_ret {bool} -- [whether check return] (default: {False})
    """
    test_instance.log.info("CMD: %s", cmd)
    status = None
    output = None
    exception_hit = False
    try:
        status, output = test_instance.session.cmd_status_output(cmd, timeout=timeout)
    except Exception as err:
        test_instance.log.error("Run cmd failed as %s" % err)
        status = None
        exception_hit = True
    if exception_hit:
        try:
            test_instance.log.info("Try to close and reconnect")
            test_instance.session.close()
            test_instance.session.connect(timeout=test_instance.ssh_wait_timeout)
        except Exception as err:
            test_instance.log.error("")
            handle_ssh_exception(test_instance.vm, err, is_get_console=is_get_console)
        test_instance.log.info("Test connection via uname, if still fail, restart vm")
        try:
            status, output = test_instance.session.cmd_status_output('uname -r',
                                                            timeout=120)
            status, output = test_instance.session.cmd_status_output(cmd,
                                                            timeout=timeout)
        except Exception as err:
            test_instance.log.error("")
            handle_ssh_exception(test_instance.vm, err, is_get_console=is_get_console)

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