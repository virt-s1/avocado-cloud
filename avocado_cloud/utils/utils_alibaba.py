from avocado.utils import process
import os
import time
import logging

LOG = logging.getLogger('avocado.test')
logging.basicConfig(level=logging.DEBUG)


def collect_information(test_instance, label='general'):
    test_instance.log.info('Collect Information')
    test_instance.log.info('Flavor: %s' % test_instance.vm.flavor)

    # Get ENV
    guest_path = test_instance.session.cmd_output('echo $HOME') + '/workspace'
    guest_logpath = guest_path + '/log'
    host_logpath = os.path.dirname(
        test_instance.job.logfile) + '/validation_data'
    test_instance.session.cmd_output('mkdir -p {0}'.format(guest_logpath))

    # Deliver script to instance
    test_instance.session.copy_files_to(
        local_path='{0}/../../scripts/vm_check.sh'.format(test_instance.pwd),
        remote_path=guest_path)

    # Cleanup logpath
    test_instance.session.cmd_output('rm -rf {0}/*'.format(guest_logpath))

    # Run script
    timestamp = time.strftime('%Y%m%d%H%M%S', time.localtime())
    logpath = '{0}/collection_{1}_{2}_{3}'.format(guest_logpath,
                                                  test_instance.vm.flavor,
                                                  label, timestamp)
    test_instance.session.cmd_output('bash {0}/vm_check.sh {1}'.format(
        guest_path, logpath),
                                     timeout=1200)

    # Create tarball
    # test_instance.session.cmd_output(
    #     'cd {0} && tar -zcf vm_check_results_{1}.tar.gz .'.format(
    #         guest_logpath, test_instance.vm.flavor))

    # Deliver logs to local
    process.run(cmd='mkdir -p ' + host_logpath,
                timeout=20,
                verbose=False,
                ignore_status=False,
                shell=True)
    test_instance.log.debug('Copying logs to host...')
    test_instance.session.copy_files_from(
        local_path=host_logpath,
        remote_path='{0}/*'.format(guest_logpath),
        timeout=1200)
    test_instance.log.info(
        'Copy logs to {0} successfully.'.format(host_logpath))

    # Cleanup scripts and logs
    test_instance.session.cmd_output('rm -rf ' + guest_path)


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
            vm=None,
            ret_status=False):
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
        ret_status {bool} -- return ret code instead of output

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
            test_instance.log.info("Try to reconnect")
            session.connect(timeout=test_instance.ssh_wait_timeout)
        except Exception as err:
            test_instance.log.error("")
            handle_ssh_exception(vm, err, is_get_console=is_get_console)
        test_instance.log.info(
            "Test connection via uname, if still fail, restart vm")
        try:
            status, output = session.cmd_status_output('uname -r', timeout=120)
            status, output = session.cmd_status_output(cmd, timeout=timeout)
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
                test_instance.cancel("%s found, cancel case %s" %
                                     (key_word, output))
    test_instance.log.info("CMD out:%s" % output)
    if ret_status:
        return status
    return output
