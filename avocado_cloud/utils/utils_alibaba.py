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
                                     timeout=300)

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
