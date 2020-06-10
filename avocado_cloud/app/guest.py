from avocado_cloud.utils import remote
import logging
import os


class GuestSession(object):
    def __init__(self, vm):
        self.vm = vm
        self.session = None

    def connect(self, timeout=120, authentication="publickey"):
        try:
            self.session = remote.wait_for_login(client="ssh",
                                                 host=self.vm.floating_ip,
                                                 port='22',
                                                 username=self.vm.vm_username,
                                                 password=self.vm.vm_password,
                                                 prompt=r"[\#\$]\s*$",
                                                 timeout=timeout,
                                                 authentication=authentication)
            return True
        except Exception as e:
            logging.error("Timeout. Cannot login VM. Exception: %s", str(e))
            return False

    def cmd_output(self, cmd='', timeout=30):
        if self.session is None:
            self.connect()
        output = self.session.cmd_output(cmd, timeout).rstrip('\n')

        # cheshi, workaround for ^H issue in RHEL6.x
        if output.find('\x08' * 10) != -1 and output.find(cmd[:10]) != -1:
            logging.warning('Workaround for ^H issue in RHEL6.x')
            output = "".join(output.splitlines(True)[1:])

        logging.debug(output)
        return output

    def send_line(self, cmd):
        if self.session is None:
            self.connect()
        self.session.sendline(cmd)

    def cmd_status_output(self, cmd='', timeout=30):
        if self.session is None:
            self.connect()
        ret = self.session.cmd_status_output(cmd, timeout)
        ret = (ret[0], ret[1].rstrip('\n'))
        logging.debug(ret)
        return ret

    def copy_files_to(self,
                      local_path,
                      remote_path,
                      timeout=600,
                      authentication="publickey"):
        remote.copy_files_to(self.vm.floating_ip, "scp", self.vm.vm_username,
                             self.vm.vm_password, 22, local_path, remote_path,
                             "", None, False, timeout, None, None,
                             authentication)

    def copy_files_from(self,
                        remote_path,
                        local_path,
                        timeout=600,
                        authentication="publickey"):
        remote.copy_files_from(self.vm.floating_ip, "scp", self.vm.vm_username,
                               self.vm.vm_password, 22, remote_path,
                               local_path, "", None, False, timeout, None,
                               None, authentication)

    def copy_data_to_guest(self, cloud_provider, src_file):
        pwd = os.path.abspath(os.path.dirname(__file__))
        root_path = os.path.dirname(os.path.dirname(pwd))
        src_dir = os.path.join(os.path.join(root_path, "data"), cloud_provider)
        dest_dir = "/tmp/"
        self.copy_files_to(os.path.join(src_dir, src_file), dest_dir)

    def copy_scripts_to_guest(self, src_file):
        pwd = os.path.abspath(os.path.dirname(__file__))
        root_path = os.path.dirname(os.path.dirname(pwd))
        src_dir = os.path.join(os.path.join(root_path, "scripts"))
        dest_dir = "/tmp/"
        self.copy_files_to(os.path.join(src_dir, src_file), dest_dir)

    def close(self):
        if self.session:
            self.session.close()
