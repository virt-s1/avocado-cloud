from ..base import VM
from avocado_cloud.utils import utils_misc
import openstack

openstack.enable_logging(debug=True)


class OpenstackVM(VM):
    def __init__(self, params, **kwargs):
        super(OpenstackVM, self).__init__(params)
        self._data = None

        # Openstack connection credentials
        auth_url = params.get('auth_url', '*/Cloud/*')
        project_name = params.get('project_name', '*/Cloud/*')
        project_domain_name = params.get('project_domain_name', '*/Cloud/*')
        user_domain_name = params.get('user_domain_name', '*/Cloud/*')
        username = params.get('username', '*/Credential/*')
        password = params.get('password', '*/Credential/*')

        self.conn = openstack.connect(auth_url=auth_url,
                                      project_name=project_name,
                                      project_domain_name=project_domain_name,
                                      user_domain_name=user_domain_name,
                                      username=username,
                                      password=password)

        # VM creation parameters
        self.vm_name = params.get('vm_name', '*/VM/*')
        self.image_name = params.get('image_name', '*/VM/*')
        self.network_name = params.get('network_name', '*/VM/*')
        self.network_id = params.get('network_id', '*/VM/*')
        self.floating_network_id = params.get('floating_network_id', '*/VM/*',
                                              '')
        self.flavor = params.get('name', '*/Flavor/*')
        self.flavor_id = params.get('id', '*/Flavor/*')
        self.size = params.get('size', '*/Flavor/*')
        self.keypair = params.get('keypair', '*/VM/*')
        self.user_data = None

        # VM creation timeout
        self.create_timeout = kwargs.get("create_timeout")

        # VM access parameters
        self.vm_username = params.get('username', '*/VM/*')
        self.vm_password = params.get('password', '*/VM/*', '')

        self.arch = 'x86_64'

    @property
    def data(self):
        if not self._data:
            self.data = self.vm_name
        return self._data

    @data.setter
    def data(self, name):
        for server in self.conn.compute.servers(name=name):
            self._data = server

    @property
    def floating_ip(self):
        f_ip = None
        for net in self.data.addresses.values():
            for ip in net:
                if ip['OS-EXT-IPS:type'] == 'floating':
                    f_ip = ip['addr']
                elif ip['OS-EXT-IPS:type'] == 'fixed' and  ip['version']== 4:
                    f_ip = ip['addr']
        return f_ip

    def create(self, wait=False, auto_ip=True):
        image_id = self.conn.compute.find_image(self.image_name).id

        args = {
            'name': self.vm_name,
            'image_id': image_id,
            'flavor_id': self.flavor_id,
            'networks': [{
                "uuid": self.network_id
            }],
        }
        if self.keypair:
            args['key_name'] = self.keypair
        if self.user_data:
            args['user_data'] = self.user_data

        server = self.conn.compute.create_server(**args)

        if wait:
            if self.create_timeout:
                server = self.conn.compute.wait_for_server(
                    server=server, wait=self.create_timeout)
            else:
                server = self.conn.compute.wait_for_server(server)
            if auto_ip and self.floating_network_id != '':
                f_ip = self.conn.network.create_ip(
                    floating_network_id=self.floating_network_id)
                self.conn.compute.add_floating_ip_to_server(
                    server, f_ip.floating_ip_address)
        self._data = None

    def delete(self, wait=False):
        f_ip = self.floating_ip
        if f_ip and self.floating_network_id != '':
            f_ip_id = self.conn.network.find_ip(f_ip)
            self.conn.network.delete_ip(f_ip_id)

        self.conn.compute.delete_server(self.data.id)

        if wait:
            for count in utils_misc.iterate_timeout(
                    60, "Timed out waiting for server to get deleted."):
                if not self.exists():
                    break

    def start(self, wait=False):
        self.conn.compute.start_server(self.data.id)
        if wait:
            for count in utils_misc.iterate_timeout(
                    60, "Timed out waiting for server to get started."):
                if self.is_started():
                    break

    def stop(self, wait=False):
        self.conn.compute.stop_server(self.data.id)
        if wait:
            for count in utils_misc.iterate_timeout(
                    60, "Timed out waiting for server to get stopped."):
                if self.is_stopped():
                    break

    def reboot(self, wait=False):
        self.conn.compute.reboot_server(self.data.id, 'SOFT')
        if wait:
            for count in utils_misc.iterate_timeout(
                    60, "Timed out waiting for server to get rebooted."):
                if self.is_started():
                    break

    def pause(self, wait=False):
        self.conn.compute.pause_server(self.data.id)
        if wait:
            for count in utils_misc.iterate_timeout(
                    60, "Timed out waiting for server to get paused."):
                if self.is_paused():
                    break

    def unpause(self, wait=False):
        self.conn.compute.unpause_server(self.data.id)
        if wait:
            for count in utils_misc.iterate_timeout(
                    60, "Timed out waiting for server to get unpaused."):
                if self.is_started():
                    break

    def exists(self):
        count = sum(1 for i in self.conn.compute.servers(name=self.vm_name))
        if count > 0:
            return True
        else:
            return False

    def _get_status(self):
        self.data = self.vm_name
        return self.data.status

    def is_started(self):
        return self._get_status() == 'ACTIVE'

    def is_stopped(self):
        return self._get_status() == 'SHUTOFF'

    def is_paused(self):
        return self._get_status() == 'PAUSED'

    def show(self):
        return self.data
