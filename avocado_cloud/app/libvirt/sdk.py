from ..base import VM
from avocado_cloud.utils import utils_misc
import xml.etree.ElementTree as ET
import libvirt
import re


class LibvirtVM(VM):
    def __init__(self, params):
        super(LibvirtVM, self).__init__(params)
        self._data = None

        uri = params.get('uri', '*/Cloud/*')

        self.conn = libvirt.open(uri)

        # VM creation parameters
        self.vm_name = params.get('vm_name', '*/VM/*')
        self.image_name = params.get('image_name', '*/VM/*')
        self.arch = params.get('arch', '*/VM/*', 'undefined')
        if self.arch == 'undefined':
            self.arch = re.search(r'\.([^.]+)\.[^.]+$',
                                  self.image_name).group(1)
        self.flavor = params.get('name', '*/Flavor/*')
        self.vcpus = params.get('cpu', '*/Flavor/*')
        self.memory = params.get('memory', '*/Flavor/*')
        self.size = params.get('size', '*/Flavor/*')
        self.user_data = None

        # VM access parameters
        self.vm_username = params.get('username', '*/VM/*')
        self.vm_password = params.get('password', '*/VM/*', '')

    @property
    def data(self):
        if not self._data:
            self.data = self.vm_name
        return self._data

    @data.setter
    def data(self, name):
        for dom in self.conn.listAllDomains():
            if dom.name() == name:
                self._data = {"uuid": dom.UUIDString()}

    @property
    def floating_ip(self):
        f_ip = None
        uuid = self.data.get("uuid")
        dom = self.conn.lookupByUUIDString(uuid)
        net = dom.interfaceAddresses(
            libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE, 0)
        if net.get("vnet0"):
            for addr in net.get("vnet0").get("addrs"):
                f_ip = addr.get("addr")
        return f_ip

    def create(self, wait=False):
        root = ET.fromstring(dom_xml)
        if self.arch == "x86_64":
            root.find("os").find("type").set("arch", self.arch)
            root.find("os").find("type").set("machine", "pc")
        elif self.arch == "ppc64le":
            root.find("os").find("type").set("arch", self.arch)
            root.find("os").find("type").set("machine", "pseries")
        elif self.arch == "s390x":
            root.find("os").find("type").set("arch", self.arch)
            root.find("os").find("type").set("machine", "s390-ccw-virtio")
        elif self.arch == "aarch64":
            root.find("os").find("type").set("arch", self.arch)
            root.find("os").find("type").set("machine", "virt")
            sub_cpu = ET.fromstring(
                '<cpu mode="host-passthrough"><model fallback="allow" /></cpu>'
            )
            root.insert(3, sub_cpu)
            sub_loader = ET.fromstring('<loader readonly="yes" type="pflash">\
/usr/share/AAVMF/AAVMF_CODE.verbose.fd</loader>')
            root.find("os").insert(0, sub_loader)
            sub_nvram = ET.fromstring(
                '<nvram>/usr/share/AAVMF/AAVMF_VARS.fd</nvram>')
            root.find("os").insert(0, sub_nvram)
            root.find("devices").find("rng").find(
                "backend").text = "/dev/urandom"
        else:
            root.find("os").find("type").set("arch", self.arch)
            root.find("os").find("type").set("machine", "pc")
        root.find("name").text = self.vm_name
        root.find("vcpu").text = str(self.vcpus)
        root.find("memory").text = str(self.memory * 1024 * 1024)
        root.find("currentMemory").text = str(self.memory * 1024 * 1024)
        root.find("devices").find("disk").find("source").set(
            "file", "/var/lib/libvirt/images/" + self.image_name)
        xmlconfig = ET.tostring(root).decode()
        dom = self.conn.defineXML(xmlconfig)
        dom.create()
        if wait:
            for count in utils_misc.iterate_timeout(
                    60, "Timed out waiting for server to get Created."):
                if self.exists() and self.floating_ip:
                    break
        self._data = None

    def delete(self, wait=False):
        dom = self.conn.lookupByUUIDString(self.data.get("uuid"))
        if not self.is_stopped():
            dom.destroy()
        dom.undefine()
        if wait:
            for count in utils_misc.iterate_timeout(
                    60, "Timed out waiting for server to get deleted."):
                if not self.exists():
                    break

    def start(self, wait=False):
        dom = self.conn.lookupByUUIDString(self.data.get("uuid"))
        dom.create()
        if wait:
            for count in utils_misc.iterate_timeout(
                    60, "Timed out waiting for server to get started."):
                if self.is_started():
                    break

    def stop(self, wait=False):
        dom = self.conn.lookupByUUIDString(self.data.get("uuid"))
        dom.shutdown()
        if wait:
            for count in utils_misc.iterate_timeout(
                    60, "Timed out waiting for server to get stopped."):
                if self.is_stopped():
                    break

    def reboot(self, wait=False):
        dom = self.conn.lookupByUUIDString(self.data.get("uuid"))
        dom.reboot()
        if wait:
            for count in utils_misc.iterate_timeout(
                    60, "Timed out waiting for server to get rebooted."):
                if self.is_started():
                    break

    def pause(self, wait=False):
        dom = self.conn.lookupByUUIDString(self.data.get("uuid"))
        dom.suspend()
        if wait:
            for count in utils_misc.iterate_timeout(
                    60, "Timed out waiting for server to get paused."):
                if self.is_paused():
                    break

    def unpause(self, wait=False):
        dom = self.conn.lookupByUUIDString(self.data.get("uuid"))
        dom.resume()
        if wait:
            for count in utils_misc.iterate_timeout(
                    60, "Timed out waiting for server to get unpaused."):
                if self.is_started():
                    break

    def exists(self):
        self._data = None
        if self.data is None:
            return False
        count = sum(1 for i in self.data)
        if count > 0:
            return True
        else:
            return False

    def _get_status(self):
        self.data = self.vm_name
        dom = self.conn.lookupByUUIDString(self.data.get("uuid"))
        state, reason = dom.state()
        return state

    def is_started(self):
        return self._get_status() == libvirt.VIR_DOMAIN_RUNNING

    def is_stopped(self):
        return self._get_status() == libvirt.VIR_DOMAIN_SHUTOFF

    def is_paused(self):
        return self._get_status() == libvirt.VIR_DOMAIN_PAUSED

    def show(self):
        return self.data


dom_xml = """
<domain type='kvm'>
  <name>rhel</name>
  <memory unit='KiB'>1048576</memory>
  <currentMemory unit='KiB'>1048576</currentMemory>
  <vcpu>1</vcpu>
  <os>
    <type arch='x86_64' machine='pc'>hvm</type>
    <boot dev='hd'/>
  </os>
  <features>
    <acpi/>
    <apic/>
  </features>
  <devices>
    <emulator>/usr/libexec/qemu-kvm</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='/tmp/rhel-guest-image.qcow2'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <interface type='network'>
      <source network='default' bridge='virbr0'/>
      <target dev='vnet0'/>
      <model type='virtio'/>
    </interface>
    <graphics type='vnc' port='5900' listen='127.0.0.1'/>
    <serial type='pty'/>
    <console type='pty'/>
    <channel type='unix'>
       <target type='virtio' name='org.qemu.guest_agent.0'/>
    </channel>
    <rng model='virtio'>
      <rate period='2000' bytes='1234'/>
      <backend model='random'>/dev/random</backend>
    </rng>
  </devices>
</domain>
"""
