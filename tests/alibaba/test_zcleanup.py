from avocado import Test
from avocado_cloud.app import Setup


class CleanUp(Test):
    """Release cloud resources.

    :avocado: tags=cleanup,fulltest,acceptance,fast_check
    """
    def setUp(self):
        """Set up."""
        self.log.info("Cleanup Begain!")
        self.cloud = Setup(self.params, self.name)
        self.vm = self.cloud.vm

    def test_release_nics(self):
        """Release NIC resources.

        :avocado: tags=test_release_nics
        """
        self.log.info("Release {0} NIC(s) named {1}.".format(
            len(self.vm.list_nics()),
            self.vm.ecs.vm_params.get('NetworkInterfaceName')))
        self.vm.delete_nics(wait=True)

    def test_release_cloud_disks(self):
        """Release cloud disk resources.

        :avocado: tags=test_release_cloud_disks
        """
        self.log.info("Release {0} disk(s) named {1}.".format(
            len(self.vm.query_cloud_disks()),
            self.vm.ecs.vm_params.get('DiskName')))
        self.vm.delete_cloud_disks(wait=True)

    def tearDown(self):
        """Tear down."""
        self.log.info("Cleanup Done!")
