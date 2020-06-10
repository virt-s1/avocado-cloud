from avocado import Test
from avocado_cloud.app import Setup


class GeneralTest(Test):
    def setUp(self):
        cloud = Setup(self.params, self.name)
        self.vm = cloud.vm
        self.session = cloud.init_vm(pre_delete=False, pre_stop=False)

    def tearDown(self):
        self.session.close()
