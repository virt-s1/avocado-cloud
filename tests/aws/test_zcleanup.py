from avocado import Test
from avocado_cloud.app.aws import aws


class CleanUp(Test):
    '''
    :avocado: tags=cleanup,fulltest,acceptance,fast_check
    '''
    def setUp(self):
        self.ssh_wait_timeout = None

    def test_cleanupall(self):
        '''
        :avocado: tags=test_cleanupall
        '''
        self.log.info("Cleanup previous saved resources!")
        aws.cleanup_stored(self.teststmpdir, self.params)
        self.log.info("Repeat again as some disk may be attached to \
instance at first time")
        aws.cleanup_stored(self.teststmpdir, self.params)

    def tearDown(self):
        self.log.info("Cleanup Done!")
