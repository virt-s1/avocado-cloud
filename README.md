Cloud test suite for RHEL guests with avocado framework.

# Setup avocado-cloud

## 1. Clone the code

`git clone ssh://cheshi@code.engineering.redhat.com/avocado-cloud`

## 2. Install avocado-cloud

```
cd avocado-cloud
pip install -r requirements.txt
python setup.py install
```

# Run tests

## Alibaba

1. SSH keypair

```
sudo vi /etc/ssh/ssh_config.d/05-redhat.conf
```

Add your pem file as below:

```
Host *
        GSSAPIAuthentication yes
        IdentityFile /home/cheshi/pem/cheshi.pem
```

Ensure the pem file has a correct premission:

```
sudo chmod 600 /home/cheshi/pem/cheshi.pem
```


2. Update `./config/alibaba_common.yaml` according to your own.

```
cd ./config
cp alibaba.yaml alibaba_common.yaml
vi alibaba_common.yaml
```

3. Trim `./config/alibaba_flavors.yaml` according to your needs.

```
cd ./config
cp alibaba_flavors_full.yaml alibaba_flavors.yaml
vi alibaba_flavors.yaml
```

4. Trim `./config/alibaba_testcases.yaml` according to your needs.

```
cd ./config
cp alibaba_testcases_full.yaml alibaba_testcases.yaml
vi alibaba_testcases.yaml
```

5. No need to update `./config/test_alibaba.yaml`, its content should be:

```
test:
    !include : alibaba_flavors.yaml
    !include : alibaba_testcases.yaml
    !include : alibaba_common.yaml
```

6. Edit `./order_run.py`

```python
# Distro: azure/openstack/huawei/alibaba
distro = "alibaba"
```

7. Run your tests

```
export PYTHONPATH=.
./order_run.py
```

`order_run.py` will parse all the test cases from `./config/alibaba_testcases.yaml` and look up the test code from `./tests/`. It is very important to set `export PYTHONPATH=.` before running your tests.

## AWS

1. SSH keypair

```
sudo vi /etc/ssh/ssh_config.d/05-redhat.conf
```

Add your pem file as below:

```
Host *.amazonaws.com
        GSSAPIAuthentication yes
        IdentityFile /home/cheshi/pem/cheshi.pem
```

Ensure the pem file has a correct premission:

```
sudo chmod 600 /home/cheshi/pem/cheshi.pem
```

2. Run your tests

All test scripts are located in  `./scripts/avocado-cloud`.

2.1 Run tests

`$avocado run -m ./config/ec2_test.yaml ./tests/aws/ --execution-order=tests-per-variant`

2.2 Run one sub test filtered by tags

`$avocado run -m ./config/ec2_test.yaml --filter-by-tags storage ./tests/aws/ --execution-order=tests-per-variant`

2.3 Run multiple sub tests by specified tags:

`$avocado run -m ./config/ec2_test.yaml --filter-by-tags storage --filter-by-tags network ./tests/aws/ --execution-order=tests-per-variant`

2.4 Run single case by spefified tags:

`$avocado run -m ./config/ec2_test.yaml --filter-by-tags test_multi_disk_hotplug,storage --filter-by-tags test_cleanup,storage ./tests/aws/ --execution-order=tests-per-variant`

3. List cases

3.1 List cases filtered by tags:

`$avocado list --filter-by-tags generalverify --filter-by-tags lifecycle --filter-by-tags storage ./tests/aws/`

`$avocado list --filter-by-tags test_multi_disk_hotplug,storage --filter-by-tags test_cleanup,storage ./tests/aws/`

**Notes**

> **Avaliable tags:** kdump, lifecycle, ltp, network, storage, generalverify, cloudinit  
> **Required pkgs in AMI:** automake autoconf sysstat.x86_64 gcc unzip wget quota bzip2 iperf3 pciutils fio nvme-cli psmisc.x86_64 expect ntpdate  
(Suggest you install them while creating the AMI. So that it will prevent the failure when repo is not accessible during your test)

# Contribute

1. Ensure email is your redhat account.  
   Set it by `git config user.email "xxxx@redhat.com"`
2. Commit your change.  
   By `git commit` and write down the details in commit message.
3. Trigger a gerrit review.  
   After commit, you can trigger the gerrit review by `git-review`.
4. Go to [gerrit page](https://code.engineering.redhat.com/gerrit/#/dashboard/self) and choose the one your summited.
5. Add reviewers and call for review.
6. Update your code according to the comments if needed.  
   a) Update your code  
   b) Use `git commit --amend` to amend the privous commit.  
   c) Repeat step 3 ~ 5.
7. Submit your code.  
   After getting "review+2" and "verified", click "submit" button in the page.
