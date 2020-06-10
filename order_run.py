#!/usr/bin/python
import subprocess
import os
import yaml

# Distro: azure/openstack/huawei/alibaba
distro = "azure"
# testsuite: the name after test_functional_,
#            such as checkup/clouddisk/lifecycle...
# If "", run all test cases of the distro
testsuite = ""

REALPATH = os.path.split(os.path.realpath(__file__))[0]

with open("{0}/config/{1}_testcases.yaml".format(REALPATH, distro), 'r') as f:
    case_list = yaml.load(f).get("cases").split(' ')

new_case_list = []
for case in case_list:
    # print case
    if distro == "huawei":
        if "test_functional_lifecycle" in case or \
           "test_functional_checkup" in case:
            tmp_distro = "openstack"
        else:
            tmp_distro = "huawei"
    else:
        tmp_distro = distro
    if "test_functional_" + testsuite in case:
        new_case_list.append(
            case.replace(
                'test_functional_',
                '{0}/tests/{1}/test_functional_'.format(REALPATH, tmp_distro)))

cmd = "/usr/bin/avocado run {0} --mux-yaml {1}/config/test_{2}.yaml \
--execution-order=tests-per-variant".format(' '.join(new_case_list), REALPATH,
                                            distro)
print(cmd)
p = subprocess.Popen(cmd,
                     shell=True,
                     stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT)

while p.poll() is None:
    line = p.stdout.readline()
    line = line.strip()
    if line:
        print(line)

if p.returncode == 0:
    print("Run Success")
else:
    print("Run Failed")
