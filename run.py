#!/usr/bin/python
import argparse
import os
import yaml
import subprocess

# Parse params
ARG_PARSER = argparse.ArgumentParser(description='Run tests in avocado-cloud.')

ARG_PARSER.add_argument('--platform',
                        dest='platform',
                        action='store',
                        help='The platform to run avocado-cloud testing; \
The possible value can be "azure", "openstack", "huawei", "alibaba", ...',
                        default='alibaba',
                        required=False)
ARG_PARSER.add_argument('--testsuite',
                        dest='testsuite',
                        action='store',
                        help='The name following "test_functional_"; \
The possible value can be "checkup", "clouddisk", "lifecycle", ..., \
or "" (run all test cases of the platform)',
                        default='',
                        required=False)

ARGS = ARG_PARSER.parse_args()
REALPATH = os.path.split(os.path.realpath(__file__))[0]

# Get all test cases
with open('{0}/config/{1}_testcases.yaml'.format(REALPATH, ARGS.platform),
          'r') as f:
    case_list = yaml.load(f).get('cases').split(' ')

# Expand the real path for test cases
expanded_case_list = []
for case in case_list:
    if 'test_functional_' + ARGS.testsuite in case:
        expanded_case_list.append(
            case.replace(
                'test_functional_', '{0}/tests/{1}/test_functional_'.format(
                    REALPATH, ARGS.platform)))
        continue
    if 'test_zcleanup' in case:
        expanded_case_list.append(
            case.replace(
                'test_zcleanup',
                '{0}/tests/{1}/test_zcleanup'.format(REALPATH, ARGS.platform)))
        continue

# Execute the test
cmd = 'export PYTHONPATH={0}; \
/usr/bin/avocado run {1} --mux-yaml {0}/config/test_{2}.yaml \
--execution-order=tests-per-variant'.format(REALPATH,
                                            ' '.join(expanded_case_list),
                                            ARGS.platform)

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
    print('Run Success')
    exit(0)
else:
    print('Run Failed')
    exit(1)
