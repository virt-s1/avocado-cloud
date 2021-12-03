#!/usr/bin/env python

# Description: Run containerized avocado-cloud testing.
# Maintainer: Charles Shih <schrht@gmail.com>

import argparse
import yaml
import subprocess

# Parse params
ARG_PARSER = argparse.ArgumentParser(
    description='Run tests in containerized avocado-cloud.')

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

CODEPATH = '/app'
DATAPATH = '/data'

# Get all test cases
with open('{0}/{1}_testcases.yaml'.format(DATAPATH, ARGS.platform),
          'r') as f:
    case_list = yaml.safe_load(f).get('cases').split(' ')

# Expand the real path for test cases
expanded_case_list = []
for case in case_list:
    # Add speicified test suites or all of them
    if 'test_functional_' + ARGS.testsuite in case:
        expanded_case_list.append(
            case.replace(
                'test_functional_', '{0}/tests/{1}/test_functional_'.format(
                    CODEPATH, ARGS.platform)))
        continue

    # Always add clean up test suite if possible
    if 'test_zcleanup' in case:
        expanded_case_list.append(
            case.replace(
                'test_zcleanup',
                '{0}/tests/{1}/test_zcleanup'.format(CODEPATH, ARGS.platform)))
        continue

# Execute the test
cmd = 'export PYTHONPATH={0}; \
/usr/bin/avocado run {2} --mux-yaml {1}/test_{3}.yaml \
--execution-order=tests-per-variant'.format(
    CODEPATH, DATAPATH, ' '.join(expanded_case_list), ARGS.platform)

print('Run command: \n{}'.format(cmd))

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
