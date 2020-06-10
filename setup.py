# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# See LICENSE for more details.
#

from setuptools import setup

VERSION = '0.1.0dev'

setup(
    name='avocado-cloud',
    version=VERSION,
    description='Avocado Cloud test suite',
    author='Xen QE',
    author_email='xen-qe-list@redhat.com',
    url='http://github.com/avocado-framework/avocado',
    packages=[
        'avocado_cloud',
    ],
)
