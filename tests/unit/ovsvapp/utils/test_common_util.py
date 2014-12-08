# Copyright (c) 2014 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

from neutron.plugins.ovsvapp.utils import common_util
from neutron.tests.unit.ovsvapp import test
from neutron.tests.unit.ovsvapp.utils import fake_vmware_api
from neutron.tests.unit.ovsvapp.utils import stubs


class TestVmwareCommonUtil(test.TestCase):

    def setUp(self):
        super(TestVmwareCommonUtil, self).setUp()
        self.fake_visdk = self.useFixture(stubs.FakeVmware())
        self.session = self.fake_visdk.session

    def test_get_inventory_path(self):
        datacenter = fake_vmware_api.create_datacenter()
        datacenter.name = "Datacenter"
        datacenter.parent = self.session._get_vim(
        ).get_service_content().rootFolder
        cluster = fake_vmware_api.create_cluster_compute_resource()
        cluster.name = "Cluster"
        cluster.parent = datacenter
        path = common_util.get_inventory_path(self.session, cluster)
        self.assertEqual(path, "/".join((datacenter.name, cluster.name)))
