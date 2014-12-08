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

import mock
from neutron.plugins.ovsvapp.utils import error_util
from neutron.plugins.ovsvapp.utils import resource_util
from neutron.tests.unit.ovsvapp import test
from neutron.tests.unit.ovsvapp.utils import fake_vmware_api
from neutron.tests.unit.ovsvapp.utils import stubs


class TestVmwareResourceUtil(test.TestCase):

    def setUp(self):
        super(TestVmwareResourceUtil, self).setUp()
        self.fake_visdk = self.useFixture(stubs.FakeVmware())
        self.session = self.fake_visdk.session
        self.useFixture(stubs.CacheFixture())

    def test_get_cluster_mor_for_vm(self):
        cluster_mor = resource_util.get_cluster_mor_for_vm(
            self.session, fake_vmware_api.Constants.VM_UUID)
        self.assertTrue(cluster_mor)

    def test_get_cluster_mor_for_invalid_vm(self):
        cluster_mor = resource_util.get_cluster_mor_for_vm(
            self.session, "1234-1234-1234-1234")
        self.assertFalse(cluster_mor)

    def test_get_host_mors_for_cluster(self):
        cluster_mor = resource_util.get_cluster_mor_for_vm(
            self.session, fake_vmware_api.Constants.VM_UUID)
        self.assertTrue(cluster_mor)
        host_mor = resource_util.get_host_mors_for_cluster(
            self.session, cluster_mor)
        self.assertTrue(host_mor)
        self.assertTrue(isinstance(host_mor, list))

    def test_get_host_mors_for_cluster_with_invalid_mor(self):
        host_mor = resource_util.get_host_mors_for_cluster(self.session, None)
        self.assertFalse(host_mor)

    def test_get_host_mors_for_cluster_exc(self):
        vim_exc = error_util.VimException("Session closed",
                                          Exception("Session error"))
        with mock.patch.object(self.session, "_call_method",
                               side_effect=vim_exc):
            host_mor = resource_util.get_host_mors_for_cluster(self.session,
                                                               None)
            self.assertFalse(host_mor)

    def tearDown(self):
        test.TestCase.tearDown(self)
