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

from neutron.plugins.ovsvapp.utils import error_util
from neutron.plugins.ovsvapp.utils import vim_session
from neutron.plugins.ovsvapp.utils import vim_util
from neutron.tests.unit.ovsvapp import test
from neutron.tests.unit.ovsvapp.utils import fake_vmware_api
from neutron.tests.unit.ovsvapp.utils import stubs


class TestVmwareApiSession(test.TestCase):

    def setUp(self):
        super(TestVmwareApiSession, self).setUp()
        self.host_ip = "192.168.1.3"
        self.host_username = "user"
        self.host_password = "password"
        self.api_retry_count = "2"
        self.wsdl_url = "https://www.vmware.com/sdk/fake.wsdl"
        self.useFixture(stubs.FakeVmware())

    def test_vmware_api_session(self):
        session = vim_session.VMWareAPISession(self.host_ip,
                                               self.host_username,
                                               self.host_password,
                                               self.api_retry_count,
                                               self.wsdl_url)
        self.assertTrue(session._session_id)

    def test_already_created_session(self):
        session_old = vim_session.VMWareAPISession(self.host_ip,
                                                   self.host_username,
                                                   self.host_password,
                                                   self.api_retry_count,
                                                   self.wsdl_url)
        self.assertTrue(session_old._session_id)
        session_new = session_old._create_session()
        self.assertNotEqual(session_old._session_id, session_new)

    def test_call_method(self):
        session = vim_session.VMWareAPISession(self.host_ip,
                                               self.host_username,
                                               self.host_password,
                                               self.api_retry_count,
                                               self.wsdl_url)
        host_mor = session._call_method(
            vim_util, "get_objects", "HostSystem", ['name'])
        self.assertTrue(isinstance(host_mor[0], fake_vmware_api.ManagedObject))
        self.assertEqual(host_mor[0].propSet[0].val, "test_host")

    def test_wait_for_task_error(self):
        session = vim_session.VMWareAPISession(self.host_ip,
                                               self.host_username,
                                               self.host_password,
                                               self.api_retry_count,
                                               self.wsdl_url)
        task_ref = fake_vmware_api.create_task("test_task", "error")
        raised = self.assertRaises(error_util.RunTimeError,
                                   session._wait_for_task, task_ref)
        self.assertTrue(raised)
