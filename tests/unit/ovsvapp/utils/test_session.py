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

import contextlib
import mock
from neutron.plugins.ovsvapp.utils import error_util
from neutron.plugins.ovsvapp.utils import vim_session
from neutron.plugins.ovsvapp.utils import vim_util
from neutron.tests.unit.ovsvapp import test
from oslo.vmware import api


class TestVmwareApiSession(test.TestCase):

    def setUp(self):
        super(TestVmwareApiSession, self).setUp()
        self.host_ip = "192.168.1.3"
        self.host_username = "user"
        self.host_password = "password"
        self.api_retry_count = "2"
        self.wsdl_url = "https://www.vmware.com/sdk/fake.wsdl"
        with contextlib.nested(
            mock.patch('oslo.vmware.api.VMwareAPISession.'
                       '_create_session')
                       ):
            self.vm_session = vim_session.VMWareAPISession(self.host_ip,
                                                        self.host_username,
                                                        self.host_password,
                                                        self.api_retry_count,
                                                        self.wsdl_url)

    def test_vmware_api_session(self):
        self.assertTrue(self.vm_session)

    def test_call_method(self):
        with contextlib.nested(
            mock.patch.object(api.VMwareAPISession,
                              "invoke_api"),
            mock.patch.object(self.vm_session,
                              "_is_vim_object",
                              return_value=True)
                       ) as (invoke_ob, is_vim_ob):
            self.vm_session._call_method(vim_util,
                                         "get_objects",
                                         "HostSystem", ['name'])
            self.assertTrue(invoke_ob.called)

    def test_wait_for_task_error(self):
        with mock.patch.object(api.VMwareAPISession,
                              "wait_for_task") as wait_ob:
            self.vm_session._wait_for_task("task")
            self.assertTrue(wait_ob.called)
