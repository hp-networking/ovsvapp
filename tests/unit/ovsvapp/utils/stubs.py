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

import fixtures
from neutron.plugins.ovsvapp.utils import cache
from neutron.plugins.ovsvapp.utils import vim_session
from neutron.tests.unit.ovsvapp.utils import fake_vmware_api


def fake_get_vim_object(arg):
    """Stubs out the VMwareAPISession's get_vim_object method."""
    return fake_vmware_api.FakeVim()


def fake_is_vim_object(arg, module):
    """Stubs out the VMwareAPISession's is_vim_object method."""
    return isinstance(module, fake_vmware_api.FakeVim)


class FakeVmware(fixtures.Fixture):

    def __init__(self):
        self.session = None

    def setUp(self):
        super(FakeVmware, self).setUp()
        fake_vmware_api.reset()
        self.useFixture(fixtures.MonkeyPatch(
            'neutron.plugins.ovsvapp.utils.vim_session.'
            'VMWareAPISession._get_vim_object', fake_get_vim_object))
        self.useFixture(fixtures.MonkeyPatch(
            'neutron.plugins.ovsvapp.utils.vim_session.'
            'VMWareAPISession._is_vim_object', fake_is_vim_object))
        self.vcenter_ip = "192.168.1.3"
        self.vcenter_username = "user"
        self.vcenter_password = "password"
        self.vcenter_api_retry_count = 2
        self.wsdl_loc = "https://www.vmware.com/sdk/fake.wsdl"
        vim_session.ConnectionHandler.\
            set_vc_details(self.vcenter_ip,
                           self.vcenter_username,
                           self.vcenter_password,
                           self.vcenter_api_retry_count,
                           self.wsdl_loc)
        self.session = vim_session.ConnectionHandler.create_connection()
        self.addCleanup(fake_vmware_api.cleanup)


class CacheFixture(fixtures.Fixture):

    def setUp(self):
        fixtures.Fixture.setUp(self)
        cache.VCCache.reset()
        self.addCleanup(cache.VCCache.reset)
