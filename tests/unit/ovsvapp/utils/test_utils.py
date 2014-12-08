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

from neutron.plugins.ovsvapp.common import utils
from neutron.plugins.ovsvapp.drivers import driver
from neutron.tests.unit.ovsvapp.drivers import fake_driver
from neutron.tests.unit.ovsvapp import test


class CommonUtilsTestCase(test.TestCase):

    def setUp(self):
        super(CommonUtilsTestCase, self).setUp()
        self.fake_network_full_name = \
            "neutron.tests.unit.ovsvapp.drivers.fake_driver.FakeNetworkDriver"
        self.invalid_driver_name =  \
            "neutron.tests.unit.ovsvapp.drivers.fake_driver.FakeInvalidDriver"

    def test_import_class(self):
        class_obj = utils.import_class(self.fake_network_full_name)
        self.assertTrue(class_obj == fake_driver.FakeNetworkDriver)

    def test_import_class_exc(self):
        import_class_fn = utils.import_class
        invalid_class = self.fake_network_full_name + "Invalid"
        import_err = ImportError
        self.assertRaises(import_err, import_class_fn, invalid_class)

    def test_load_object(self):
        driver_obj = utils.load_object(
            self.fake_network_full_name, driver.NetworkDriver)
        self.assertTrue(isinstance(driver_obj, fake_driver.FakeNetworkDriver))

    def test_fullname(self):
        class_name = utils.fullname(str)
        self.assertTrue(class_name == "str")
