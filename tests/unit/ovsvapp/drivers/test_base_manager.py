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

from neutron.plugins.ovsvapp.drivers import base_manager
from neutron.tests.unit.ovsvapp import test


class DriverManagerTestCase(test.TestCase):

    def setUp(self):
        test.TestCase.setUp(self)
        self.base_manager = base_manager.DriverManager()

    def test_initialize_driver(self):
        self.assertRaises(NotImplementedError,
            self.base_manager.initialize_driver)

    def test_handle_conf_update(self):
        self.assertRaises(NotImplementedError,
            self.base_manager.handle_conf_update)

    def test_start(self):
        self.assertTrue(self.base_manager.start() is None)

    def test_pause(self):
        self.assertTrue(self.base_manager.pause() is None)

    def test_stop(self):
        self.assertTrue(self.base_manager.stop() is None)
