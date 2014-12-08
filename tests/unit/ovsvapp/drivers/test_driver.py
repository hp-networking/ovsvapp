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

from neutron.plugins.ovsvapp.drivers import driver
from neutron.tests.unit.ovsvapp.drivers import fake_driver
from neutron.tests.unit.ovsvapp import test
from oslo.config import cfg

CONF = cfg.CONF


class TestNetworkDriver(test.TestCase):

    def setUp(self):
        super(TestNetworkDriver, self).setUp()
        self.driver = driver.NetworkDriver()

    def test_set_callback(self):
        mock_driver = fake_driver.MockNetworkDriver()
        callback = fake_driver.MockCallback()
        mock_driver.set_callback(callback)
        self.assertEqual(mock_driver.callback_impl, callback)

    def test_monitor_events(self):
        self.assertRaises(NotImplementedError,
                          self.driver.monitor_events)

    def test_pause(self):
        self.assertIsNone(self.driver.pause())

    def test_stop(self):
        self.assertIsNone(self.driver.stop())

    def test_is_connected(self):
        self.assertRaises(NotImplementedError,
                          self.driver.is_connected)

    def test_create_network(self):
        self.assertRaises(NotImplementedError,
                          self.driver.create_network, None, None)

    def test_delete_network(self):
        self.assertRaises(NotImplementedError,
                          self.driver.delete_network, None, None)

    def test_create_port(self):
        self.assertRaises(NotImplementedError,
                          self.driver.create_port, None, None, None)

    def test_update_port(self):
        self.assertRaises(NotImplementedError,
                          self.driver.update_port, None, None, None)

    def test_post_create_port(self):
        self.assertRaises(NotImplementedError,
                          self.driver.post_create_port, None)

    def test_post_delete_vm(self):
        self.assertRaises(NotImplementedError,
                          self.driver.post_delete_vm, None)


class TestNetworkDriverCallback(test.TestCase):

    def setUp(self):
        super(TestNetworkDriverCallback, self).setUp()
        self.callback = driver.NetworkDriverCallback()

    def test_process_event(self):
        self.assertRaises(NotImplementedError,
                          self.callback.process_event, None)
