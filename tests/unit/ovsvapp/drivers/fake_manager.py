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

from neutron.plugins.ovsvapp.drivers import base_manager as driver_manager
from neutron.tests.unit.ovsvapp.drivers import fake_driver


class MockNetworkManager(driver_manager.DriverManager):

    def __init__(self, callback):
        driver_manager.DriverManager.__init__(self)
        self.methods = {}

    def get_driver(self):
        return self.driver

    def initialize_driver(self):
        self.driver = fake_driver.MockNetworkDriver()

    def handle_conf_update(self):
        self.methods["handle_conf_update"] = {}

    def start(self):
        self.methods["start"] = {}

    def pause(self):
        self.methods["pause"] = {}

    def stop(self):
        self.methods["stop"] = {}

    def reset(self):
        self.methods = {}
