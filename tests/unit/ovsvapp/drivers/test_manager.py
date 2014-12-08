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
import eventlet
import mock
from neutron.plugins.ovsvapp.drivers import driver
from neutron.plugins.ovsvapp.drivers import dvs_driver
from neutron.plugins.ovsvapp.drivers import manager
from neutron.plugins.ovsvapp.utils import vim_session
from neutron.tests.unit.ovsvapp.drivers import fake_driver
from neutron.tests.unit.ovsvapp import test
from neutron.tests.unit.ovsvapp.utils import stubs


class TestVcenterManager(test.TestCase):

    def setUp(self):
        test.TestCase.setUp(self)
        self.callback = fake_driver.MockCallback()
        self.manager = manager.VcenterManager(self.callback)
        self.useFixture(stubs.FakeVmware())

    def test_parse_mapping(self):
        tuples = self.manager._parse_mapping("abc:123")
        self.assertEqual(len(tuples), 1)

    def test_parse_mapping_multiple(self):
        tuples = self.manager._parse_mapping("abc:123,,def:456")
        self.assertEqual(len(tuples), 2)

    def test_parse_mapping_excp(self):
        tuples = self.manager._parse_mapping(None)
        self.assertEqual(len(tuples), 0)

    def test_initialize_driver_non_enterprise(self):
        self.flags(is_enterprise=True, group="VMWARE")
        with mock.patch.object(vim_session.ConnectionHandler, "stop",
                               return_value=None):
            self.manager.initialize_driver()
            self.assertEqual(self.manager.driver.state, driver.State.IDLE)

    def test_initialize_driver_noconf(self):
        with mock.patch.object(vim_session.ConnectionHandler, "stop",
                               return_value=None):
            self.manager.initialize_driver()
            self.assertEqual(self.manager.driver.state, driver.State.IDLE)

    def test_initialize_driver_re(self):
        self.flags(vcenter_ip="vcenter.test.com", group='VMWARE')
        self.flags(vcenter_username="root", group='VMWARE')
        self.flags(vcenter_password="pass", group="VMWARE")
        self.flags(wsdl_location="http://esx.test.com", group="VMWARE")
        with contextlib.nested(
            mock.patch.object(vim_session.ConnectionHandler, "stop",
                              return_value=None),
            mock.patch.object(dvs_driver.DvsNetworkDriver, 'stop')):
                self.manager.initialize_driver()
                self.flags(vcenter_ip="other.test.com", group="VMWARE")
                self.flags(vcenter_username="root", group="VMWARE")
                self.flags(vcenter_password="pass", group="VMWARE")
                self.flags(wsdl_location="http://esx.test.com", group="VMWARE")
                self.manager.initialize_driver()
                self.assertIsNotNone(self.manager.driver)

    def test_handle_conf_update(self):
        cluster1 = "cluster1"
        dvs1 = "vds1"
        cluster2 = "cluster2"
        dvs2 = "vds2"
        with mock.patch.object(dvs_driver.DvsNetworkDriver, 'add_cluster'):
            self.manager.driver = dvs_driver.DvsNetworkDriver()
            self.flags(cluster_dvs_mapping=["%s:%s" % (cluster1, dvs1)],
                       group="VMWARE")
            self.manager.handle_conf_update()
            self.assertEqual(len(self.manager.cluster_switch_mapping), 1)
            self.assertIn(cluster1, self.manager.cluster_switch_mapping)
            self.flags(cluster_dvs_mapping=["%s:%s, %s:%s" %
                                            (cluster1, dvs1, cluster2, dvs2)],
                       group="VMWARE")
            self.manager.handle_conf_update()
            self.assertEqual(len(self.manager.cluster_switch_mapping), 2)
            self.assertIn(cluster1, self.manager.cluster_switch_mapping)
            self.assertIn(cluster2, self.manager.cluster_switch_mapping)

    def test_handle_conf_update_remove(self):
        cluster1 = "cluster1"
        dvs1 = "vds1"
        cluster2 = "cluster2"
        dvs2 = "vds2"
        with contextlib.nested(
            mock.patch.object(dvs_driver.DvsNetworkDriver, 'add_cluster'),
            mock.patch.object(dvs_driver.DvsNetworkDriver,
                              'remove_cluster')):
                self.manager.driver = dvs_driver.DvsNetworkDriver()
                self.flags(cluster_dvs_mapping=["%s:%s, %s:%s" %
                                                (cluster1, dvs1, cluster2,
                                                 dvs2)],
                           group="VMWARE")
                self.manager.handle_conf_update()
                self.assertEqual(len(self.manager.cluster_switch_mapping), 2)
                self.assertIn(cluster1, self.manager.
                              cluster_switch_mapping)
                self.assertIn(cluster2, self.manager.
                              cluster_switch_mapping)
                self.flags(cluster_dvs_mapping=["%s:%s" % (cluster1, dvs1)],
                           group="VMWARE")
                self.manager.handle_conf_update()
                self.assertEqual(len(self.manager.cluster_switch_mapping), 1)
                self.assertIn(cluster1,
                              self.manager.cluster_switch_mapping)
                self.assertNotIn(cluster2,
                                 self.manager.cluster_switch_mapping)

    def test_handle_conf_update_init(self):
        cluster1 = "cluster1"
        dvs1 = "vds1"
        self.flags(vcenter_ip="vcenter.test.com", group="VMWARE")
        self.flags(vcenter_username="root", group="VMWARE")
        self.flags(vcenter_password="pass", group="VMWARE")
        self.flags(wsdl_location="http://esx.test.com", group="VMWARE")
        self.flags(cluster_dvs_mapping=["%s:%s" % (cluster1, dvs1)],
                   group="VMWARE")
        with mock.patch.object(vim_session.ConnectionHandler, 'stop',
                               return_value=None) as conn_stop:
            self.manager.handle_conf_update()
            self.assertTrue(conn_stop.called)

    def test_start(self):
        cluster1 = "cluster1"
        dvs1 = "vds1"
        self.flags(vcenter_ip="vcenter.test.com", group="VMWARE")
        self.flags(vcenter_username="root", group="VMWARE")
        self.flags(vcenter_password="pass", group="VMWARE")
        self.flags(wsdl_location="http://esx.test.com", group="VMWARE")
        self.flags(cluster_dvs_mapping=["%s:%s" % (cluster1, dvs1)],
                   group="VMWARE")
        with contextlib.nested(
            mock.patch.object(vim_session.ConnectionHandler, 'stop',
                              return_value=None),
            mock.patch.object(dvs_driver.DvsNetworkDriver, 'add_cluster',
                              return_value=None),
            mock.patch.object(eventlet, 'spawn_n', return_value=None)):
                self.manager.initialize_driver()
                self.manager.start()
                self.assertIn(cluster1,
                              self.manager.cluster_switch_mapping)

    def test_start_nonedriver(self):
        self.manager.driver = None
        self.assertIsNone(self.manager.start())

    def test_pause_nonedriver(self):
        self.manager.driver = None
        self.assertIsNone(self.manager.pause())

    def test_pause(self):
        with mock.patch.object(dvs_driver.DvsNetworkDriver, 'pause') as pause:
            self.manager.driver = dvs_driver.DvsNetworkDriver()
            self.manager.pause()
            self.assertTrue(pause.called)

    def test_stop(self):
        with contextlib.nested(
            mock.patch.object(vim_session.ConnectionHandler, "stop",
                              return_value=None),
            mock.patch.object(dvs_driver.DvsNetworkDriver, 'stop')
        ) as (conn_stop, dvs_stop):
                self.manager.driver = dvs_driver.DvsNetworkDriver()
                self.manager.stop()
                self.assertTrue(dvs_stop.called)
