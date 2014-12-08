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
from eventlet import timeout
import fixtures
import mock
from neutron.plugins.ovsvapp.common import error
from neutron.plugins.ovsvapp.common import model
from neutron.plugins.ovsvapp.drivers import driver
from neutron.plugins.ovsvapp.drivers import vc_driver as vmware_driver
from neutron.plugins.ovsvapp.utils import cache
from neutron.plugins.ovsvapp.utils import resource_util
from neutron.plugins.ovsvapp.utils import vim_util
from neutron.tests.unit.ovsvapp.drivers import fake_driver
from neutron.tests.unit.ovsvapp import test
from neutron.tests.unit.ovsvapp.utils import fake_vmware_api
from neutron.tests.unit.ovsvapp.utils import stubs
from oslo.config import cfg

CONF = cfg.CONF
VcCache = cache.VCCache


def fake_is_valid_switch(obj, cluster_mor, switch):
    return fake_vmware_api._db_content["HostSystem"].values()


def fake_get_unused_portgroups(obj, switch):
    return []


def fake_delete_portgroup(obj, switch, pg):
    return


def fake_create_network(obj, network, virtual_switch):
    return


class TestVmwareDriver(test.TestCase):

    def setUp(self):
        super(TestVmwareDriver, self).setUp()
        self.cluster_dvs_mapping = {"ClusterComputeResource": "test_dvs"}
        self.fake_visdk = self.useFixture(stubs.FakeVmware())
        self.session = self.fake_visdk.session
        self.useFixture(stubs.CacheFixture())
        self.useFixture(fixtures.MonkeyPatch(
            'neutron.plugins.ovsvapp.drivers.vc_driver.'
            'VCNetworkDriver.is_valid_switch', fake_is_valid_switch))
        self.useFixture(fixtures.MonkeyPatch(
            'neutron.plugins.ovsvapp.drivers.vc_driver.'
            'VCNetworkDriver.get_unused_portgroups',
            fake_get_unused_portgroups))
        self.useFixture(fixtures.MonkeyPatch(
            'neutron.plugins.ovsvapp.drivers.vc_driver.'
            'VCNetworkDriver.delete_portgroup', fake_delete_portgroup))
        self.useFixture(fixtures.MonkeyPatch(
            'neutron.plugins.ovsvapp.drivers.vc_driver.'
            'VCNetworkDriver.create_network', fake_create_network))
        self.vc_driver = vmware_driver.VCNetworkDriver()
        self.vc_driver.state = driver.State.RUNNING
        self.vc_driver.add_cluster("ClusterComputeResource", "test_dvs")
        self.thread = None

    def test_set_callback(self):
        self.vc_driver.state = driver.State.READY
        mock_callback = fake_driver.MockCallback()
        self.vc_driver.set_callback(mock_callback)
        with timeout.Timeout(1, False):
            self.thread = eventlet.spawn(self.vc_driver.monitor_events)
            self.thread.wait()
        if self.thread:
            self.thread.kill()
        self.assertTrue(len(mock_callback.events) > 0)
        for event in mock_callback.events:
            self.assertIn(event.event_type,
                          (model.EventType.VM_CREATED,
                          model.EventType.VM_UPDATED))

    def test_stop(self):
        with mock.patch.object(vim_util, "cancel_wait_for_updates",
                               return_value=None):
            self.vc_driver.stop()
            self.assertEqual(self.vc_driver.state, driver.State.STOPPED)

    def test_add_cluster_none(self):
        old_mapping = cache.VCCache.get_cluster_switch_mapping()
        self.vc_driver.add_cluster("", "test_dvs")
        self.assertEqual(old_mapping,
                        cache.VCCache.get_cluster_switch_mapping(),
                        "Cluster mapping got changed even for invalid"
                        "mapping")

    def test_add_cluster_invalid(self):
        with mock.patch.object(self.vc_driver, "is_valid_switch",
                               return_value=None):
            self.assertIn("ClusterComputeResource",
                          cache.VCCache.get_cluster_switch_mapping())
            self.vc_driver.add_cluster("ClusterComputeResource", "invalid_dvs")
            self.assertNotIn("ClusterComputeResource",
                             cache.VCCache.get_cluster_switch_mapping())

    def test_add_cluster_updatevds(self):
        self.assertEqual(cache.VCCache.
                         get_switch_for_cluster_path(
                             "ClusterComputeResource"), "test_dvs")
        self.vc_driver.add_cluster("ClusterComputeResource", "new_dvs")
        self.assertEqual(cache.VCCache.
                         get_switch_for_cluster_path(
                             "ClusterComputeResource"), "new_dvs")

    def test_add_cluster_clusterchanged(self):
        self.vc_driver.state = driver.State.IDLE
        cluster_mor = resource_util.\
            get_cluster_mor_by_path(self.session,
                                    "ClusterComputeResource")
        old_clu_id = cluster_mor.value
        object.__setattr__(cluster_mor, 'value', "new_value")
        with contextlib.nested(
            mock.patch.object(resource_util, "get_cluster_mor_by_path",
                              return_value=cluster_mor),
            mock.patch.object(self.vc_driver,
                              "_unregister_cluster_for_updates",
                              return_value=None)):
                self.assertEqual(cache.VCCache.
                                get_switch_for_cluster_path(
                                    "ClusterComputeResource"), "test_dvs")
                self.assertIn(old_clu_id,
                              cache.VCCache.clusters_id_to_path)
                self.vc_driver.add_cluster("ClusterComputeResource", "new_dvs")
                self.assertNotIn(old_clu_id,
                                 cache.VCCache.clusters_id_to_path)
                self.assertIn("new_value",
                              cache.VCCache.clusters_id_to_path)
                self.assertEqual(cache.VCCache.
                                get_switch_for_cluster_path(
                                    "ClusterComputeResource"), "new_dvs")
                self.assertEqual(self.vc_driver.state, driver.State.READY)

    def test_is_connected_none(self):
        self.vc_driver.session = None
        self.assertFalse(self.vc_driver.is_connected())

    def test_create_port(self):
        vm_id = fake_vmware_api.Constants.VM_UUID
        vlan = model.Vlan(vlanIds=["1001"])
        network_config = model.NetworkConfig(vlan)
        network = model.Network(
            name="net-1234", network_type=model.NetworkType.VLAN,
            config=network_config)
        port = model.Port(name=None,
                          mac_address=None,
                          ipaddresses=None,
                          vm_id=vm_id)
        virtual_nic = model.VirtualNic(mac_address=None,
                                       port_uuid=None,
                                       vm_id=vm_id,
                                       vm_name=None,
                                       nic_type=None)
        with mock.patch.object(model, "VirtualSwitch") as vswitch:
            self.vc_driver.create_port(network, port, virtual_nic)
            self.assertTrue(vswitch.called)

    def test_create_port_exc(self):
        vm_id = fake_vmware_api.Constants.VM_UUID
        vlan = model.Vlan(vlanIds=["1001"])
        network_config = model.NetworkConfig(vlan)
        network = model.Network(
            name="net-1234", network_type=model.NetworkType.VLAN,
            config=network_config)
        port = model.Port(name=None,
                          mac_address=None,
                          ipaddresses=None,
                          vm_id=vm_id)
        virtual_nic = model.VirtualNic(mac_address=None,
                                       port_uuid=None,
                                       vm_id=vm_id,
                                       vm_name=None, nic_type=None)
        with mock.patch.object(self.vc_driver, "is_valid_switch",
                               return_value=None):
            exc = self.assertRaises(error.ConfigurationError,
                                    self.vc_driver.create_port,
                                    network, port, virtual_nic)
            self.assertIn("Invalid Switch", str(exc))

    def test_create_port_invalid_cluster(self):
        vm_id = fake_vmware_api.Constants.VM_UUID
        vlan = model.Vlan(vlanIds=["1001"])
        network_config = model.NetworkConfig(vlan)
        network = model.Network(
            name="net-1234", network_type=model.NetworkType.VLAN,
            config=network_config)
        port = model.Port(name=None,
                          mac_address=None,
                          ipaddresses=None,
                          vm_id=vm_id)
        virtual_nic = model.VirtualNic(mac_address=None,
                                       port_uuid=None,
                                       vm_id=vm_id,
                                       vm_name=None,
                                       nic_type=None)
        cluster_mor = fake_vmware_api.DataObject()
        cluster_mor.value = "invalid_id"
        cache.VCCache.add_cluster_mor_for_vm(vm_id, cluster_mor)
        exc = self.assertRaises(error.ConfigurationError,
                                self.vc_driver.create_port,
                                network, port, virtual_nic)
        self.assertIn("Cluster for VM %s could not be determined" %
                      vm_id, str(exc))

    def test_process_update_set_filterset_none(self):
        updateSet = fake_vmware_api.DataObject()
        updateSet.version = 1
        updateSet.filterSet = None
        events = self.vc_driver._process_update_set(updateSet)
        self.assertEqual(len(events), 0)

    def test_process_update_set_objectset_none(self):
        updateSet = fake_vmware_api.DataObject()
        updateSet.version = 1
        filterSet = []
        updateSet.filterSet = filterSet
        propFilterUpdate = fake_vmware_api.DataObject()
        filterSet.append(propFilterUpdate)
        propFilterUpdate.objectSet = None
        events = self.vc_driver._process_update_set(updateSet)
        self.assertEqual(len(events), 0)

    def test_process_update_set_invalid(self):
        updateSet = fake_vmware_api.DataObject()
        updateSet.version = 1
        filterSet = []
        updateSet.filterSet = filterSet
        propFilterUpdate = fake_vmware_api.DataObject()
        filterSet.append(propFilterUpdate)
        objectSet = []
        propFilterUpdate.objectSet = objectSet
        objectUpdate = fake_vmware_api.DataObject()
        objectUpdate.obj = fake_vmware_api.\
            _db_content["ClusterComputeResource"].values()[0]
        objectUpdate.kind = "enter"
        changeSet = []
        objectUpdate.changeSet = changeSet
        for prop in objectUpdate.obj.propSet:
            changeSet.append(prop)
        objectSet.append(objectUpdate)
        events = self.vc_driver._process_update_set(updateSet)
        self.assertEqual(len(events), 0)

    def test_process_update_set_modify(self):
        updateSet = fake_vmware_api.DataObject()
        updateSet.version = 1
        filterSet = []
        updateSet.filterSet = filterSet
        propFilterUpdate = fake_vmware_api.DataObject()
        filterSet.append(propFilterUpdate)
        objectSet = []
        propFilterUpdate.objectSet = objectSet
        objectUpdate = fake_vmware_api.DataObject()
        objectUpdate.obj = fake_vmware_api.\
            _db_content["VirtualMachine"].values()[0]
        objectUpdate.kind = "modify"
        changeSet = []
        objectUpdate.changeSet = changeSet
        for prop in objectUpdate.obj.propSet:
            if prop.name == "runtime.host":
                delattr(prop, "val")
            changeSet.append(prop)
        objectSet.append(objectUpdate)
        events = self.vc_driver._process_update_set(updateSet)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, model.EventType.VM_CREATED)

    def test_process_update_set_leave(self):
        updateSet = fake_vmware_api.DataObject()
        updateSet.version = 1
        filterSet = []
        updateSet.filterSet = filterSet
        propFilterUpdate = fake_vmware_api.DataObject()
        filterSet.append(propFilterUpdate)
        objectSet = []
        propFilterUpdate.objectSet = objectSet
        objectUpdate = fake_vmware_api.DataObject()
        objectUpdate.obj = fake_vmware_api.\
            _db_content["VirtualMachine"].values()[0]
        objectUpdate.kind = "leave"
        changeSet = []
        objectUpdate.changeSet = changeSet
        objectSet.append(objectUpdate)
        events = self.vc_driver._process_update_set(updateSet)
        self.assertEqual(len(events), 0)

    def test_process_update_set_invalid_extraConfig(self):
        updateSet = fake_vmware_api.DataObject()
        updateSet.version = 1
        filterSet = []
        updateSet.filterSet = filterSet
        propFilterUpdate = fake_vmware_api.DataObject()
        filterSet.append(propFilterUpdate)
        objectSet = []
        propFilterUpdate.objectSet = objectSet
        objectUpdate = fake_vmware_api.DataObject()
        objectUpdate.obj = fake_vmware_api.\
            _db_content["VirtualMachine"].values()[0]
        objectUpdate.kind = "modify"
        changeSet = []
        objectUpdate.changeSet = changeSet
        for prop in objectUpdate.obj.propSet:
            if prop.name == 'config.extraConfig["nvp.vm-uuid"]':
                delattr(prop, "val")
            changeSet.append(prop)
        objectSet.append(objectUpdate)
        events = self.vc_driver._process_update_set(updateSet)
        self.assertEqual(len(events), 0)

    def test_delete_stale_portgroups(self):
        with mock.patch.object(self.vc_driver, "get_unused_portgroups",
            return_value=[fake_vmware_api.Constants.PORTGROUP_NAME]):
            self.vc_driver.delete_stale_portgroups("test_dvs")

    def test_post_delete_vm(self):
        uuid = fake_vmware_api.Constants.VM_UUID
        clus_mor = fake_vmware_api.\
            _db_content["ClusterComputeResource"].values()[0]
        vm_mor = fake_vmware_api.\
            _db_content["VirtualMachine"].values()[0]
        VcCache.add_cluster_mor_for_vm(uuid, clus_mor)
        VcCache.add_vm_mor_for_uuid(uuid, vm_mor)
        vm_model = model.VirtualMachine(name=vm_mor.name,
                                        vnics=[],
                                        uuid=uuid,
                                        key=vm_mor.value)
        VcCache.add_vm_model_for_uuid(uuid, vm_model)
        self.assertIn(uuid, VcCache.vm_to_cluster)
        self.assertIn(uuid, VcCache.vm_uuid_to_mor)
        self.assertIn(vm_mor.value, VcCache.vm_moid_to_uuid)
        self.assertIn(uuid, VcCache.vm_uuid_to_model)
        self.vc_driver.post_delete_vm(vm_model)
        self.assertNotIn(uuid, VcCache.vm_to_cluster)
        self.assertNotIn(uuid, VcCache.vm_uuid_to_mor)
        self.assertNotIn(vm_mor.value, VcCache.vm_moid_to_uuid)
        self.assertNotIn(uuid, VcCache.vm_uuid_to_model)

    def tearDown(self):
        if self.thread:
            self.thread.kill()
        test.TestCase.tearDown(self)
