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
from neutron.plugins.ovsvapp.utils import network_util
from neutron.plugins.ovsvapp.utils import resource_util
from neutron.plugins.ovsvapp.utils import vim_util
from neutron.tests.unit.ovsvapp import test
from neutron.tests.unit.ovsvapp.utils import fake_vmware_api
from neutron.tests.unit.ovsvapp.utils import stubs


class TestVmwareNetworkUtil(test.TestCase):

    def setUp(self):
        super(TestVmwareNetworkUtil, self).setUp()
        self.fake_visdk = self.useFixture(stubs.FakeVmware())
        self.session = self.fake_visdk.session
        self.useFixture(stubs.CacheFixture())

    def test_get_dvs_mor_by_name(self):
        self.assertTrue(
            network_util.get_dvs_mor_by_name(self.session, "test_dvs"))

    def test_get_dvs_mor_by_name_for_invalid_dvs(self):
        self.assertFalse(
            network_util.get_dvs_mor_by_name(self.session, "invalid_dvs"))

    def test_is_valid_dvswitch(self):
        cluster_mor = resource_util.get_cluster_mor_for_vm(
            self.session, fake_vmware_api.Constants.VM_UUID)
        self.assertTrue(len(network_util.is_valid_dvswitch(self.session,
                                                           cluster_mor,
                                                           "test_dvs"))
                        > 0)

    def test_is_valid_dvswitch_no_host(self):
        cluster_mor = resource_util.get_cluster_mor_for_vm(
            self.session, fake_vmware_api.Constants.VM_UUID)
        with mock.patch.object(resource_util, "get_host_mors_for_cluster",
                               return_value=None):
            self.assertIsNone(network_util.is_valid_dvswitch(self.session,
                                                           cluster_mor,
                                                           "test_dvs"))

    def test_get_portgroup_mor_by_name(self):
        dvs_name = "test_dvs"
        port_group_name = fake_vmware_api.Constants.PORTGROUP_NAME
        dvs = fake_vmware_api.DataObject()
        dvs_config = fake_vmware_api.DataObject()
        port_group_mors = []
        pg1 = fake_vmware_api.create_network()
        pg1.set("summary.name", "pg1")
        port_group_mors.append(pg1)
        pg2 = fake_vmware_api.create_network()
        pg2.set("summary.name", port_group_name)
        port_group_mors.append(pg2)
        dvs_config.ManagedObjectReference = port_group_mors
        with contextlib.nested(
            mock.patch.object(vim_util,
                              'get_properties_for_a_collection_of_objects',
                              return_value=port_group_mors),
            mock.patch.object(network_util, "get_dvs_mor_by_name",
                              return_value=dvs),
            mock.patch.object(vim_util, "get_dynamic_property",
                              return_value=dvs_config)):
                port_group = network_util.get_portgroup_mor_by_name(
                    self.session, dvs_name, port_group_name)
                self.assertEqual(port_group.value, pg2.value)

    def test_get_portgroup_and_datacenter_id_by_name(self):
        dvs_name = "test_dvs"
        port_group_name = fake_vmware_api.Constants.PORTGROUP_NAME
        dvs = fake_vmware_api.DataObject()
        dvs_config = fake_vmware_api.DataObject()
        folder_mor = fake_vmware_api.create_folder()
        port_group_mors = []
        pg1 = fake_vmware_api.create_network()
        pg1.set("summary.name", "pg1")
        pg1.set("parent", folder_mor)
        port_group_mors.append(pg1)
        pg2 = fake_vmware_api.create_network()
        pg2.set("summary.name", port_group_name)
        pg2.set("parent", folder_mor)
        port_group_mors.append(pg2)
        dvs_config.ManagedObjectReference = port_group_mors
        with contextlib.nested(
            mock.patch.object(vim_util,
                              'get_properties_for_a_collection_of_objects',
                              return_value=port_group_mors),
            mock.patch.object(network_util, "get_dvs_mor_by_name",
                              return_value=dvs),
            mock.patch.object(vim_util, "get_dynamic_property",
                              return_value=dvs_config)):
                port_groupid, datacenter_id = network_util.\
                    get_portgroup_and_datacenter_id_by_name(self.session,
                                                            dvs_name,
                                                            port_group_name
                                                            )
                self.assertEqual(port_groupid, pg2.value)
                self.assertEqual(datacenter_id, datacenter_id)

    def test_get_portgroup_and_datacenter_id_by_name_no_dvs(self):
        dvs_name = "non_existent_dvs"
        port_group_name = fake_vmware_api.Constants.PORTGROUP_NAME
        with mock.patch.object(network_util, "get_dvs_mor_by_name",
                               return_value=None):
            port_groupid, datacenter_id = network_util.\
                get_portgroup_and_datacenter_id_by_name(
                    self.session, dvs_name, port_group_name)
            self.assertIsNone(port_groupid)
            self.assertIsNone(datacenter_id)

    def test_get_portgroup_and_datacenter_id_by_name_not_found(self):
        dvs_name = "test_dvs"
        port_group_name = fake_vmware_api.Constants.PORTGROUP_NAME
        dvs = fake_vmware_api.DataObject()
        dvs_config = fake_vmware_api.DataObject()
        folder_mor = fake_vmware_api.create_folder()
        port_group_mors = []
        pg1 = fake_vmware_api.create_network()
        pg1.set("summary.name", "pg1")
        pg1.set("parent", folder_mor)
        port_group_mors.append(pg1)
        dvs_config.ManagedObjectReference = port_group_mors
        with contextlib.nested(
            mock.patch.object(vim_util,
                              'get_properties_for_a_collection_of_objects',
                              return_value=port_group_mors),
            mock.patch.object(network_util, "get_dvs_mor_by_name",
                              return_value=dvs),
            mock.patch.object(vim_util, "get_dynamic_property",
                              return_value=dvs_config)):
                (port_groupid, datacenter_id) = network_util. \
                    get_portgroup_and_datacenter_id_by_name(self.session,
                                                            dvs_name,
                                                            port_group_name
                                                            )
                self.assertIsNone(port_groupid)
                self.assertIsNone(datacenter_id)

    def test_get_portgroup_mor_by_name_no_dvs(self):
        dvs_name = "non_existent_dvs"
        port_group_name = fake_vmware_api.Constants.PORTGROUP_NAME
        with mock.patch.object(network_util, "get_dvs_mor_by_name",
                               return_value=None):
            port_group = network_util.get_portgroup_mor_by_name(
                self.session, dvs_name, port_group_name)
            self.assertIsNone(port_group)

    def test_get_portgroup_mor_by_name_not_found(self):
        dvs_name = "test_dvs"
        port_group_name = fake_vmware_api.Constants.PORTGROUP_NAME
        dvs = fake_vmware_api.DataObject()
        dvs_config = fake_vmware_api.DataObject()
        port_group_mors = []
        pg1 = fake_vmware_api.create_network()
        pg1.set("summary.name", "pg1")
        port_group_mors.append(pg1)
        dvs_config.ManagedObjectReference = port_group_mors
        with contextlib.nested(
            mock.patch.object(vim_util,
                              'get_properties_for_a_collection_of_objects',
                              return_value=port_group_mors),
            mock.patch.object(network_util, "get_dvs_mor_by_name",
                              return_value=dvs),
            mock.patch.object(vim_util, "get_dynamic_property",
                              return_value=dvs_config)):
                port_group = network_util.get_portgroup_mor_by_name(
                    self.session, dvs_name, port_group_name)
                self.assertIsNone(port_group)

    def test_create_port_group_with_invalid_vlanid(self):
        dvs_name = "test_dvs"
        pg_name = fake_vmware_api.Constants.PORTGROUP_NAME
        vlanid = "1002"
        pg = fake_vmware_api.DataObject()
        defaultPortConfig = fake_vmware_api.DataObject()
        vlan = fake_vmware_api.DataObject()
        vlan.vlanId = "1004"
        defaultPortConfig.vlan = vlan
        port_group_config = fake_vmware_api.DataObject()
        port_group_config.defaultPortConfig = defaultPortConfig
        with contextlib.nested(
            mock.patch.object(network_util, "get_portgroup_mor_by_name",
                              return_value=pg),
            mock.patch.object(vim_util, "get_dynamic_property",
                              return_value=port_group_config)):
                raised = self.assertRaises(error_util.RunTimeError,
                                           network_util.create_port_group,
                                           self.session,
                                           dvs_name, pg_name, vlanid)
                self.assertTrue(raised)

    def test_create_port_group_existing(self):
        dvs_name = "test_dvs"
        pg_name = fake_vmware_api.Constants.PORTGROUP_NAME
        vlanid = "1002"
        pg = fake_vmware_api.DataObject()
        defaultPortConfig = fake_vmware_api.DataObject()
        vlan = fake_vmware_api.DataObject()
        vlan.vlanId = vlanid
        defaultPortConfig.vlan = vlan
        port_group_config = fake_vmware_api.DataObject()
        port_group_config.defaultPortConfig = defaultPortConfig
        with contextlib.nested(
            mock.patch.object(network_util, "get_portgroup_mor_by_name",
                              return_value=pg),
            mock.patch.object(vim_util, "get_dynamic_property",
                              return_value=port_group_config)
        ) as (mor, get_prop):
                network_util.create_port_group(self.session, dvs_name, pg_name,
                                               vlanid)
                self.assertTrue(get_prop.called)

    def test_create_port_group_err_status(self):
        dvs_name = "test_dvs"
        pg_name = fake_vmware_api.Constants.PORTGROUP_NAME
        vlanid = "5001"
        task_info = fake_vmware_api.DataObject()
        task_info.name = "AddDVPortgroup_Task"
        task_info.key = "task-1234"
        task_info.state = "error"
        task_info.error = fake_vmware_api.DataObject()
        task_info.error.localizedMessage = ("A specified parameter "
                                            "was not correct. spec.vlan")
        with contextlib.nested(
            mock.patch.object(network_util, "get_portgroup_mor_by_name",
                              return_value=None),
            mock.patch.object(vim_util, "get_dynamic_property",
                              return_value=task_info)):
                raised = self.assertRaises(error_util.RunTimeError,
                                           network_util.create_port_group,
                                           self.session, dvs_name,
                                           pg_name, vlanid)
                self.assertTrue(raised)

    def test_get_all_portgroup_mors_for_switch(self):
        port_group_mors = network_util.get_all_portgroup_mors_for_switch(
            self.session, "test_dvs")
        self.assertTrue(port_group_mors)
        self.assertTrue(isinstance(port_group_mors, list))

    def test_get_all_portgroup_mors_for_invalid_switch(self):
        dvs_name = "test_invalid_dvs"
        with mock.patch.object(network_util, "get_dvs_mor_by_name",
                               return_value=None):
            self.assertFalse(network_util.get_all_portgroup_mors_for_switch
                             (self.session, dvs_name))

    def test_get_unused_portgroup_names(self):
        # change vm object value
        fake_vmware_api._db_content['DistributedVirtualPortgroup'].values()[0]\
            .propSet[1].val = None
        self.assertTrue(network_util.get_unused_portgroup_names(self.session,
                                                                "test_dvs"))

    def test_get_used_portgroup_names(self):
        self.assertFalse(network_util.get_unused_portgroup_names(self.session,
                                                                 "test_dvs"))

    def test_port_block_status_on_vm(self):
        vm_id = fake_vmware_api.Constants.VM_UUID
        mac_address = fake_vmware_api.Constants.VM_MAC
        port_block_status = network_util.port_block_status_on_vm(
            self.session,
            vm_id, mac_address)
        self.assertFalse(port_block_status)

    def test_port_block_status_on_vm_with_no_port(self):
        vm_id = fake_vmware_api.Constants.VM_UUID
        mac_address = "11:22:33:44:55:eg"
        port_block_status = network_util.port_block_status_on_vm(
            self.session,
            vm_id, mac_address)
        self.assertTrue(port_block_status)
