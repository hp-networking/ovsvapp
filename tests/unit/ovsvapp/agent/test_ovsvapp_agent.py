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
import time

from neutron.agent.linux import ovs_lib
from neutron.plugins.common import constants as p_const
from neutron.plugins.ovsvapp.agent import ovsvapp_agent
from neutron.plugins.ovsvapp.common import model
from neutron.plugins.ovsvapp.common import error
from neutron.plugins.ovsvapp.utils import resource_util
from neutron.tests.unit.ovsvapp import test
from neutron.tests.unit.ovsvapp.drivers import fake_manager
from oslo.config import cfg


class sampleEvent():
    def __init__(self, type, host, cluster, srcobj):
        self.event_type = type
        self.host_name = host
        self.cluster_id = cluster
        self.src_obj = srcobj


class VM():
    def __init__(self, uuid, vnics):
        self.uuid = uuid
        self.vnics = vnics


class samplePort():
    def __init__(self, port_uuid):
        self.port_uuid = port_uuid


class samplePortUIDMac():
    def __init__(self, port_uuid, mac_address):
        self.port_uuid = port_uuid
        self.mac_address = mac_address


class TestOVSvAppL2Agent(test.TestCase):

    def setUp(self):
        super(TestOVSvAppL2Agent, self).setUp()
        cfg.CONF.set_default('firewall_driver',
            'neutron.plugins.ovsvapp.drivers.ovs_firewall.OVSFirewallDriver',
            group='SECURITYGROUP')
        cfg.CONF.set_default('tenant_network_type',
                             'vlan',
                             group='OVSVAPP')
        with contextlib.nested(
            mock.patch('neutron.plugins.ovsvapp.agent.'
                       'OVSvAppL2Agent.setup_integration_br'),
            mock.patch('neutron.plugins.ovsvapp.agent.'
                       'OVSvAppL2Agent.setup_physical_bridges'),
            mock.patch('neutron.plugins.ovsvapp.agent.'
                       'OVSvAppL2Agent.setup_tunnel_br'),
            mock.patch('neutron.plugins.ovsvapp.agent.'
                       'OVSvAppL2Agent._init_ovs_flows'),
            mock.patch('neutron.plugins.ovsvapp.agent.'
                       'RpcPluginApi'),
            mock.patch('neutron.plugins.ovsvapp.agent.'
                       'OVSvAppPluginApi'),
            mock.patch('neutron.plugins.ovsvapp.drivers.manager.'
                       'get_cluster_dvs_mapping',
                       return_value=list("FakeCluster:FakeSwitch")),
            mock.patch('neutron.common.config.'
                       'init'),
            mock.patch('neutron.common.config.'
                       'setup_logging'),
            mock.patch('neutron.agent.rpc.'
                       'PluginReportStateAPI'),
            mock.patch('neutron.context.'
                       'get_admin_context_without_session'),
            mock.patch('neutron.agent.rpc.'
                       'create_consumers')):
            self.agent = ovsvapp_agent.OVSvAppL2Agent()
        self.LOG = ovsvapp_agent.LOG

    def test_setup_security_br_none(self):
        self.flags(security_bridge=None, group="SECURITYGROUP")
        self.agent.sec_br = mock.Mock()
        with contextlib.nested(
            mock.patch.object(self.LOG, 'debug'),
            mock.patch.object(self.agent.sec_br,
                              'bridge_exists')
                              ) as (logger_debug, ovs_bridge):
            self.agent.setup_security_br()
            self.assertTrue(logger_debug.called)
            self.assertFalse(ovs_bridge.called)

    def test_setup_security_br(self):
        self.flags(security_bridge="br-fake:fake_if",
                   group="SECURITYGROUP")
        self.agent.sec_br = mock.Mock()
        self.agent.int_br = mock.Mock()
        with contextlib.nested(
            mock.patch.object(self.LOG, 'info'),
            mock.patch.object(ovs_lib, "OVSBridge"),
            mock.patch.object(self.agent.sec_br,
                              "add_patch_port",
                              return_value=5),
            mock.patch.object(self.agent.int_br,
                              "add_patch_port",
                              return_value=6),
        )as (logger_info, ovs_br, sec_add_patch_port, int_add_patch_port):
            self.agent.setup_security_br()
            self.assertTrue(ovs_br.called)
            self.assertTrue(self.agent.sec_br.add_patch_port.called)
            self.assertTrue(logger_info.called)

    def _build_aur_port(self):
        aur_port = {'admin_state_up': False,
                    'id': 'xxx',
                    'device': 'xxx',
                    'network_id': 'yyy',
                    'physical_network': 'foo',
                    'segmentation_id': 'bar',
                    'network_type': 'baz',
                    'fixed_ips': [{'subnet_id': 'my-subnet-uuid',
                                   'ip_address': '1.1.1.1'}],
                    'device_owner': 'compute:None',
                    'security_groups': ['abcd'],
                    'mac_address': '01:02:03:04:05:06',
                    'device_id': 'zzz',
                    }
        return aur_port

    def test_map_port_to_common_model_vlan(self):
        aur_port = self._build_aur_port()
        self.tenant_network_type = p_const.TYPE_VLAN
        network, port = self.agent._map_port_to_common_model(aur_port)
        self.assertEqual(aur_port['network_id'], network.name)
        self.assertEqual(aur_port['id'], port.uuid)

    def test_map_port_to_common_model_vxlan(self):
        aur_port = self._build_aur_port()
        self.tenant_network_type = p_const.TYPE_VXLAN
        self.agent.local_vlan_map = {}
        self.agent.local_vlan_map[aur_port['network_id']] =\
            ovsvapp_agent.LocalVLANMapping(1, 'vxlan', 'bar', 'fake_cluster')
        network, port = self.agent._map_port_to_common_model(aur_port, 1)
        self.assertEqual(aur_port['network_id'], network.name)
        self.assertEqual(aur_port['id'], port.uuid)

    def test_process_event_ignore_event(self):
        vm = VM("fakevm", [])
        event = sampleEvent(model.EventType.VNIC_ADDED, "fakehost-1",
                            "fakecluster", vm)
        with contextlib.nested(
            mock.patch.object(self.agent,
                              "notify_device_added"),
            mock.patch.object(self.agent,
                              "_notify_device_updated"),
            mock.patch.object(self.agent,
                              "_notify_device_deleted"),
            mock.patch.object(self.LOG, 'debug')
        ) as (add_vm, update_vm, del_vm, log_debug):
            self.agent.process_event(event)
            self.assertTrue(log_debug.called)
            self.assertFalse(add_vm.called)
            self.assertFalse(update_vm.called)
            self.assertFalse(del_vm.called)

    def test_process_event_exception(self):
        vm = VM("fakevm", [])

        event = sampleEvent(model.EventType.VM_CREATED,
                            "fakehost-1", "fakecluster", vm)
        with contextlib.nested(
            mock.patch.object(self.agent,
                              "notify_device_added",
                              side_effect=Exception()),
            mock.patch.object(self.LOG, 'exception'),
            mock.patch.object(self.LOG, 'error'),
        ) as (add_vm, log_exception, log_error):
            self.agent.process_event(event)
            self.assertTrue(log_error.called)
            self.assertTrue(log_exception.called)

    def test_process_event_vm_create_nonics_non_host_non_cluster(self):
        self.agent.esx_hostname = 'fakehost-2'

        vm = VM("fakevm", [])

        self.agent.cluster_id = "fakecluster"
        event = sampleEvent(model.EventType.VM_CREATED,
                            "fakehost-1", "fakecluster", vm)
        self.agent.process_event(event)
        self.assertIn(vm.uuid, self.agent.cluster_devices)

    def test_process_event_vm_create_nonics_non_host(self):
        self.agent.esx_hostname = 'fakehost-2'

        vm = VM("fakevm", [])

        event = sampleEvent(model.EventType.VM_CREATED,
                            "fakehost-1", "fakecluster", vm)
        self.agent.process_event(event)
        self.assertIn(vm.uuid, self.agent.cluster_devices)

    def test_process_event_vm_create_nics_non_host(self):
        self.agent.esx_hostname = 'fakehost-2'

        vm_port1 = samplePort("fakeportid1")
        vm_port2 = samplePort("fakeportid2")

        vm = VM("fakevm", ([vm_port1, vm_port2]))

        event = sampleEvent(model.EventType.VM_CREATED,
                            'fakehost-1', 'fakecluster', vm)
        self.agent.process_event(event)
        self.assertIn(vm.uuid, self.agent.cluster_devices)
        for vnic in vm.vnics:
            self.assertIn(vnic.port_uuid, self.agent.devices_to_filter)
            self.assertIn(vnic.port_uuid, self.agent.cluster_other_ports)
            self.assertNotIn(vnic.port_uuid, self.agent.cluster_host_ports)

    def test_process_event_vm_create_nics_host(self):
        self.agent.esx_hostname = 'fakehost-1'

        vm_port1 = samplePort("fakeportid1")
        vm_port2 = samplePort("fakeportid2")

        vm = VM("fakevm", ([vm_port1, vm_port2]))

        event = sampleEvent(model.EventType.VM_CREATED,
                            'fakehost-1', 'fakecluster', vm)
        self.agent.process_event(event)
        self.assertIn(vm.uuid, self.agent.cluster_devices)
        for vnic in vm.vnics:
            self.assertIn(vnic.port_uuid, self.agent.devices_to_filter)
            self.assertIn(vnic.port_uuid, self.agent.cluster_host_ports)
            self.assertNotIn(vnic.port_uuid, self.agent.cluster_other_ports)

    def test_process_event_vm_delete_hosted_vm(self):
        self.agent.esx_hostname = 'fakehost'
        self.agent.cluster_devices.add('fakevm')
        self.agent.cluster_host_ports.add('xxx')
        self.agent.tenant_network_type = p_const.TYPE_VLAN
        ovsvapp_agent.network_port_count['yyy'] = 1

        port = self._build_aur_port()
        ovsvapp_agent.ports_dict[port['id']] = ovsvapp_agent.portInfo(
                                                  port['segmentation_id'],
                                                  port['mac_address'],
                                                  port['security_groups'],
                                                  port['fixed_ips'],
                                                  port['admin_state_up'],
                                                  port['network_id'],
                                                  port['device_id'])

        vm_port = samplePortUIDMac("xxx", "01:02:03:04:05:06")

        vm = VM("fakevm", ([vm_port]))

        event = sampleEvent(model.EventType.VM_DELETED,
                            'fakehost', 'fakecluster', vm)
        self.assertIn(vm.uuid, self.agent.cluster_devices)
        for vnic in vm.vnics:
            self.assertIn(vnic.port_uuid, self.agent.cluster_host_ports)
            self.assertNotIn(vnic.port_uuid, self.agent.cluster_other_ports)
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        self.agent.state = "RUNNING"
        self.agent.net_mgr.get_driver().post_delete_vm = mock.Mock()
        self.agent.net_mgr.get_driver().delete_network = mock.Mock()
        self.agent.process_event(event)
        self.assertNotIn(vm.uuid, self.agent.cluster_devices)
        for vnic in vm.vnics:
            self.assertNotIn(vnic.port_uuid, self.agent.cluster_host_ports)

    def test_process_event_vm_delete_hosted_vm_exception(self):
        self.agent.esx_hostname = 'fakehost'
        self.agent.cluster_devices.add('fakevm')
        self.agent.cluster_host_ports.add('xxx')
        self.agent.tenant_network_type = p_const.TYPE_VLAN
        ovsvapp_agent.network_port_count['yyy'] = 1

        port = self._build_aur_port()
        ovsvapp_agent.ports_dict[port['id']] = ovsvapp_agent.portInfo(
                                                  port['segmentation_id'],
                                                  port['mac_address'],
                                                  port['security_groups'],
                                                  port['fixed_ips'],
                                                  port['admin_state_up'],
                                                  port['network_id'],
                                                  port['device_id'])

        vm_port = samplePortUIDMac("xxx", "01:02:03:04:05:06")

        vm = VM("fakevm", ([vm_port]))

        event = sampleEvent(model.EventType.VM_DELETED,
                            'fakehost', 'fakecluster', vm)
        self.assertIn(vm.uuid, self.agent.cluster_devices)
        for vnic in vm.vnics:
            self.assertIn(vnic.port_uuid, self.agent.cluster_host_ports)
            self.assertNotIn(vnic.port_uuid, self.agent.cluster_other_ports)
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        self.agent.state = "RUNNING"
        self.agent.net_mgr.get_driver().post_delete_vm = mock.Mock()
        mock.patch.object(self.LOG, 'exception'),
        self.agent.process_event(event)
        self.assertNotIn(vm.uuid, self.agent.cluster_devices)
        for vnic in vm.vnics:
            self.assertNotIn(vnic.port_uuid, self.agent.cluster_host_ports)

    def test_process_event_vm_delete_non_hosted_vm(self):
        self.agent.esx_hostname = 'realhost'
        self.agent.cluster_devices.add('fakevm')
        self.agent.cluster_other_ports.add('xxx')
        self.agent.tenant_network_type = p_const.TYPE_VLAN
        ovsvapp_agent.network_port_count['yyy'] = 1

        port = self._build_aur_port()
        ovsvapp_agent.ports_dict[port['id']] = ovsvapp_agent.portInfo(
                                                  port['segmentation_id'],
                                                  port['mac_address'],
                                                  port['security_groups'],
                                                  port['fixed_ips'],
                                                  port['admin_state_up'],
                                                  port['network_id'],
                                                  port['device_id'])

        vm_port = samplePortUIDMac("xxx", "01:02:03:04:05:06")

        vm = VM("fakevm", ([vm_port]))

        event = sampleEvent(model.EventType.VM_DELETED,
                            'fakehost', 'fakecluster', vm)
        self.assertIn(vm.uuid, self.agent.cluster_devices)
        for vnic in vm.vnics:
            self.assertIn(vnic.port_uuid, self.agent.cluster_other_ports)
            self.assertNotIn(vnic.port_uuid, self.agent.cluster_host_ports)
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        self.agent.state = "RUNNING"
        with contextlib.nested(
            mock.patch.object(self.agent.net_mgr.get_driver(),
                              "post_delete_vm",
                              return_value=True),
            mock.patch.object(self.agent.net_mgr.get_driver(),
                              "delete_network"),
        ) as (post_del_vm, del_net):
            self.agent.process_event(event)
            self.assertNotIn(vm.uuid, self.agent.cluster_devices)
            for vnic in vm.vnics:
                self.assertNotIn(vnic.port_uuid,
                                 self.agent.cluster_other_ports)
            self.assertTrue(post_del_vm.called)
            self.assertFalse(del_net.called)

    def test_notify_device_added_with_hosted_vm(self):
        cluster_id = "fake_cluster"
        vm = VM("fake_vm", [])
        host = "fake_host"
        self.agent.esx_hostname = host
        with contextlib.nested(
            mock.patch.object(self.agent.ovsvapp_rpc,
                              "get_ports_for_device",
                              return_value=True),
            mock.patch.object(self.LOG, 'exception'),
            mock.patch.object(time, "sleep"),
        ) as (get_ports, log_exception, time_sleep):
            self.agent.notify_device_added(vm, host, cluster_id)
            self.assertTrue(get_ports.called)
            self.assertFalse(time_sleep.called)
            self.assertFalse(log_exception.called)

    def test_notify_device_added_rpc_exception(self):
        cfg.CONF.set_override('esx_hostname',
                              "fake_host", group="VMWARE")
        cluster_id = "cluster1234"
        vm = VM("vm1234", [])
        host = "fake_host"
        self.agent.esx_hostname = host
        with contextlib.nested(
            mock.patch.object(self.agent.ovsvapp_rpc,
                              "get_ports_for_device",
                              side_effect=Exception()),
            mock.patch.object(self.LOG, 'exception'),
            mock.patch.object(time, "sleep"),
        ) as (get_ports, log_exception, time_sleep):
            self.assertRaises(
                error.NeutronAgentError,
                self.agent.notify_device_added, vm, host, cluster_id)
            self.assertTrue(log_exception.called)
            self.assertTrue(get_ports.called)
            self.assertFalse(time_sleep.called)

    def test_notify_device_added_with_retry(self):
        cluster_id = "cluster1234"
        vm = VM("vm1234", [])
        host = "fake_host"
        self.agent.esx_hostname = host

        with contextlib.nested(
            mock.patch.object(self.agent.ovsvapp_rpc,
                              "get_ports_for_device",
                              return_value=False),
            mock.patch.object(self.LOG, 'exception'),
            mock.patch.object(time, "sleep"),
        ) as (get_ports, log_exception, time_sleep):
            self.agent.notify_device_added(vm, host, cluster_id)
            self.assertTrue(get_ports.called)
            self.assertTrue(time_sleep.called)
            self.assertFalse(log_exception.called)

    def test_report_state(self):
        with mock.patch.object(self.agent.state_rpc,
                               "report_state") as report_st:
            self.agent.cluster_id = "fake_cluster"
            self.agent._report_state()
            report_st.assert_called_with(self.agent.context,
                                         self.agent.agent_state)
            self.assertEqual(
                self.agent.agent_state["configurations"]["cluster_id"],
                self.agent.cluster_id
            )

    def test_report_state_exception(self):
        with contextlib.nested(
            mock.patch.object(self.agent.state_rpc,
                              "report_state",
                              side_effect=Exception()),
            mock.patch.object(self.LOG, 'exception'),
        ) as (report_st, log_exception):
            self.agent.cluster_id = "fake_cluster"
            self.agent._report_state()
            report_st.assert_called_with(self.agent.context,
                                         self.agent.agent_state)
            self.assertTrue(log_exception.called)

    def test_device_create_cluster_mismatch(self):
        device = {'id': "fake_id",
                  'cluster_id': "fake_cluster",
                  'host': "fake_host"}
        self.agent.cluster_id = "real_cluster"
        with contextlib.nested(
            mock.patch.object(self.LOG,
                              'debug'),
            mock.patch.object(self.agent,
                              'process_create_vlan',
                              return_value=True),
        ) as (logger_debug, create_vlan):
            self.agent.device_create("unused_context",
                                     device=device)
            self.assertTrue(logger_debug.called)
            self.assertFalse(create_vlan.called)

    def test_device_create_non_hosted_vm(self):
        device = {'id': '1234',
                  'cluster_id': "fake_cluster",
                  'host': "fake_host"}
        ports = [{'id': '5678',
                  'segmentation_id': '100',
                  'mac_address': 'aa:bb:cc:dd:ee:ff',
                  'security_groups': '13579',
                  'fixed_ips': [],
                  'admin_state_up': True,
                  'network_id': '2468',
                  'device_id': '6789'}]
        sg_rules = {'1234': '6789'}
        self.agent.cluster_id = "fake_cluster"
        self.agent.esx_hostname = "real_host"
        self.agent.tenant_network_type = p_const.TYPE_VLAN
        with contextlib.nested(
            mock.patch.object(self.LOG,
                              'debug'),
            mock.patch.object(self.agent.ovsvapp_rpc,
                              'update_port_binding',
                              return_value=True),
        ) as (logger_debug, update_port):
            self.agent.device_create("unused_context",
                                     device=device,
                                     ports=ports,
                                     sg_rules=sg_rules)
            self.assertTrue(logger_debug.called)
            self.assertIn('5678', self.agent.cluster_other_ports)
            self.assertNotIn('5678', self.agent.cluster_host_ports)
            self.assertFalse(update_port.called)

    def test_device_create_hosted_vm_vlan(self):
        device = {'id': '1234',
                  'cluster_id': "fake_cluster",
                  'host': "fake_host"}
        ports = [{'id': '5678',
                  'segmentation_id': '100',
                  'mac_address': 'aa:bb:cc:dd:ee:ff',
                  'security_groups': '13579',
                  'fixed_ips': [],
                  'admin_state_up': True,
                  'network_id': '2468',
                  'device_id': '6789'}]
        sg_rules = {'1234': '6789'}
        self.agent.cluster_id = "fake_cluster"
        self.agent.esx_hostname = "fake_host"
        self.agent.tenant_network_type = p_const.TYPE_VLAN
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        with contextlib.nested(
            mock.patch.object(self.LOG,
                              'debug'),
            mock.patch.object(self.agent.plugin_rpc,
                              'update_device_up',
                              return_value=True),
        ) as (logger_debug, update_device):
            self.agent.device_create("unused_context",
                                     device=device,
                                     ports=ports,
                                     sg_rules=sg_rules)
            self.assertTrue(logger_debug.called)
            self.assertIn('5678', self.agent.cluster_host_ports)
            self.assertNotIn('5678', self.agent.cluster_other_ports)
            self.assertTrue(update_device.called)

    def test_device_create_hosted_vm_vxlan(self):
        self.flags(tenant_network_type='vxlan', group='OVSVAPP')
        device = {'id': '1234',
                  'cluster_id': "fake_cluster",
                  'host': "fake_host"}
        ports = [{'id': '5678',
                  'segmentation_id': '100',
                  'mac_address': 'aa:bb:cc:dd:ee:ff',
                  'security_groups': '13579',
                  'fixed_ips': [],
                  'admin_state_up': True,
                  'device_id': '6789',
                  'network_type': 'vxlan',
                  'network_id': 'yyy'}]
        sg_rules = {'1234': '6789'}
        cfg.CONF.set_override('tenant_network_type',
                              'vxlan', group='OVSVAPP')
        cfg.CONF.set_override('tunnel_bridge',
                              'br-tun',
                              group='OVSVAPP')
        cfg.CONF.set_override('tunnel_types',
                              'vxlan',
                              group='OVSVAPPAGENT')
        cfg.CONF.set_override('polling_interval',
                              2,
                              group='OVSVAPPAGENT')
        cfg.CONF.set_override('vxlan_udp_port',
                              4789,
                              group='OVSVAPPAGENT')
        with contextlib.nested(
            mock.patch('neutron.plugins.ovsvapp.agent.'
                       'OVSvAppL2Agent.setup_tunnel_br'),
        ):
            self.agent.init_parameters()
        self.agent.cluster_id = "fake_cluster"
        self.agent.esx_hostname = "fake_host"
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        self.agent.state = "RUNNING"
        self.agent.cluster_dvs_info = ["DatacenterName/host/ClusterName",
                                       "vDSName"]

        with contextlib.nested(
            mock.patch.object(self.LOG,
                              'debug'),
            mock.patch.object(self.agent.plugin_rpc,
                              'update_device_up',
                              return_value=True),
            mock.patch.object(self.agent.net_mgr.get_driver(),
                              'get_pg_vlanid',
                              return_value=0),
        ) as (logger_debug, update_device, get_pg_vlan):
            self.agent.local_vlan_map = {}
            self.agent.device_create("unused_context",
                                     device=device,
                                     ports=ports,
                                     sg_rules=sg_rules)
            self.assertTrue(logger_debug.called)
            self.assertIn('5678', self.agent.cluster_host_ports)
            self.assertNotIn('5678', self.agent.cluster_other_ports)
            self.assertTrue(get_pg_vlan.called)
            self.assertTrue(update_device.called)

    def test_device_create_hosted_vm_create_port_exception(self):
        device = {'id': '1234',
                  'cluster_id': "fake_cluster",
                  'host': "fake_host"}
        ports = [{'id': '5678',
                  'segmentation_id': '100',
                  'mac_address': 'aa:bb:cc:dd:ee:ff',
                  'security_groups': '13579',
                  'fixed_ips': [],
                  'admin_state_up': True,
                  'network_id': '2468',
                  'device_id': '6789'}]
        sg_rules = {'1234': '6789'}
        self.agent.cluster_id = "fake_cluster"
        self.agent.esx_hostname = "fake_host"
        self.agent.tenant_network_type = p_const.TYPE_VLAN
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        self.agent.net_mgr.get_driver().create_port =\
            mock.Mock(side_effect=Exception())
        with contextlib.nested(
            mock.patch.object(self.LOG,
                              'debug'),
            mock.patch.object(self.agent.plugin_rpc,
                              'update_device_up'),
            mock.patch.object(self.LOG, 'exception'),
        ) as (logger_debug, update_device, log_excep):
            self.assertRaises(
                error.NeutronAgentError,
                self.agent.device_create,
                "unused_context",
                device=device,
                ports=ports,
                sg_rules=sg_rules)
            self.assertTrue(logger_debug.called)
            self.assertIn('5678', self.agent.cluster_host_ports)
            self.assertNotIn('5678', self.agent.cluster_other_ports)
            self.assertFalse(update_device.called)
            self.assertTrue(log_excep.called)

    def test_device_create_hosted_vm_update_device_exception(self):
        device = {'id': '1234',
                  'cluster_id': "fake_cluster",
                  'host': "fake_host"}
        ports = [{'id': '5678',
                  'segmentation_id': '100',
                  'mac_address': 'aa:bb:cc:dd:ee:ff',
                  'security_groups': '13579',
                  'fixed_ips': [],
                  'admin_state_up': True,
                  'network_id': '2468',
                  'device_id': '6789'}]
        sg_rules = {'1234': '6789'}
        self.agent.cluster_id = "fake_cluster"
        self.agent.esx_hostname = "fake_host"
        self.agent.tenant_network_type = p_const.TYPE_VLAN
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        with contextlib.nested(
            mock.patch.object(self.LOG,
                              'debug'),
            mock.patch.object(self.agent.plugin_rpc,
                              'update_device_up',
                              side_effect=Exception()),
            mock.patch.object(self.LOG, 'exception'),
        ) as (logger_debug, update_device, log_excep):
            self.assertRaises(
                error.NeutronAgentError,
                self.agent.device_create,
                "unused_context",
                device=device,
                ports=ports,
                sg_rules=sg_rules)
            self.assertTrue(logger_debug.called)
            self.assertIn('5678', self.agent.cluster_host_ports)
            self.assertNotIn('5678', self.agent.cluster_other_ports)
            self.assertTrue(update_device.called)
            self.assertTrue(log_excep.called)

    def test_port_update_admin_state_up(self):
        port = self._build_aur_port()

        ovsvapp_agent.ports_dict[port['id']] = ovsvapp_agent.portInfo(
                                                  port['segmentation_id'],
                                                  port['mac_address'],
                                                  port['security_groups'],
                                                  port['fixed_ips'],
                                                  port['admin_state_up'],
                                                  port['network_id'],
                                                  port['device_id'])
        self.agent.tenant_network_type = 'vlan'
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        self.agent.state = "RUNNING"

        neutron_port = {'segmentation_id': port['segmentation_id'],
                        'port': {'id': port['id'],
                                 'mac_address': port['mac_address'],
                                 'security_groups': port['security_groups'],
                                 'fixed_ips': port['fixed_ips'],
                                 'admin_state_up': True,
                                 'network_id': port['network_id'],
                                 'device_id': port['device_id']}}

        with contextlib.nested(
            mock.patch.object(self.agent.plugin_rpc,
                              "update_device_up"),
            mock.patch.object(self.agent.plugin_rpc,
                              "update_device_down"),
            mock.patch.object(self.LOG, 'exception'),
            mock.patch.object(self.LOG, 'debug')
        ) as (device_up, device_down,
              log_exception, log_debug):

            self.agent.port_update(self.agent.context, **neutron_port)
            self.assertEqual(
                ovsvapp_agent.ports_dict[port['id']].admin_state_up,
                neutron_port['port']['admin_state_up']
            )
            self.assertTrue(device_up.called)
            self.assertFalse(log_exception.called)

    def test_port_update_rpc_exception(self):
        port = self._build_aur_port()

        ovsvapp_agent.ports_dict[port['id']] = ovsvapp_agent.portInfo(
                                                  port['segmentation_id'],
                                                  port['mac_address'],
                                                  port['security_groups'],
                                                  port['fixed_ips'],
                                                  port['admin_state_up'],
                                                  port['network_id'],
                                                  port['device_id'])
        self.agent.tenant_network_type = 'vlan'
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        self.agent.state = "RUNNING"

        neutron_port = {'segmentation_id': port['segmentation_id'],
                        'port': {'id': port['id'],
                                 'mac_address': port['mac_address'],
                                 'security_groups': port['security_groups'],
                                 'fixed_ips': port['fixed_ips'],
                                 'admin_state_up': True,
                                 'network_id': port['network_id'],
                                 'device_id': port['device_id']}}

        with contextlib.nested(
            mock.patch.object(self.agent.plugin_rpc,
                              "update_device_up",
                              side_effect=Exception()),
            mock.patch.object(self.agent.plugin_rpc,
                              "update_device_down"),
            mock.patch.object(self.LOG, 'exception'),
            mock.patch.object(self.LOG, 'debug')
        ) as (device_up, device_down,
              log_exception, log_debug):

            self.assertRaises(
                error.NeutronAgentError,
                self.agent.port_update, self.agent.context, **neutron_port)
            self.assertEqual(
                ovsvapp_agent.ports_dict[port['id']].admin_state_up,
                neutron_port['port']['admin_state_up']
            )
            self.assertTrue(log_exception.called)
            self.assertTrue(device_up.called)

    def test_device_update_maintenance_mode(self):

        kwargs = {'device_data': {'ovsvapp_agent': 'fake_host1',
                  'esx_host_name': 'fake_esx_host2',
                  'assigned_agent_host': 'fake_host2'}}
        self.agent.hostname = 'fake_host2'
        self.agent.state = "RUNNING"
        self.agent.esx_maintenance_mode = True
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        self.agent.net_mgr.get_driver().session = "fake_session"
        with contextlib.nested(
            mock.patch.object(resource_util,
                              "get_vm_mor_by_name",
                              return_value="vm_mor"),
            mock.patch.object(resource_util,
                              "get_host_mor_by_name",
                              return_value="host_mor"),
            mock.patch.object(resource_util,
                              "set_vm_poweroff"),
            mock.patch.object(resource_util,
                              "set_host_into_maintenance_mode"),
            mock.patch.object(resource_util,
                              "set_host_into_shutdown_mode"),
            mock.patch.object(self.LOG, 'exception'),
            mock.patch.object(time, 'sleep')
        ) as (vm_mor_by_name, host_mor_by_name, power_off,
              maintenance_mode, shutdown_mode,
              log_exception, time_sleep):
            self.agent.device_update(self.agent.context, **kwargs)
            self.assertTrue(vm_mor_by_name.called)
            self.assertTrue(power_off.called)
            self.assertTrue(maintenance_mode.called)
            self.assertFalse(shutdown_mode.called)
            self.assertFalse(log_exception.called)

    def test_device_update_shutdown_mode(self):

        kwargs = {'device_data': {'ovsvapp_agent': 'fake_host1',
                  'esx_host_name': 'fake_esx_host2',
                  'assigned_agent_host': 'fake_host2'}}
        self.agent.hostname = 'fake_host2'
        self.agent.state = "RUNNING"
        self.agent.esx_maintenance_mode = False
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        self.agent.net_mgr.get_driver().session = "fake_session"
        with contextlib.nested(
            mock.patch.object(resource_util,
                              "get_vm_mor_by_name",
                              return_value="vm_mor"),
            mock.patch.object(resource_util,
                              "get_host_mor_by_name",
                              return_value="host_mor"),
            mock.patch.object(resource_util,
                              "set_vm_poweroff"),
            mock.patch.object(resource_util,
                              "set_host_into_maintenance_mode"),
            mock.patch.object(resource_util,
                              "set_host_into_shutdown_mode"),
            mock.patch.object(self.LOG, 'exception'),
            mock.patch.object(time, 'sleep')
        ) as (vm_mor_by_name, host_mor_by_name, power_off,
              maintenance_mode, shutdown_mode,
              log_exception, time_sleep):
            self.agent.device_update(self.agent.context, **kwargs)
            self.assertTrue(vm_mor_by_name.called)
            self.assertFalse(power_off.called)
            self.assertFalse(maintenance_mode.called)
            self.assertTrue(shutdown_mode.called)
            self.assertFalse(log_exception.called)

    def test_device_update_power_off_exception(self):

        kwargs = {'device_data': {'ovsvapp_agent': 'fake_host1',
                  'esx_host_name': 'fake_esx_host2',
                  'assigned_agent_host': 'fake_host2'}}
        self.agent.hostname = 'fake_host2'
        self.agent.state = "RUNNING"
        self.agent.esx_maintenance_mode = True
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        self.agent.net_mgr.get_driver().session = "fake_session"
        with contextlib.nested(
            mock.patch.object(resource_util,
                              "get_vm_mor_by_name",
                              return_value="vm_mor"),
            mock.patch.object(resource_util,
                              "get_host_mor_by_name",
                              return_value="host_mor"),
            mock.patch.object(resource_util,
                              "set_vm_poweroff",
                              side_effect=Exception()),
            mock.patch.object(resource_util,
                              "set_host_into_maintenance_mode"),
            mock.patch.object(resource_util,
                              "set_host_into_shutdown_mode"),
            mock.patch.object(self.LOG, 'exception'),
            mock.patch.object(time, 'sleep')
        ) as (vm_mor_by_name, host_mor_by_name, power_off,
              maintenance_mode, shutdown_mode,
              log_exception, time_sleep):
            self.agent.device_update(self.agent.context, **kwargs)
            self.assertTrue(vm_mor_by_name.called)
            self.assertTrue(power_off.called)
            self.assertTrue(maintenance_mode.called)
            self.assertFalse(shutdown_mode.called)
            self.assertTrue(log_exception.called)

    def test_device_update_maintenance_mode_exception(self):

        kwargs = {'device_data': {'ovsvapp_agent': 'fake_host1',
                  'esx_host_name': 'fake_esx_host2',
                  'assigned_agent_host': 'fake_host2'}}
        self.agent.hostname = 'fake_host2'
        self.agent.state = "RUNNING"
        self.agent.esx_maintenance_mode = True
        self.agent.net_mgr = fake_manager.MockNetworkManager("callback")
        self.agent.net_mgr.initialize_driver()
        self.agent.net_mgr.get_driver().session = "fake_session"
        with contextlib.nested(
            mock.patch.object(resource_util,
                              "get_vm_mor_by_name",
                              return_value="vm_mor"),
            mock.patch.object(resource_util,
                              "get_host_mor_by_name",
                              return_value="host_mor"),
            mock.patch.object(resource_util,
                              "set_vm_poweroff"),
            mock.patch.object(resource_util,
                              "set_host_into_maintenance_mode",
                              side_effect=Exception()),
            mock.patch.object(resource_util,
                              "set_host_into_shutdown_mode"),
            mock.patch.object(self.LOG, 'exception'),
            mock.patch.object(time, 'sleep')
        ) as (vm_mor_by_name, host_mor_by_name, power_off,
              maintenance_mode, shutdown_mode,
              log_exception, time_sleep):
            self.agent.device_update(self.agent.context, **kwargs)
            self.assertTrue(vm_mor_by_name.called)
            self.assertTrue(power_off.called)
            self.assertTrue(maintenance_mode.called)
            self.assertFalse(shutdown_mode.called)
            self.assertTrue(log_exception.called)
            self.assertTrue(time_sleep.called)

    def test_process_event_vm_updated_nonhost(self):
        self.agent.esx_hostname = 'fakehost-2'

        vm_port1 = samplePort("fake_port")
        vm = VM("fakevm", [vm_port1])
        event = sampleEvent(model.EventType.VM_UPDATED,
                            "fakehost-1", "fakecluster", vm)
        self.agent.esx_hostname = "fakehost-2"
        self.agent.process_event(event)
        self.assertIn("fake_port", self.agent.cluster_other_ports)

    def test_notify_device_updated_host(self):
        self.agent.esx_hostname = 'fakehost-2'

        vm_port1 = samplePort("fake_port")
        vm = VM("fakevm", [vm_port1])
        with contextlib.nested(
            mock.patch.object(self.agent.ovsvapp_rpc,
                              "update_port_binding"),
            mock.patch.object(self.LOG, 'exception'),
        ) as (update_port_binding, log_exception):
            self.agent._notify_device_updated(vm, "fakehost-2")
            self.assertTrue(update_port_binding.called)
            self.assertIn("fake_port", self.agent.cluster_host_ports)
            self.assertFalse(log_exception.called)

    def test_notify_device_updated_rpc_exception(self):
        self.agent.esx_hostname = 'fakehost-2'

        vm_port1 = samplePort("fake_port")
        vm = VM("fakevm", [vm_port1])
        with contextlib.nested(
            mock.patch.object(self.agent.ovsvapp_rpc,
                              "update_port_binding",
                              side_effect=Exception()),
            mock.patch.object(self.LOG, 'exception'),
        ) as (update_port_binding, log_exception):
            self.assertRaises(
                error.NeutronAgentError,
                self.agent._notify_device_updated, vm, "fakehost-2")
            self.assertTrue(update_port_binding.called)
            self.assertIn("fake_port", self.agent.cluster_host_ports)
            self.assertTrue(log_exception.called)

    def test_add_ports_to_host_ports(self):
        self.agent.cluster_other_ports.add("fake_port")
        self.assertNotIn("fake_port", self.agent.cluster_host_ports)
        self.agent._add_ports_to_host_ports(["fake_port"])
        self.assertIn("fake_port", self.agent.cluster_host_ports)
        self.assertNotIn("fake_port", self.agent.cluster_other_ports)

    def test_add_ports_to_other_cluster_ports(self):
        self.agent.cluster_host_ports.add("fake_port")
        self.assertNotIn("fake_port", self.agent.cluster_other_ports)
        self.agent._add_ports_to_host_ports(["fake_port"], False)
        self.assertIn("fake_port", self.agent.cluster_other_ports)
        self.assertNotIn("fake_port", self.agent.cluster_host_ports)

    def test_update_port_binding(self):
        self.agent.update_port_bindings.append("fake_port")
        with contextlib.nested(
            mock.patch.object(self.agent.ovsvapp_rpc,
                              "update_port_binding"),
            mock.patch.object(self.LOG, 'exception'),
        ) as (update_port_binding, log_exception):
            self.agent._update_port_bindings()
            self.assertTrue(update_port_binding.called)
            self.assertFalse(log_exception.called)

    def test_update_port_binding_rpc_exception(self):
        self.agent.update_port_bindings.append("fake_port")
        with contextlib.nested(
            mock.patch.object(self.agent.ovsvapp_rpc,
                              "update_port_binding",
                              side_effect=Exception()),
            mock.patch.object(self.LOG, 'exception'),
        ) as (update_port_binding, log_exception):
            self.assertRaises(
                error.NeutronAgentError,
                self.agent._update_port_bindings)
            self.assertTrue(update_port_binding.called)
            self.assertTrue(log_exception.called)

    def test_update_port_binding_null_list(self):
        self.agent.update_port_bindings = []
        with contextlib.nested(
            mock.patch.object(self.agent.ovsvapp_rpc,
                              "update_port_binding"),
            mock.patch.object(self.LOG, 'exception'),
        ) as (update_port_binding, log_exception):
            self.agent._update_port_bindings()
            self.assertFalse(update_port_binding.called)
            self.assertFalse(log_exception.called)
