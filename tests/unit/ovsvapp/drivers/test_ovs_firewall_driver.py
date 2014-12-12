# Copyright (c) 2012 OpenStack Foundation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#F
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import contextlib
import mock
from neutron.plugins.ovsvapp.drivers import ovs_firewall as ovs_fw
from neutron.tests import base
from oslo.config import cfg
import threading

fake_port = {'security_group_source_groups': 'abc',
             'mac_address': '00:11:22:33:44:55',
             'network_id': "netid",
             'id': "123",
             'security_groups': "abc",
             'segmentation_id': "100",
             "security_group_rules": [
                 {"direction": "ingress",
                  "protocol": "tcp",
                  "port_range_min": 2001,
                  "port_range_max": 2009,
                  "source_port_range_min": 67,
                  "source_port_range_max": 77,
                  "ethertype": "IPv4",
                  "source_ip_prefix": "150.1.1.0/22",
                  "dest_ip_prefix": "170.1.1.0/22"}]}


class TestOVSFirewallDriver(base.BaseTestCase):
    def setUp(self):
        super(TestOVSFirewallDriver, self).setUp()
        cfg.CONF.set_override('security_bridge',
                              "br-fake:fake_if", 'SECURITYGROUP')
        with contextlib.nested(
            mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.'
                       'get_port_ofport'),
            mock.patch('neutron.agent.linux.ovs_lib.OVSBridge.__init__'),
            mock.patch('neutron.plugins.ovsvapp.agent.'
                'portCache'),
            mock.patch('neutron.plugins.ovsvapp.drivers.ovs_firewall.'
                       'OVSFirewallDriver.setup_base_flows')
                  ):
            self.ovs_firewall = ovs_fw.OVSFirewallDriver()
            self.ovs_firewall.sg_br = mock.Mock()

    def test_setup_base_flows(self):
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall.sg_br, 'add_flow'),
            mock.patch.object(self.ovs_firewall, 'add_icmp_learn_flow')
                              ) as (add_flow_fn, add_icmp_learn_flow_fn):
            self.ovs_firewall.setup_base_flows()
            self.assertTrue(add_flow_fn.called)
            self.assertTrue(add_icmp_learn_flow_fn.called)

    def test_prepare_port_filter(self):
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall, 'get_lock'),
            mock.patch.object(self.ovs_firewall, 'release_lock'),
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred'),
            mock.patch.object(self.ovs_firewall, '_setup_flows'),
            mock.patch.object(self.ovs_firewall, '_add_flows')
                              ) as (get_lock_fn, release_lock_fn, deferred_fn,
                                    _setup_flows_fn, _add_flows_fn):
            self.ovs_firewall.prepare_port_filter(fake_port)
            self.assertTrue(get_lock_fn.called)
            self.assertTrue(release_lock_fn.called)
            self.assertTrue(deferred_fn.called)
            self.assertTrue(_setup_flows_fn.called)
            self.assertTrue(_add_flows_fn.called)

    def test_prepare_port_filter_exception(self):
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall, 'get_lock'),
            mock.patch.object(self.ovs_firewall, 'release_lock'),
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred',
                              side_effect=Exception()),
            mock.patch.object(self.ovs_firewall, '_setup_flows'),
            mock.patch.object(self.ovs_firewall, '_add_flows'),
            mock.patch.object(ovs_fw.LOG, 'exception')
                              ) as (get_lock_fn, release_lock_fn, deferred_fn,
                                    _setup_flows_fn, _add_flows_fn,
                                    logger_exc):
            self.ovs_firewall.prepare_port_filter(fake_port)
            self.assertTrue(get_lock_fn.called)
            self.assertTrue(release_lock_fn.called)
            self.assertTrue(deferred_fn.called)
            self.assertFalse(_setup_flows_fn.called)
            self.assertFalse(_add_flows_fn.called)
            self.assertTrue(logger_exc.called)

    def test_update_port_filter(self):
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall, 'get_lock'),
            mock.patch.object(self.ovs_firewall, 'release_lock'),
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred'),
            mock.patch.object(self.ovs_firewall, '_setup_flows'),
            mock.patch.object(self.ovs_firewall, '_add_flows'),
            mock.patch.object(self.ovs_firewall, '_remove_flows')
                              ) as (get_lock_fn, release_lock_fn, deferred_fn,
                                    _setup_flows_fn,
                                    _add_flows_fn, _remove_flows_fn):
            self.ovs_firewall.filtered_ports = {"123": fake_port}
            self.ovs_firewall.update_port_filter(fake_port)
            self.assertTrue(get_lock_fn.called)
            self.assertTrue(release_lock_fn.called)
            self.assertTrue(deferred_fn.called)
            self.assertTrue(_setup_flows_fn.called)
            self.assertTrue(_add_flows_fn.called)
            self.assertTrue(_remove_flows_fn.called)

    def test_update_port_filter_exception(self):
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall, 'get_lock'),
            mock.patch.object(self.ovs_firewall, 'release_lock'),
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred'),
            mock.patch.object(self.ovs_firewall, '_setup_flows'),
            mock.patch.object(self.ovs_firewall, '_add_flows',
                              side_effect=Exception()),
            mock.patch.object(self.ovs_firewall, '_remove_flows'),
            mock.patch.object(ovs_fw.LOG, 'exception')
                              ) as (get_lock_fn, release_lock_fn, deferred_fn,
                                    _setup_flows_fn, _add_flows_fn,
                                    _remove_flows_fn, logger_exc):
            self.ovs_firewall.filtered_ports = {"123": fake_port}
            self.ovs_firewall.update_port_filter(fake_port)
            self.assertTrue(get_lock_fn.called)
            self.assertTrue(release_lock_fn.called)
            self.assertTrue(deferred_fn.called)
            self.assertTrue(_setup_flows_fn.called)
            self.assertTrue(_add_flows_fn.called)
            self.assertTrue(_remove_flows_fn.called)
            self.assertTrue(logger_exc.called)

    def test_remove_port_filter(self):
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall, 'get_lock'),
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred'),
            mock.patch.object(self.ovs_firewall.sg_br, '_remove_flows'),
            mock.patch.object(self.ovs_firewall, 'release_lock'),
            mock.patch.object(self.ovs_firewall, 'remove_lock')
                              ) as (get_lock_fn, deferred_fn,
                                    _remove_flows_fn, release_lock_fn,
                                    remove_lock_fn):
            self.ovs_firewall.filtered_ports = {"123": fake_port}
            self.ovs_firewall.remove_port_filter("123")
            self.assertTrue(get_lock_fn.called)
            self.assertTrue(release_lock_fn.called)
            self.assertTrue(remove_lock_fn.called)

    def test_remove_port_filter_exception(self):
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall, 'get_lock'),
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred'),
            mock.patch.object(self.ovs_firewall, '_remove_flows',
                              side_effect=Exception()),
            mock.patch.object(self.ovs_firewall, 'release_lock'),
            mock.patch.object(self.ovs_firewall, 'remove_lock'),
            mock.patch.object(ovs_fw.LOG, 'exception')
                              ) as (get_lock_fn, deferred_fn,
                                    _remove_flows_fn, release_lock_fn,
                                    remove_lock_fn, logger_exc):
            self.ovs_firewall.filtered_ports = {"123": fake_port}
            self.ovs_firewall.remove_port_filter("123")
            self.assertTrue(get_lock_fn.called)
            self.assertTrue(release_lock_fn.called)
            self.assertTrue(remove_lock_fn.called)
            self.assertTrue(logger_exc.called)

    def test_clean_port_filters(self):
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall, 'get_lock'),
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred'),
            mock.patch.object(self.ovs_firewall, '_remove_flows'),
            mock.patch.object(self.ovs_firewall, 'release_lock'),
            mock.patch.object(self.ovs_firewall, 'remove_lock')
                              ) as (get_lock_fn, deferred_fn,
                                    _remove_flows_fn, release_lock_fn,
                                    remove_lock_fn):
            self.ovs_firewall.filtered_ports = {"123": fake_port}
            self.ovs_firewall.clean_port_filters(fake_port)
            self.assertTrue(get_lock_fn.called)
            self.assertTrue(deferred_fn.called)
            self.assertFalse(_remove_flows_fn.called)
            self.assertTrue(release_lock_fn.called)
            self.assertTrue(remove_lock_fn.called)

    def test_clean_port_filters_exception(self):
        with contextlib.nested(
            mock.patch.object(self.ovs_firewall, 'get_lock'),
            mock.patch.object(self.ovs_firewall.sg_br, 'deferred'),
            mock.patch.object(self.ovs_firewall, '_remove_flows',
                              side_effect=Exception()),
            mock.patch.object(self.ovs_firewall, 'release_lock'),
            mock.patch.object(self.ovs_firewall, 'remove_lock'),
            mock.patch.object(ovs_fw.LOG, 'exception')
                              ) as (get_lock_fn, deferred_fn,
                                    _remove_flows_fn, release_lock_fn,
                                    remove_lock_fn, logger_exc):
            self.ovs_firewall.filtered_ports = {"1": fake_port}
            ports = ['1']
            self.ovs_firewall.clean_port_filters(ports)
            self.assertTrue(get_lock_fn.called)
            self.assertTrue(deferred_fn.called)
            self.assertTrue(_remove_flows_fn.called)
            self.assertTrue(release_lock_fn.called)
            self.assertTrue(remove_lock_fn.called)
            self.assertTrue(logger_exc.called)

    def test_add_flows(self):
        deferred_obj = mock.Mock()
        fake_port1 = {'security_group_source_groups': 'abc',
             'mac_address': '00:11:22:33:44:55',
             'network_id': "netid",
             'id': "123",
             'security_groups': "abc",
             'segmentation_id': "100",
             "security_group_rules": [
                 {"direction": "egress",
                  "protocol": "udp",
                  "port_range_min": 2001,
                  "port_range_max": 2009,
                  "source_port_range_min": 67,
                  "source_port_range_max": 77,
                  "ethertype": "IPv4",
                  "source_ip_prefix": "150.1.1.0/22",
                  "dest_ip_prefix": "170.1.1.0/22"}]}
        with contextlib.nested(
            mock.patch.object(deferred_obj, 'add_flow'),
            mock.patch.object(self.ovs_firewall, 'add_flow_with_range')
                              ) as (add_flow_fn, add_flow_with_range_fn):
            self.ovs_firewall._add_flows(deferred_obj, fake_port)
            self.ovs_firewall._add_flows(deferred_obj, fake_port1)
            fake_port1["security_group_rules"][0]["protocol"] = 'icmp'
            self.ovs_firewall._add_flows(deferred_obj, fake_port1)
            fake_port1["security_group_rules"][0]["protocol"] = 'ip'
            self.ovs_firewall._add_flows(deferred_obj, fake_port1)
            fake_port1["security_group_rules"][0]["protocol"] = None
            fake_port1["security_group_rules"][0]["ethertype"] = 'IPv6'
            self.ovs_firewall._add_flows(deferred_obj, fake_port1)
            self.assertTrue(add_flow_with_range_fn.called)

    def test_setup_flows(self):
        deferred_obj = mock.Mock()
        with contextlib.nested(
            mock.patch.object(deferred_obj, 'add_flow')):
            self.ovs_firewall._setup_flows(deferred_obj, fake_port)

    def test_remove_flows(self):
        deferred_obj = mock.Mock()
        with mock.patch.object(deferred_obj, 'delete_flows') as delete_flow_fn:
            self.ovs_firewall.filtered_ports = {"123": fake_port}
            self.ovs_firewall._remove_flows(deferred_obj, fake_port)
            self.assertTrue(delete_flow_fn.called)

    def test_add_flow_with_range(self):
        deferred_obj = mock.Mock()
        flows = {}
        with mock.patch.object(deferred_obj, 'add_flow') as add_flow_fn:
            self.ovs_firewall.add_flow_with_range(deferred_obj, flows)
            self.assertTrue(add_flow_fn.called)

    def test_add_ports_to_filter(self):
        with mock.patch.object(self.ovs_firewall, '_get_mini_port'
                               ) as get_mini_port_fn:
            ports = [fake_port]
            self.ovs_firewall.add_ports_to_filter(ports)
            self.assertTrue(get_mini_port_fn.called)

    def test_get_lock(self):
        self.ovs_firewall.get_lock('123')

    def test_release_lock(self):
        self.ovs_firewall.locks = {'123': {}}
        self.ovs_firewall.locks['123'] = threading.RLock()
        self.ovs_firewall.locks['123'].acquire()
        self.ovs_firewall.release_lock('123')

    def test_remove_lock(self):
        self.ovs_firewall.locks = {'123': {}}
        self.ovs_firewall.locks['123'] = threading.RLock()
        self.ovs_firewall.locks['123'].acquire()
        self.ovs_firewall.remove_lock('123')

    def test_filter_defer_apply(self):
        self.ovs_firewall.filter_defer_apply_on()
        self.assertTrue(self.ovs_firewall._defer_apply)
        self.ovs_firewall.filter_defer_apply_off()
        self.assertFalse(self.ovs_firewall._defer_apply)
