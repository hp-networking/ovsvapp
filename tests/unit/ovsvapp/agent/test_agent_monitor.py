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
import copy
import datetime
import mock

from oslo.config import cfg

from neutron.common import topics
from neutron import context as neutron_context
from neutron.db import agents_db
from neutron import manager
from neutron.openstack.common import loopingcall
from neutron.openstack.common import timeutils
from neutron.plugins.ovsvapp.agent import agent_monitor
from neutron.plugins.ml2 import rpc
from neutron.tests import base

AGENT_TYPE_OVSVAPP = "OVSvApp L2 Agent"

def make_active_agent(fake_id, fake_agent_type, config=None):
    agent_dict = dict(id=fake_id,
                      agent_type=fake_agent_type,
                      host='localhost_' + str(fake_id),
                      heartbeat_timestamp=timeutils.utcnow(),
                      configurations=config)
    return agent_dict


def make_inactive_agent(fake_id, fake_agent_type, delta, config=None):
    agent_dict = dict(id=fake_id,
                      agent_type=fake_agent_type,
                      host='remotehost_' + str(fake_id),
                      heartbeat_timestamp=(timeutils.utcnow() - datetime.
                                           timedelta(delta)),
                      configurations=config)
    return agent_dict


class FakePlugin(agents_db.AgentDbMixin):

    def __init__(self):
        self.notifier = rpc.AgentNotifierApi(topics.AGENT)


class TestAgentMonitor(base.BaseTestCase):

    fake_a_agent_list = []
    fake_i_agent_list = []
    fake_ovs_agent_list = []
    fake_a_agent_ids = []
    fake_i_agent_ids = []

    def setUp(self):
        super(TestAgentMonitor, self).setUp()
        cfg.CONF.set_override('core_plugin',
                              "neutron.plugins.ml2.plugin.Ml2Plugin")
        self.plugin = FakePlugin()
        self.context = neutron_context.get_admin_context()
        cfg.CONF.set_override('agent_down_time', 10)
        self.agentmon = agent_monitor.AgentMonitor(mock.Mock())
        self.agentmon.plugin = self.plugin
        self.agentmon.context = self.context
        self.agentmon.agent_ext_support = True
        self.LOG = agent_monitor.LOG

    def populate_agent_lists(self, config=None):
        self.fake_a_agent_list = []
        self.fake_a_agent_list.append(make_active_agent(
            '1111', AGENT_TYPE_OVSVAPP, config))
        self.fake_a_agent_list.append(make_active_agent(
            '2222', AGENT_TYPE_OVSVAPP, config))
        self.fake_a_agent_list.append(make_active_agent(
            '3333', AGENT_TYPE_OVSVAPP, config))

        self.fake_i_agent_list = []
        self.fake_i_agent_list.append(make_inactive_agent(
            '4444', AGENT_TYPE_OVSVAPP, 52, config))
        self.fake_i_agent_list.append(make_inactive_agent(
            '6666', AGENT_TYPE_OVSVAPP, 55, config))

        self.fake_ovs_agent_list = [make_inactive_agent('7777',
                                                        'OVS agent', 52)]

        self.fake_a_agent_ids = ['1111', '2222', '3333']
        self.fake_i_agent_ids = ['4444', '6666']

    def test_initialize_thread_exception(self):
        with mock.patch.object(loopingcall,
                               'FixedIntervalLoopingCall',
                               side_effect=Exception) as call_back_thread:
            with mock.patch.object(self.LOG, 'exception') as logger_call:
                self.agentmon.initialize_thread()
                self.assertTrue(call_back_thread.called)
                self.assertTrue(logger_call.called)

    def test_initialize_thread(self):
        with mock.patch.object(loopingcall,
                               'FixedIntervalLoopingCall'
                               ) as call_back_thread:
            with mock.patch.object(self.LOG, 'debug') as logger_debug:
                self.agentmon.initialize_thread()
                self.assertTrue(call_back_thread.called)
                self.assertTrue(logger_debug.called)

    def test_get_plugin_and_initialize(self):
        with contextlib.nested(
            mock.patch.object(neutron_context,
                              'get_admin_context',
                              return_value=self.context),
            mock.patch.object(manager.NeutronManager,
                              'get_plugin',
                              return_value=self.plugin),
            mock.patch.object(self.LOG, 'exception')
        ) as (get_context, get_plugin, logger_call):
            status = self.agentmon.get_plugin_and_initialize()
            self.assertTrue(get_context.called)
            self.assertTrue(get_plugin.called)
            self.assertTrue(status)
            self.assertFalse(logger_call.called)

    def test_get_plugin_and_initialize_exception(self):
        with contextlib.nested(
            mock.patch.object(neutron_context,
                              'get_admin_context',
                              return_value=self.context),
            mock.patch.object(manager.NeutronManager,
                              'get_plugin',
                              side_effect=Exception),
            mock.patch.object(self.LOG, 'exception')
        ) as (get_context, get_plugin, logger_call):
            status = self.agentmon.get_plugin_and_initialize()
            self.assertTrue(get_context.called)
            self.assertTrue(get_plugin.called)
            self.assertFalse(status)
            self.assertTrue(logger_call.called)

    def test_get_plugin_and_initialize_no_plugin(self):
        with contextlib.nested(
            mock.patch.object(neutron_context,
                              'get_admin_context',
                              return_value=self.context),
            mock.patch.object(manager.NeutronManager,
                              'get_plugin',
                              return_value=None),
            mock.patch.object(self.LOG, 'exception')
        ) as (get_context, get_plugin, logger_call):
            status = self.agentmon.get_plugin_and_initialize()
            self.assertTrue(get_context.called)
            self.assertTrue(get_plugin.called)
            self.assertFalse(status)
            self.assertFalse(logger_call.called)

    def test_get_eligble_ovsvapp_agent(self):
        config = {'cluster_id': 'foo'}
        self.populate_agent_lists(config)
        fake_all_agent_list = copy.deepcopy(self.fake_i_agent_list)
        fake_all_agent_list.extend(self.fake_a_agent_list)
        self.agentmon.active_agents = self.fake_a_agent_ids
        self.agentmon.inactive_agents = self.fake_i_agent_ids
        self.agentmon.agents = fake_all_agent_list
        chosen_agent = self.agentmon._get_eligible_ovs_vapp_agent(
            self.fake_i_agent_list[1])
        self.assertIsNotNone(chosen_agent)

    def test_get_eligble_ovsvapp_agent_nothing_available(self):
        config = {'cluster_id': 'foo'}
        config1 = {'cluster_id': 'foo1'}
        alien_agent = make_inactive_agent('5555', AGENT_TYPE_OVSVAPP,
                                          52, config1)
        self.populate_agent_lists(config)
        self.fake_i_agent_list.append(alien_agent)
        fake_all_agent_list = copy.deepcopy(self.fake_i_agent_list)
        fake_all_agent_list.extend(self.fake_a_agent_list)
        self.agentmon.active_agents = self.fake_a_agent_ids
        self.agentmon.inactive_agents = self.fake_i_agent_ids
        self.agentmon.agents = fake_all_agent_list
        chosen_agent = self.agentmon._get_eligible_ovs_vapp_agent(
            alien_agent)
        self.assertIsNone(chosen_agent)

    def test_process_ovsvapp_agent(self):
        dead_agent = {'configurations': {'esx_host_name': 'foo'},
                      'host': 'dead_host'}
        chosen_agent = {'configurations': {'esx_host_name': 'bar'},
                        'host': 'alive_host',
                        'id': '1111'}
        self.agentmon.active_agents = ['1111']
        with contextlib.nested(
            mock.patch.object(self.agentmon,
                              '_get_eligible_ovs_vapp_agent',
                              return_value=chosen_agent),
            mock.patch.object(self.agentmon.notifier, 'device_update'),
            mock.patch.object(self.LOG, 'exception'),
            mock.patch.object(self.LOG, 'debug')
        ) as (get_eligible_agent, device_update, exception_log, debug_log):
            self.agentmon.process_ovsvapp_agent(dead_agent)
            self.assertTrue(get_eligible_agent.called)
            self.assertFalse(exception_log.called)
            self.assertEqual(debug_log.call_count, 2)
            self.assertEqual(len(self.agentmon.active_agents), 1)
            self.assertTrue(device_update.called)

    def test_process_ovsvapp_agent_no_eligible_agents(self):
        dead_agent = {'configurations': {'esx_host_name': 'foo'},
                      'host': 'dead_host'}
        with contextlib.nested(
            mock.patch.object(self.agentmon,
                              '_get_eligible_ovs_vapp_agent',
                              return_value=None),
            mock.patch.object(self.agentmon.notifier,
                              'device_update'),
            mock.patch.object(self.LOG, 'exception'),
            mock.patch.object(self.LOG, 'debug')
        ) as (get_eligible_agent, device_update, exception_log, debug_log):
            self.agentmon.process_ovsvapp_agent(dead_agent)
            self.assertTrue(get_eligible_agent.called)
            self.assertFalse(exception_log.called)
            self.assertEqual(debug_log.call_count, 2)
            self.assertFalse(device_update.called)

    def test_process_ovsvapp_agent_exception(self):
        dead_agent = {'configurations': {'esx_host_name': 'foo'},
                      'host': 'dead_host'}
        with contextlib.nested(
            mock.patch.object(self.agentmon,
                              '_get_eligible_ovs_vapp_agent',
                              side_effect=Exception),
            mock.patch.object(self.agentmon.notifier,
                              'device_update'),
            mock.patch.object(self.LOG, 'exception'),
            mock.patch.object(self.LOG, 'debug')
        ) as (get_eligible_agent, device_update, exception_log, debug_log):
            self.agentmon.process_ovsvapp_agent(dead_agent)
            self.assertTrue(get_eligible_agent.called)
            self.assertTrue(exception_log.called)
            self.assertEqual(debug_log.call_count, 1)
            self.assertFalse(device_update.called)

    def test_monitor_agent_state(self):
        self.populate_agent_lists()
        fake_all_agent_list = copy.deepcopy(self.fake_i_agent_list)
        fake_all_agent_list.extend(self.fake_a_agent_list)
        self.agentmon.active_agents = self.fake_a_agent_ids
        self.agentmon.inactive_agents = []
        with contextlib.nested(
            mock.patch.object(self.agentmon, 'update_agent_admin_state'),
            mock.patch.object(self.agentmon, 'process_ovsvapp_agent'),
            mock.patch.object(self.plugin, 'get_agents',
                              return_value=fake_all_agent_list)
        ) as (update_agent_call, process_ovsvapp, get_agent_list):
            self.agentmon.monitor_agent_state()
            status = {'agent': {'admin_state_up': False}}
            agent_id = self.fake_i_agent_ids[1]
            self.assertTrue(get_agent_list.called)
            a_count = len(self.fake_i_agent_ids)
            self.assertEqual(update_agent_call.call_count, a_count)
            process_ovsvapp.assert_called_with(self.fake_i_agent_list[1])
            self.assertEqual(len(self.agentmon.active_agents),
                             len(self.fake_a_agent_ids))
            self.assertEqual(len(self.agentmon.inactive_agents),
                             len(self.fake_i_agent_ids))
            update_agent_call.assert_called_with(self.context,
                                                 agent_id, status)

    def test_monitor_agent_state_agent_no_plugin(self):
        self.agentmon.plugin = None
        with contextlib.nested(
            mock.patch.object(self.agentmon, 'get_plugin_and_initialize',
                              return_value=False),
            mock.patch.object(self.LOG, 'debug'),
            mock.patch.object(self.plugin, 'get_agents')
        ) as (get_plugin, debug_log, get_agent_list):
            self.agentmon.monitor_agent_state()
            self.assertTrue(get_plugin.called)
            self.assertTrue(debug_log.called)
            self.assertFalse(get_agent_list.called)

    def test_monitor_agent_state_agent_ext_not_supported(self):
        self.agentmon.agent_ext_support = False
        with contextlib.nested(
            mock.patch.object(self.LOG, 'debug'),
            mock.patch.object(self.plugin, 'get_agents')
        ) as (debug_log, get_agent_list):
            self.agentmon.monitor_agent_state()
            self.assertTrue(debug_log.called)
            self.assertFalse(get_agent_list.called)

    def test_monitor_agent_state_agent_exception_get_agents(self):
        with contextlib.nested(
            mock.patch.object(self.LOG, 'debug'),
            mock.patch.object(self.plugin, 'get_agents',
                              side_effect=Exception),
            mock.patch.object(self.LOG, 'exception')
        ) as (debug_log, get_agent_list, exception_log):
            self.agentmon.monitor_agent_state()
            self.assertFalse(debug_log.called)
            self.assertTrue(get_agent_list.called)
            self.assertTrue(exception_log.called)

    def test_monitor_agent_state_nothing_new_to_process(self):
        self.populate_agent_lists()
        fake_all_agent_list = copy.deepcopy(self.fake_i_agent_list)
        fake_all_agent_list.extend(self.fake_a_agent_list)
        self.agentmon.active_agents = self.fake_a_agent_ids
        self.agentmon.inactive_agents = self.fake_i_agent_ids
        with contextlib.nested(
            mock.patch.object(self.agentmon, 'update_agent_admin_state'),
            mock.patch.object(self.agentmon, 'process_ovsvapp_agent'),
            mock.patch.object(self.plugin, 'get_agents',
                              return_value=fake_all_agent_list)
        ) as (update_agent_call, process_ovsvapp, get_agent_list):
            self.agentmon.monitor_agent_state()
            self.assertTrue(get_agent_list.called)
            self.assertEqual(len(self.agentmon.active_agents),
                             len(self.fake_a_agent_ids))
            self.assertEqual(len(self.agentmon.inactive_agents),
                             len(self.fake_i_agent_ids))
            self.assertFalse(update_agent_call.called)
            self.assertFalse(process_ovsvapp.called)

    def test_monitor_agent_state_exception_in_update(self):
        self.populate_agent_lists()
        fake_all_agent_list = copy.deepcopy(self.fake_i_agent_list)
        fake_all_agent_list.extend(self.fake_a_agent_list)
        self.agentmon.active_agents = self.fake_a_agent_ids
        self.agentmon.inactive_agents = []
        with contextlib.nested(
            mock.patch.object(self.agentmon, 'update_agent_admin_state',
                              side_effect=Exception),
            mock.patch.object(self.agentmon, 'process_ovsvapp_agent'),
            mock.patch.object(self.plugin, 'get_agents',
                              return_value=fake_all_agent_list),
            mock.patch.object(self.LOG, 'exception')
        ) as (update_agent, process_ovsvapp, get_agent_list, exception_log):
            self.agentmon.monitor_agent_state()
            self.assertTrue(get_agent_list.called)
            self.assertEqual(update_agent.call_count, 2)
            self.assertTrue(exception_log.called)
            self.assertFalse(process_ovsvapp.called)

    def test_monitor_agent_state_agent_active_to_inactive(self):
        self.populate_agent_lists()
        fake_all_agent_list = copy.deepcopy(self.fake_i_agent_list)
        fake_all_agent_list.extend(self.fake_a_agent_list)
        self.agentmon.active_agents = self.fake_a_agent_ids
        self.agentmon.active_agents += self.fake_i_agent_ids
        self.agentmon.inactive_agents = []
        with contextlib.nested(
            mock.patch.object(self.agentmon, 'update_agent_admin_state'),
            mock.patch.object(self.agentmon, 'process_ovsvapp_agent'),
            mock.patch.object(self.plugin, 'get_agents',
                              return_value=fake_all_agent_list)
        ) as (update_agent_call, process_ovsvapp, get_agent_list):
            self.agentmon.monitor_agent_state()
            status = {'agent': {'admin_state_up': False}}
            agent_id = self.fake_i_agent_ids[1]
            self.assertTrue(get_agent_list.called)
            a_count = len(self.fake_i_agent_ids)
            self.assertEqual(update_agent_call.call_count, a_count)
            self.assertEqual(len(self.agentmon.active_agents),
                             len(self.fake_a_agent_ids))
            self.assertEqual(len(self.agentmon.inactive_agents),
                             len(self.fake_i_agent_ids))
            update_agent_call.assert_called_with(self.context,
                                                 agent_id, status)
            self.assertEqual(process_ovsvapp.call_count, a_count)

    def test_monitor_agent_state_agent_inactive_to_active(self):
        self.populate_agent_lists()
        fake_all_agent_list = copy.deepcopy(self.fake_i_agent_list)
        fake_all_agent_list.extend(self.fake_a_agent_list)
        self.agentmon.inactive_agents = self.fake_i_agent_ids
        self.agentmon.inactive_agents += self.fake_a_agent_ids
        self.agentmon.active_agents = []
        with contextlib.nested(
            mock.patch.object(self.agentmon, 'update_agent_admin_state'),
            mock.patch.object(self.agentmon, 'process_ovsvapp_agent'),
            mock.patch.object(self.plugin, 'get_agents',
                              return_value=fake_all_agent_list)
        ) as (update_agent_call, process_ovsvapp, get_agent_list):
            self.agentmon.monitor_agent_state()
            status = {'agent': {'admin_state_up': True}}
            agent_id = self.fake_a_agent_ids[2]
            self.assertTrue(get_agent_list.called)
            a_count = len(self.fake_a_agent_ids)
            self.assertEqual(update_agent_call.call_count, a_count)
            self.assertEqual(len(self.agentmon.active_agents),
                             len(self.fake_a_agent_ids))
            self.assertEqual(len(self.agentmon.inactive_agents),
                             len(self.fake_i_agent_ids))
            update_agent_call.assert_called_with(self.context,
                                                 agent_id, status)
            self.assertFalse(process_ovsvapp.called)
