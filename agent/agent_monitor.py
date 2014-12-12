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
#    under the License.from oslo.config import cfg

from neutron import context as neutron_context
from neutron.db import agents_db
from neutron.db import common_db_mixin
from neutron import manager
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.openstack.common import timeutils
from oslo.config import cfg

LOG = logging.getLogger(__name__)

AGENT_TYPE_OVSVAPP = "OVSvApp L2 Agent"

class AgentMonitor(agents_db.AgentDbMixin, common_db_mixin.CommonDbMixin):
    """Represents agent_monitor class which maintains active and inactive
       agents and reschedules its resources
    """
    active_agents = []
    inactive_agents = []
    agents = {}
    context = None
    plugin = None
    l3plugin = None
    agent_ext_support = None

    def __init__(self, notifier=None):
        super(AgentMonitor, self).__init__()
        self.notifier = notifier

    def _check_plugin_ext_support(self, extension):
        """Helper Method to check if plugin supports Agent Management
           Extension.
        """
        try:
            if self.plugin:
                return extension in self.plugin.supported_extension_aliases
        except Exception:
            LOG.debug("%s extension is not supported", extension)
        return False

    def initialize_thread(self):
        """Initialization of agent monitor thread
        """
        try:
            monitor_interval = 5
            monitor_thread = loopingcall. \
                FixedIntervalLoopingCall(self.monitor_agent_state)
            monitor_thread.start(interval=monitor_interval)
            LOG.debug("Successfully initialized agent monitor"
                      " thread with loop interval %s", monitor_interval)
        except Exception:
            LOG.exception(_("Cannot initialize agent monitor thread.."))

    def get_plugin_and_initialize(self):
        """Initializes plugin and populates list of all agents
        """
        try:
            self.context = neutron_context.get_admin_context()
            self.plugin = manager.NeutronManager.get_plugin()
            if not self.plugin:
                return False
            self.agent_ext_support = self._check_plugin_ext_support('agent')
        except Exception:
            LOG.exception(_("Failed initialization of agent monitor.."))
            return False
        return True

    def _get_eligible_ovs_vapp_agent(self, old_agent):
        chosen_agent = None
        latest_time = old_agent['heartbeat_timestamp']
        cluster_id = old_agent['configurations'].get('cluster_id')
        for agent in self.agents:
            agent_cluster_id = agent['configurations'].get('cluster_id')
            if cluster_id != agent_cluster_id:
                continue
            delta = timeutils.delta_seconds(latest_time,
                                            agent['heartbeat_timestamp'])
            if delta > 0:
                latest_time = agent['heartbeat_timestamp']
                chosen_agent = agent
        return chosen_agent

    def process_ovsvapp_agent(self, agent):
        """Inform the OVSvApp agent to set the other host into maintenance or
           shutdown mode.
        """
        try:
            LOG.debug("Processing the OVSvApp agent to set the other host "
                      "into maintenance or shutdown mode %s", agent)
            device_data = {}
            source_host = agent['configurations'].get('esx_host_name')
            chosen_agent = self._get_eligible_ovs_vapp_agent(agent)
            if chosen_agent and (chosen_agent['id'] in self.active_agents):
                device_data['assigned_agent_host'] = chosen_agent['host']
                device_data['esx_host_name'] = source_host
                device_data['ovsvapp_agent'] = agent['host']
                LOG.debug("Posting device_update RPC with target host %s",
                          chosen_agent['host'])
                self.notifier.device_update(self.context,
                                            device_data)
            else:
                LOG.debug("No eligible OVSvApp agents found for "
                          "processing")
        except Exception:
            LOG.exception(_("Unable to inform the OVSvApp agent "
                            "for host operation"))

    def _update_agent_state(self, agent_id, status):
        agent_state = {'agent': {'admin_state_up': status}}
        return self.update_agent_admin_state(self.context,
                                             agent_id,
                                             agent_state)

    def update_agent_admin_state(self, context, id, agt):
        agent_data = agt['agent']
        with context.session.begin(subtransactions=True):
            agent = self._get_agent(context, id)
            if agent['admin_state_up'] != agent_data['admin_state_up']:
                agent.update(agent_data)
                return True
        return False

    def monitor_agent_state(self):
        """Represents a thread which maintains list of active
           and inactive agents based on the heartbeat recorded
        """
        #Do nothing until plugin is initialized
        agents_to_process = []
        if not self.plugin:
            status = self.get_plugin_and_initialize()
            if not status:
                LOG.debug("Plugin not defined...returning")
                return
        if not self.agent_ext_support:
            LOG.debug("Agent extension is not loaded by plugin")
            return
        try:
            self.agents = self.plugin.get_agents(self.context,
                                filters={'agent_type': [AGENT_TYPE_OVSVAPP]})
        except Exception:
            LOG.exception(_("Unable to get agent list continue..."))
            return
        for agent in self.agents:
            agent_time_stamp = agent['heartbeat_timestamp']
            agent_id = agent['id']
            status = timeutils.is_older_than(agent_time_stamp,
                                             cfg.CONF.agent_down_time * 2)
            LOG.debug(_("for agent %(agent)s agent_state %(state)s"),
                      {'agent': agent, 'state': status})
            try:
                if not status:
                    if agent_id not in self.active_agents:
                        LOG.debug("Moving agent: %s from inactive to "
                                  "active", agent_id)
                        self.active_agents.append(agent_id)
                        self._update_agent_state(agent_id, True)
                    if agent_id in self.inactive_agents:
                        LOG.debug("Removing agent: %s from inactive "
                                  "agent list", agent_id)
                        self.inactive_agents.remove(agent_id)
                else:
                    if agent_id not in self.inactive_agents:
                        LOG.debug("Moving agent: %s from active to "
                                  "inactive", agent_id)
                        self.inactive_agents.append(agent_id)
                        if self._update_agent_state(agent_id, False):
                            agents_to_process.append(agent)
                    if agent_id in self.active_agents:
                        LOG.debug("Removing agent: %s from active "
                                  "agent list", agent_id)
                        self.active_agents.remove(agent_id)
            except Exception:
                LOG.exception(_("Exception occurred in monitor_agent_state.."))
        LOG.debug("Number of agents for processing: %s",
                  len(agents_to_process))
        for agent in agents_to_process:
            self.process_ovsvapp_agent(agent)
        return