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

from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.extensions import portbindings
from neutron.openstack.common import log
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import mech_agent
from neutron.plugins.ovsvapp.agent import agent_monitor
from neutron.plugins.ovsvapp.ml2 import ovsvapp_rpc
from oslo.config import cfg

LOG = log.getLogger(__name__)

AGENT_MONITOR = [
     cfg.BoolOpt('enable_agent_monitor', default=True,
                 help=_('To monitor the OVSvApp Agents'))
]

cfg.CONF.register_opts(AGENT_MONITOR)
CONF = cfg.CONF

AGENT_TYPE_OVSVAPP = "OVSvApp L2 Agent"
OVSVAPP = 'ovsvapp'


class OVSvAppAgentMechanismDriver(
        mech_agent.SimpleAgentMechanismDriverBase):
    """
    Attach to networks using OVSvApp Agent.
    The OVSvAppAgentMechanismDriver integrates the ml2 plugin with the
    OVSvApp Agent. Port binding with this driver requires the
    OVSvApp Agent to be running on the port's host, and that agent
    to have connectivity to at least one segment of the port's
    network.
    """
    def __init__(self):
        super(OVSvAppAgentMechanismDriver, self).__init__(
            AGENT_TYPE_OVSVAPP,
            portbindings.VIF_TYPE_OTHER,
            {portbindings.CAP_PORT_FILTER: True})
        self._start_rpc_listeners()
        if CONF.enable_agent_monitor:
            self._check_and_start_agent_monitor(self.notifier)

    def check_segment_for_agent(self, segment, agent):
        LOG.debug("Checking segment: %(segment)s ", {'segment': segment})
        if segment[api.NETWORK_TYPE] in ['vlan', 'vxlan']:
            return True
        else:
            return False

    def _check_and_start_agent_monitor(self, notifier=None):
        self.agent_monitor = agent_monitor.AgentMonitor(notifier)
        self.agent_monitor.initialize_thread()

    def _start_rpc_listeners(self):
        self.notifier = ovsvapp_rpc.OVSvAppAgentNotifyAPI(topics.AGENT)
        self.endpoints = [ovsvapp_rpc.OVSvAppServerRpcCallback(self.notifier)]
        self.topic = OVSVAPP
        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(self.topic, self.endpoints, fanout=False)
        return self.conn.consume_in_threads()
