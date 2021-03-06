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
#Implements the RPC for OVSvAPP-l2-Agent

import time

from neutron.common import constants as q_const
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.extensions import portbindings
from neutron import manager
from neutron.openstack.common import log

LOG = log.getLogger(__name__)

DEVICE = 'device'


class OVSvAppServerRpcCallback(n_rpc.RpcCallback):

    """
    This class contains extra rpc callbacks to be served for use by the
    OVSvApp Agent.
    """

    RPC_API_VERSION = '1.0'

    def __init__(self, notifier=None):
        super(OVSvAppServerRpcCallback, self).__init__()
        self.notifier = notifier

    @property
    def plugin(self):
        return manager.NeutronManager.get_plugin()

    def _get_devices_info(self, devices, plugin):
        return dict(
            (port['id'], port)
            for port in self.plugin.get_ports_from_devices(devices)
            if port and not port['device_owner'].startswith('network:')
        )

    def get_ports_for_device(self, rpc_context, **kwargs):
        """
        This method provides information about the network and port for
        a given device_id
        """
        agent_id = kwargs.get('agent_id')
        device = kwargs.get('device')
        device_id = device['id']
        LOG.debug("Device %(device_id)s details requested by agent "
                  "%(agent_id)s",
                  {'device_id': device_id, 'agent_id': agent_id})
        if not device_id:
            return False
        try_count = 3
        try:
            while try_count > 0:
                ports = self.plugin.get_ports(rpc_context,
                                         filters={'device_id': [device_id]})
                device_ports = []
                sg_port_ids = set()
                for port in ports:
                    network = self.plugin.get_network(rpc_context,
                                                 port['network_id'])
                    port.update(
                        {'network_type': network['provider:network_type'],
                         'segmentation_id':
                         network['provider:segmentation_id'],
                         'physical_network':
                         network['provider:physical_network']})

                    new_status = (q_const.PORT_STATUS_BUILD
                                  if port['admin_state_up']
                                  else q_const.PORT_STATUS_DOWN)
                    if port['status'] != new_status:
                        port['status'] = new_status

                    if 'security_groups' in port:
                        sg_port_ids.add(port['id'])

                    device_ports.append(port)
                if not device_ports:
                    try_count -= 1
                    LOG.debug("Port details could not be retrieved for "
                              "device %s ..retrying", device_id)
                    time.sleep(3)
                else:
                    LOG.debug("Device details returned by controller:"
                              " %s", device_ports)
                    # Get the SG rules for the security enabled ports
                    sg_payload = {}
                    if sg_port_ids:
                        ports = self._get_devices_info(sg_port_ids,
                                                       self.plugin)
                        sg_rules = self.plugin.security_group_rules_for_ports(
                            rpc_context, ports)
                        sg_payload[device_id] = sg_rules
                    self.notifier.device_create(rpc_context, device,
                                                device_ports, sg_payload)
                    return True
        except Exception:
            LOG.exception(_("Failed to retrieve port details for "
                            "device %s") % device_id)
        LOG.debug("Failed to retrieve ports for device %s", device_id)
        return False

    def update_port_binding(self, rpc_context, **kwargs):
        agent_id = kwargs.get('agent_id')
        port_id = kwargs.get('port_id')
        host = kwargs.get('host')
        LOG.debug("Port %(port_id)s update_port_binding() invoked by agent "
                  "%(agent_id)s for host %(host)s",
                  {'port_id': port_id, 'agent_id': agent_id, 'host': host})
        port = {'port': {portbindings.HOST_ID: host}}
        updated_port = self.plugin.update_port(rpc_context, port_id, port)
        return updated_port


class OVSvAppAgentNotifyAPI(n_rpc.RpcProxy):

    """
    Agent side of the OVSvApp rpc API.
    """
    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic=topics.AGENT):
        super(OVSvAppAgentNotifyAPI, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)

    def _get_device_topic(self, action):
        return topics.get_topic_name(self.topic,
                                     DEVICE,
                                     action)

    def device_create(self, context, device, ports, sg_rules):
        self.fanout_cast(context,
                         self.make_msg('device_create',
                                       device=device,
                                       ports=ports,
                                       sg_rules=sg_rules),
                         topic=self._get_device_topic(topics.CREATE))

    def device_update(self, context, device_data):
        self.fanout_cast(context,
                         self.make_msg('device_update',
                                       device_data=device_data),
                         topic=self._get_device_topic(topics.UPDATE))
