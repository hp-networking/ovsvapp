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

import eventlet
import socket
import sys
import threading
import time

from neutron.agent.linux import ovs_lib
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import config as common_config
from neutron.common import constants as q_const
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils as q_utils
from neutron import context
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.plugins.common import constants as p_const
from neutron.plugins.openvswitch.agent import ovs_neutron_agent as ovs_agent
from neutron.plugins.openvswitch.common import constants
from neutron.plugins.ovsvapp.agent import agent
from neutron.plugins.ovsvapp.common import model
from neutron.plugins.ovsvapp.common import error
from neutron.plugins.ovsvapp.common import utils
from neutron.plugins.ovsvapp.drivers import manager
from neutron.plugins.ovsvapp.utils import resource_util
from oslo.config import cfg
from six import moves


LOG = logging.getLogger(__name__)

DEFAULT_BRIDGE_MAPPINGS = []
DEFAULT_TUNNEL_TYPES = []

OVSVAPP_OPTS = [
    cfg.StrOpt('tenant_network_type', default='vlan',
               help=_('Network type for tenant networks - vlan, vxlan')),
    cfg.StrOpt('integration_bridge', default="default",
               help=_('Integration Bridge')),
    cfg.ListOpt('bridge_mappings', default=DEFAULT_BRIDGE_MAPPINGS,
                help=_('Bridge mappings')),
    cfg.StrOpt('tunnel_bridge', default='br-tun',
               help=_('Tunnel Bridge')),
    cfg.StrOpt('local_ip', default='',
               help=_('Local IP address of VXLAN tunnel endpoints')),
]

OVSVAPPAGENT_OPTS = [
    cfg.IntOpt('report_interval', default=4,
               help=_('Seconds between nodes reporting state to server')),
    cfg.IntOpt('polling_interval', default=2,
               help=_('The number of seconds the agent will wait between '
                      'polling for local device changes')),
    cfg.IntOpt('veth_mtu', default=1500,
               help=_('MTU size of veth interfaces')),
    cfg.ListOpt('tunnel_types', default=DEFAULT_TUNNEL_TYPES,
                help=_("Network types supported by the agent - vxlan")),
    cfg.IntOpt('vxlan_udp_port', default=p_const.VXLAN_UDP_PORT,
               help=_("The UDP port to use for VXLAN tunnels.")),
    cfg.BoolOpt('agent_maintenance', default=False,
                help=_('Turn on this flag during agent updates to help '
                       'prevent datapath outage')),
]

VMWARE_OPTS = [
    cfg.StrOpt('esx_hostname', default="default",
               help=_('ESX host name where this OVSvApp is hosted')),
    cfg.BoolOpt('esx_maintenance_mode', default=True,
                help=_('Set host into maintenance mode')),
    cfg.BoolOpt('cert_check', default=False,
                help=_('Enable SSL certificate check for vCenter')),
    cfg.StrOpt('cert_path', default='/etc/ssl/certs/certs.pem',
               help=_('Certificate chain path containing cacert of vCenters')),
]

SECURITYGROUP_OPTS = [
    cfg.StrOpt('security_bridge',
               default=None,
               help=_("<security_bridge>:<phy_interface>")),
    cfg.BoolOpt('defer_apply',
                default=True,
                help=_('Enable defer_apply on security bridge')),
]

cfg.CONF.register_opts(OVSVAPP_OPTS, "OVSVAPP")
cfg.CONF.register_opts(OVSVAPPAGENT_OPTS, "OVSVAPPAGENT")
cfg.CONF.register_opts(VMWARE_OPTS, "VMWARE")
cfg.CONF.register_opts(SECURITYGROUP_OPTS, "SECURITYGROUP")
CONF = cfg.CONF

SEC_TO_INT_PATCH = "patch-integration"
INT_TO_SEC_PATCH = "patch-security"

AGENT_TYPE_OVSVAPP = "OVSvApp L2 Agent"

DEVICE = 'device'
OVSVAPP = 'ovsvapp'

ports_dict = {}
ovsvapplock = threading.RLock()
network_port_count = {}


class portCache():
    def __init__(self):
        pass

    def getPortVlan(self, portid):
        if portid in ports_dict:
            return ports_dict[portid].vlanid


class portInfo():
    def __init__(self, vlanid, mac_addr, sec_gps, fixed_ips, admin_state_up,
                 network_id, vm_uuid):
        self.vlanid = vlanid
        self.mac_addr = mac_addr
        self.sec_gps = sec_gps
        self.fixed_ips = fixed_ips
        self.admin_state_up = admin_state_up
        self.network_id = network_id
        self.vm_uuid = vm_uuid


class OVSVAppSecurityGroupAgent(ovs_agent.OVSSecurityGroupAgent):
    """
    OVSvApp derived class for OVSSecurityGroupAgent to override
    the behaviour of deferred refresh of firewall
    """
    def __init__(self, context, plugin_rpc, root_helper, defer_apply):
        self.context = context
        self.plugin_rpc = plugin_rpc
        self.root_helper = root_helper
        self.init_firewall(defer_apply)
        LOG.info(_("OVSVAppSecurityGroupAgent initialized"))

    def add_devices_to_filter(self, devices):
        if not devices:
            return
        self.firewall.add_ports_to_filter(devices)

    def ovsvapp_sg_update(self, port_rules):
        for port in port_rules:
            if port in self.firewall.ports:
                self.firewall.prepare_port_filter(port_rules[port])

    def remove_devices_filter(self, device_id):
        if not device_id:
            return
        LOG.info(_("Remove device filter for %r"), device_id)
        self.firewall.remove_port_filter(device_id)

    def prepare_firewall(self, device_ids):
        LOG.info(_("Prepare firewall rules %s"), len(device_ids))
        dev_list = list(device_ids)
        if len(dev_list) > 10:
            sublists = [dev_list[x:x + 10] for x in xrange(0, len(dev_list),
                                                           10)]
        else:
            sublists = [dev_list]
        for dev_ids in sublists:
            devices = self.plugin_rpc.security_group_rules_for_devices(
                self.context, dev_ids)
            for device in devices.values():
                if device['id'] in dev_ids:
                    self.firewall.prepare_port_filter(device)

    def refresh_firewall(self, device_ids=None):
        LOG.info(_("Refresh firewall rules"))
        if not device_ids:
            device_ids = self.firewall.ports.keys()
            if not device_ids:
                LOG.info(_("No ports here to refresh firewall"))
                return
        dev_list = list(device_ids)
        if len(dev_list) > 10:
            sublists = [dev_list[x:x + 10] for x in xrange(0, len(dev_list),
                                                           10)]
        else:
            sublists = [dev_list]

        for dev_ids in sublists:
            devices = self.plugin_rpc.security_group_rules_for_devices(
                self.context, dev_ids)
            for device in devices.values():
                if device['id'] in dev_ids:
                    self.firewall.update_port_filter(device)

    def _security_group_updated(self, security_groups, attribute):
        ovsvapplock.acquire()
        try:
            super(OVSVAppSecurityGroupAgent, self)._security_group_updated(
                security_groups, attribute)
        finally:
            ovsvapplock.release()

    def prepare_port_filters(self, own_devices, other_devices):
        """Configure port filters for devices.

        This routine prepares firewall rules after the agent receives devices
        create notifications typically when an agent restarts or if the
        devices belong to other ESX hosts.

        :param own_devices: set containing identifiers for devices
        belonging to this ESX host
        :param other_devices: set containing identifiers for
        devices belonging to other ESX hosts within the Cluster
        """
        if own_devices:
            LOG.info(_("Preparing firewall for %d devices")
                     % len(own_devices))
            self.prepare_firewall(own_devices)
        if other_devices:
            LOG.info(_("Preparing firewall for %d devices")
                     % len(other_devices))
            self.prepare_firewall(other_devices)

    def refresh_port_filters(self, own_devices, other_devices):
        """Update port filters for devices.

        This routine refreshes firewall rules when devices have been
        updated, or when there are changes in security group membership
         or rules.

        :param own_devices: set containing identifiers for devices
        belonging to this ESX host
        :param other_devices: set containing identifiers for
        devices belonging to other ESX hosts within the Cluster
        """
        # These data structures are cleared here in order to avoid
        # losing updates occurring during firewall refresh
        ovsvapplock.acquire()
        try:
            devices_to_refilter = self.devices_to_refilter
            global_refresh_firewall = self.global_refresh_firewall
            self.devices_to_refilter = set()
            self.global_refresh_firewall = False
            LOG.info(_("Going to refresh for devices: %s")
                     % devices_to_refilter)
        finally:
            ovsvapplock.release()
        if global_refresh_firewall:
            LOG.debug(_("Refreshing firewall for all filtered devices"))
            self.firewall.clean_port_filters(other_devices)
            self.refresh_firewall()
        else:
            own_devices = (own_devices & devices_to_refilter)
            other_devices = (other_devices & devices_to_refilter)
            self.firewall.clean_port_filters(other_devices)
            if own_devices:
                LOG.info(_("Refreshing firewall for %d devices")
                         % len(own_devices))
                self.refresh_firewall(own_devices)
            if other_devices:
                LOG.info(_("Refreshing firewall for %d devices")
                         % len(other_devices))
                self.prepare_firewall(other_devices)


# A class to represent a VIF (i.e., a port that has 'iface-id' and 'vif-mac'
# attributes set).
class LocalVLANMapping:
    """
    Maps Global VNI to local VLAN id
    """
    def __init__(self, vlan, network_type, segmentation_id, cluster_id):
        self.vlan = vlan
        self.network_type = network_type
        self.segmentation_id = segmentation_id
        self.cluster_id = cluster_id


class OVSvAppL2Agent(agent.Agent, ovs_agent.OVSNeutronAgent,
                     n_rpc.RpcCallback,
                     sg_rpc.SecurityGroupAgentRpcCallbackMixin):

    """
    OVSvApp L2 Agent
    """
    RPC_API_VERSION = '1.1'

    def __init__(self):
        agent.Agent.__init__(self)
        n_rpc.RpcCallback.__init__(self)
        common_config.init(sys.argv[1:])
        common_config.setup_logging()
        self.hostname = socket.getfqdn()
        self.esx_hostname = CONF.VMWARE.esx_hostname
        self.esx_maintenance_mode = CONF.VMWARE.esx_maintenance_mode
        self.cluster_id = None
        self.cluster_devices = set()
        self.devices_to_filter = set()
        self.cluster_host_ports = set()
        self.cluster_other_ports = set()
        self.run_refresh_firewall_loop = True
        self.refresh_firewall_required = False
        self.cluster_dvs_info = \
            (manager.get_cluster_dvs_mapping())[0].split(":")
        self.cluster_path = self.cluster_dvs_info[0]
        self.agent_state = {
            'binary': 'ovsvapp-agent',
            'host': self.hostname,
            'topic': topics.AGENT,
            'configurations': {'esx_host_name': self.esx_hostname,
                               'cluster_id': self.cluster_id},
            'agent_type': AGENT_TYPE_OVSVAPP,
            'start_flag': True}
        self.veth_mtu = CONF.OVSVAPPAGENT.veth_mtu
        self.use_veth_interconnection = False
        self.agent_under_maintenance = CONF.OVSVAPPAGENT.agent_maintenance
        self.root_helper = cfg.CONF.AGENT.root_helper
        self.int_br = ovs_lib.OVSBridge(CONF.OVSVAPP.integration_bridge,
                                        self.root_helper)
        if not self.agent_under_maintenance:
            self.setup_integration_br()
            LOG.info(_("Integration bridge successfully set"))
            self.setup_security_br()
        else:
            self.check_integration_br()
            self.recover_security_br()
        self.init_parameters()
        self.setup_rpc()
        defer_apply = CONF.SECURITYGROUP.defer_apply
        self.update_port_bindings = []
        self.sg_agent = OVSVAppSecurityGroupAgent(self.context,
                                                  self.plugin_rpc,
                                                  self.root_helper,
                                                  defer_apply)
        self.setup_report_states()

    def init_parameters(self):
        self.tenant_network_type = CONF.OVSVAPP.tenant_network_type
        if self.tenant_network_type == p_const.TYPE_VLAN:
            self.bridge_mappings = \
                q_utils.parse_mappings(CONF.OVSVAPP.bridge_mappings)
            if not self.agent_under_maintenance:
                self.setup_physical_bridges(self.bridge_mappings)
                LOG.info(_("Physical bridges successfully set"))
                self._init_ovs_flows(self.bridge_mappings)
            else:
                self.recover_physical_bridges(self.bridge_mappings)
        else:
            self.available_local_vlans = set(moves.xrange(q_const.MIN_VLAN_TAG,
                                                          q_const.MAX_VLAN_TAG
                                                          ))
            self.tunnel_types = CONF.OVSVAPPAGENT.tunnel_types
            # For now l2_pop and arp_responder are disabled
            # Once enabled, their values will be read from ini file
            self.l2_pop = False
            self.arp_responder_enabled = False
            self.local_vlan_map = {}
            self.tun_br_ofports = {p_const.TYPE_VXLAN: {}}
            self.polling_interval = CONF.OVSVAPPAGENT.polling_interval
            self.enable_tunneling = True
            self.local_ip = CONF.OVSVAPP.local_ip
            self.vxlan_udp_port = CONF.OVSVAPPAGENT.vxlan_udp_port
            self.tun_br = None
            if not self.agent_under_maintenance:
                self.setup_tunnel_br(CONF.OVSVAPP.tunnel_bridge)
                LOG.info(_("Tunnel bridge successfully set"))
            else:
                self.recover_tunnel_br(CONF.OVSVAPP.tunnel_bridge)

    def check_integration_br(self):
        '''Check if the integration bridge is still existing.

        :param bridge_name: the name of the integration bridge.
        '''
        if not self.int_br.bridge_exists(CONF.OVSVAPP.integration_bridge):
            LOG.error(_("Integration bridge %(bridge)s does not exist."
                        "Agent terminated!"),
                      {'bridge': CONF.OVSVAPP.integration_bridge})
            sys.exit(1)

    def recover_tunnel_br(self, tun_br_name=None):
        '''Setup the tunnel bridge.

        :param tun_br_name: the name of the tunnel bridge.
        '''
        self.tun_br = ovs_lib.OVSBridge(tun_br_name, self.root_helper)

        self.patch_tun_ofport = self.int_br.get_port_ofport(
            cfg.CONF.OVS.int_peer_patch_port)
        self.patch_int_ofport = self.tun_br.get_port_ofport(
            cfg.CONF.OVS.tun_peer_patch_port)
        if int(self.patch_tun_ofport) < 0 or int(self.patch_int_ofport) < 0:
            LOG.error(_("Failed to find OVS tunnel patch port(s). Cannot have "
                        "tunneling enabled on this agent, since this version "
                        "of OVS does not support tunnels or patch ports. "
                        "Agent terminated!"))
            sys.exit(1)

    def recover_physical_bridges(self, bridge_mappings):
        '''Recover data from the physical network bridges.

        :param bridge_mappings: map physical network names to bridge names.
        '''
        self.phys_brs = {}
        self.int_ofports = {}
        self.phys_ofports = {}
        ovs_bridges = ovs_lib.get_bridges(self.root_helper)
        for physical_network, bridge in bridge_mappings.iteritems():
            LOG.info(_("Mapping physical network %(physical_network)s to "
                       "bridge %(bridge)s"),
                     {'physical_network': physical_network,
                      'bridge': bridge})
            # setup physical bridge
            if bridge not in ovs_bridges:
                LOG.error(_("Bridge %(bridge)s for physical network "
                            "%(physical_network)s does not exist. Agent "
                            "terminated!"),
                          {'physical_network': physical_network,
                           'bridge': bridge})
                sys.exit(1)
            br = ovs_lib.OVSBridge(bridge, self.root_helper)
            self.phys_brs[physical_network] = br
            # interconnect physical and integration bridges using veth/patch
            # ports
            int_if_name = self.get_peer_name(constants.PEER_INTEGRATION_PREFIX,
                                             bridge)
            phys_if_name = self.get_peer_name(constants.PEER_PHYSICAL_PREFIX,
                                              bridge)
            int_ofport = self.int_br.get_port_ofport(int_if_name)
            phys_ofport = br.get_port_ofport(phys_if_name)
            if int(phys_ofport) < 0 or int(int_ofport) < 0:
                LOG.error(_("Patch ports missing for bridge %(bridge)s for "
                            "physical network %(physical_network)s. Agent "
                            "terminated!"),
                          {'physical_network': physical_network,
                           'bridge': bridge})
                sys.exit(1)
            self.int_ofports[physical_network] = int_ofport
            self.phys_ofports[physical_network] = phys_ofport

    def tunnel_sync_rpc_loop(self):
        """
        Establishes VXLAN tunnels between tunnel end points
        """
        tunnel_sync = True

        while tunnel_sync:
            try:
                start = time.time()
                # Notify the plugin of tunnel IP
                if self.enable_tunneling and tunnel_sync:
                    LOG.info(_("OVSvApp agent tunnel out of sync with plugin"))
                    tunnel_sync = self.tunnel_sync()
            except Exception:
                LOG.exception(_("Error in tunnel_sync"))
                tunnel_sync = True

            # sleep till end of polling interval
            elapsed = (time.time() - start)
            if (elapsed < self.polling_interval):
                time.sleep(self.polling_interval - elapsed)
            else:
                LOG.debug(_("Loop iteration exceeded interval "
                            "(%(polling_interval)s vs. %(elapsed)s)!"),
                          {'polling_interval': self.polling_interval,
                           'elapsed': elapsed})

    def ovsvapp_vxlan_loop(self):
        """
        A daemon loop which invokes tunnel_sync_rpc_loop
        to sync up the tunnels
        """
        self.tunnel_sync_rpc_loop()

    def _update_port_bindings(self):
        if self.update_port_bindings:
            for element in self.update_port_bindings:
                try:
                    # Update port binding with the host set as OVSvApp
                    # VM's hostname
                    LOG.debug("Update port binding for port %s" % element)
                    self.ovsvapp_rpc.update_port_binding(
                        self.context,
                        agent_id=self.agent_id,
                        port_id=element,
                        host=self.hostname)
                    self.update_port_bindings.remove(element)
                except Exception as e:
                    LOG.exception(_("update port binding failed "
                                    "for port: %s") % element)
                    raise error.NeutronAgentError(e)
                LOG.debug("update port binding RPC finished")

    def firewall_refresh_loop(self):
        """A deamon loop which will monitor devices added
           and update the OVS firewall
        """
        LOG.info(_("firewall_refresh_loop started"))
        while self.run_refresh_firewall_loop:
            if self.refresh_firewall_required:
                ovsvapplock.acquire()
                try:
                    devices_to_filter = self.devices_to_filter
                    self.devices_to_filter = set()
                    self.refresh_firewall_required = False
                finally:
                    ovsvapplock.release()
                device_list = set()
                try:
                    for device in devices_to_filter:
                        if device in ports_dict:
                            device_list.add(device)
                    LOG.info(_("will process port list: %s") % device_list)
                    devices_to_filter = devices_to_filter - device_list
                    ports = []
                    if devices_to_filter:
                        ports = self.plugin_rpc.get_devices_details_list(
                            self.context, devices_to_filter, self.agent_id)
                    for port in ports:
                        if port:
                            ovsvapplock.acquire()
                            try:
                                if 'port_id' in port.keys():
                                    port['id'] = port['port_id']
                                    ports_dict[port['id']] = portInfo(
                                        port['segmentation_id'],
                                        None, None, None,
                                        port['admin_state_up'],
                                        port['network_id'],
                                        port['device'])
                                    self.sg_agent.add_devices_to_filter([port])
                                    device_list.add(port['id'])
                                    if port['network_id'] not in \
                                        network_port_count.keys():
                                        network_port_count[
                                            port['network_id']] = 1
                                    else:
                                        network_port_count[
                                            port['network_id']] += 1
                            finally:
                                ovsvapplock.release()
                    if device_list:
                        self.sg_agent.refresh_firewall(device_list)
                        LOG.info(_("Processed Ports list: %s") % device_list)
                except Exception:
                    LOG.exception(_('Exception occurred'))
            try:
                if self.sg_agent.firewall_refresh_needed():
                    self.sg_agent.refresh_port_filters(
                        self.cluster_host_ports, self.cluster_other_ports)
            except Exception:
                    LOG.exception(_("Could not invoke "
                                    "firewall_refresh_needed"))
            self._update_port_bindings()
            time.sleep(2)

    def setup_security_br(self):
        '''Setup the security bridge.
        Create patch ports and remove all existing flows.
        :param bridge_name: the name of the security bridge.
        :returns: the security bridge
        '''
        if not CONF.SECURITYGROUP.security_bridge:
            LOG.debug("Security_bridge not configured")
            return
        secbr_list = (CONF.SECURITYGROUP.security_bridge).split(':')
        secbr_name = secbr_list[0]
        secbr_phyname = secbr_list[1]
        self.sec_br = ovs_lib.OVSBridge(secbr_name, self.root_helper)
        if not self.sec_br.bridge_exists(secbr_name):
            LOG.error(_("Security_bridge not available. Check your "
                        "security-bridge configuration, "
                        "Agent terminated!"))
            sys.exit(1)
        self.sec_br.remove_all_flows()
        self.int_br.delete_port(INT_TO_SEC_PATCH)
        self.sec_br.delete_port(SEC_TO_INT_PATCH)
        self.phy_ofport = self.sec_br.get_port_ofport(secbr_phyname)
        if not self.phy_ofport:
            LOG.error(_("phy port not available on %s. Check your "
                        "security-bridge configuration, "
                        "Agent terminated!"), secbr_name)
            sys.exit(1)
        # br-sec patch port to br-int
        self.patch_int_ofport = self.sec_br.add_patch_port(
            SEC_TO_INT_PATCH, INT_TO_SEC_PATCH)
        # br-int patch port to br-sec
        self.patch_sec_ofport = self.int_br.add_patch_port(
            INT_TO_SEC_PATCH, SEC_TO_INT_PATCH)
        if int(self.patch_int_ofport) < 0 or int(self.patch_sec_ofport) < 0:
            LOG.error(_("Failed to create OVS patch port. Cannot have "
                        "Security enabled on this agent, since this version "
                        "of OVS does not support patch ports. "
                        "Agent terminated!"))
            sys.exit(1)

        self.sec_br.add_flow(priority=0, actions="drop")
        LOG.info(_("Security bridge successfully set"))

    def recover_security_br(self):
        '''Recover the security bridge.
        :param bridge_name: the name of the security bridge.
        '''
        if not CONF.SECURITYGROUP.security_bridge:
            LOG.debug("Security_bridge not configured")
            return
        secbr_list = (CONF.SECURITYGROUP.security_bridge).split(':')
        secbr_name = secbr_list[0]
        secbr_phyname = secbr_list[1]
        self.sec_br = ovs_lib.OVSBridge(secbr_name, self.root_helper)
        if not self.sec_br.bridge_exists(secbr_name):
            LOG.error(_("Security_bridge not available. Check your "
                        "security-bridge configuration, "
                        "Agent terminated!"))
            sys.exit(1)
        self.phy_ofport = self.sec_br.get_port_ofport(secbr_phyname)
        if not self.phy_ofport:
            LOG.error(_("phy port not available on %s. Check your "
                        "security-bridge configuration, "
                        "Agent terminated!"), secbr_name)
            sys.exit(1)
        # br-sec patch port to br-int
        self.patch_int_ofport = self.sec_br.get_port_ofport(
            SEC_TO_INT_PATCH)
        # br-int patch port to br-sec
        self.patch_sec_ofport = self.int_br.get_port_ofport(
            INT_TO_SEC_PATCH)
        if int(self.patch_int_ofport) < 0 or int(self.patch_sec_ofport) < 0:
            LOG.error(_("Failed to find OVS patch port. Cannot have "
                        "Security enabled on this agent. Agent terminated!"))
            sys.exit(1)
        LOG.info(_("Security bridge successfully recovered"))

    def _init_ovs_flows(self, bridge_mappings):
        """Delete the drop flow created by OVSvApp Agent code.
           Add the new flow to allow all the packets between integration
           bridge and physical bridge
        """
        self.int_br.delete_flows(in_port=self.patch_sec_ofport)
        for physical_network, bridge in bridge_mappings.iteritems():
            self.int_br.delete_flows(
                in_port=self.int_ofports[physical_network])

            #Egress FLOWs
            self.int_br.add_flow(priority=2,
                                 in_port=self.patch_sec_ofport,
                                 actions="output:%s"
                                 % self.int_ofports[physical_network])
            br = ovs_lib.OVSBridge(bridge, self.root_helper)
            eth_name = bridge.split('-').pop()
            eth_ofport = br.get_port_ofport(eth_name)
            br.delete_flows(in_port=self.phys_ofports[physical_network])

            if eth_ofport > 0:
                br.delete_flows(in_port=eth_ofport)
                #ingress_action = "output:%s" % eth_ofport
                br.add_flow(priority=2,
                        in_port=self.phys_ofports[physical_network],
                        actions="normal")

                #Ingress FLOWs
                br.add_flow(priority=2,
                    in_port=eth_ofport,
                    actions="normal")

            self.int_br.add_flow(priority=2,
                             in_port=self.int_ofports[physical_network],
                             actions="output:%s" % self.patch_sec_ofport)

    def _map_port_to_common_model(self, aur_port, local_vlan_id=None):
        """Map the port and network objects to vCenter objects."""
        port_id = aur_port['id']
        segmentation_id = aur_port.get('segmentation_id')
        if self.tenant_network_type == p_const.TYPE_VLAN:
            network_id = aur_port.get('network_id')
        else:
            lvm = self.local_vlan_map[aur_port.get('network_id')]
            # In VXLAN deployment, we have 2 DVS per cluster. 2 portgroups
            # cannot have the same name with network_uuid within a datacenter.
            # For uniqueness clusterid is added along with network_uuid.
            network_id = str(aur_port.get('network_id')) + "-" + lvm.cluster_id
        device_id = aur_port.get('device_id')
        fixed_ips = aur_port.get('fixed_ips')
        security_groups = aur_port.get('security_groups')
        mac_address = aur_port.get('mac_address')
        port_status = (model.PortStatus.UP
                       if aur_port.get('admin_state_up')
                       else model.PortStatus.DOWN)
        # Create Common Model Network Object
        if self.tenant_network_type == p_const.TYPE_VLAN:
            vlan = model.Vlan(vlanIds=[segmentation_id])
        else:
            vlan = model.Vlan(vlanIds=[local_vlan_id])
        network_config = model.NetworkConfig(vlan)
        network = model.Network(
            name=network_id,
            network_type=model.NetworkType.VLAN,
            config=network_config)
        # Create Common Model Port Object
        port = model.Port(
            uuid=port_id,
            name=None,
            mac_address=mac_address,
            vm_id=device_id,
            network_uuid=network_id,
            ipaddresses=fixed_ips,
            port_status=port_status)
        return network, port

    def process_event(self, event):
        """
        Override the callback method for NetworkDriverCallback
        """
        try:
            LOG.debug(_("Handling event %(event_type)s for %(src_obj)s"),
                      {'event_type': event.event_type,
                      'src_obj': event.src_obj})
            vm = event.src_obj
            host = event.host_name
            if event.event_type == model.EventType.VM_CREATED:
                if not self.cluster_id:
                    self.cluster_id = event.cluster_id
                    LOG.info(_("Setting the cluster id:%s"), self.cluster_id)
                self.notify_device_added(vm, host, event.cluster_id)
            elif event.event_type == model.EventType.VM_UPDATED:
                self._notify_device_updated(vm, host)
            elif event.event_type == model.EventType.VM_DELETED:
                self._notify_device_deleted(vm, host)
            else:
                LOG.debug(_("Ignoring event %s"), event)
        except Exception as e:
            LOG.error(_("This may result in failure of network"
                        " provisioning for %(name)s %(uuid)s"),
                      {'name': event.src_obj.__class__.__name__,
                      'uuid': event.src_obj.uuid})
            LOG.exception(_("Cause of failure %s") % str(e))

    def _create_port(self, port_info, host, local_vlan_id=None,
                     pg_name=None, vm_ref=None):
        """
        Create port group based on port information
        """
        LOG.debug(_("OVSvApp Agent - port create started"))
        if host == self.esx_hostname:
            network, port = self._map_port_to_common_model(port_info,
                                                           local_vlan_id)
            retry_count = 3
            while retry_count > 0:
                try:
                    self.net_mgr.get_driver().create_port(network, port, None)
                    break
                except Exception as e:
                    LOG.error(_("Failed to create network %s ") % network.name)
                    retry_count -= 1
                    if retry_count == 0:
                        LOG.exception(_("Failed to create network %s ")
                                      % network.name)
                        raise error.NeutronAgentError(e)
                    time.sleep(2)

        #Handles tenant VM_CREATED event when spawned on non-hosted OVSvApp VM
        #Waits for portgroup to be created and then captures the local vlan id
        #associated with the portgroup - applicable only for VXLAN networks
        if host != self.esx_hostname and local_vlan_id == 0 and \
            pg_name is not None and vm_ref is not None:
            LOG.debug(_("Waiting for portgroup to be created: %s") % pg_name)
            pg_exists = self.net_mgr.get_driver().wait_for_portgroup(
                vm_ref, pg_name)
            if pg_exists:
                local_vlan_id = self.net_mgr.get_driver().get_pg_vlanid(
                    self.cluster_dvs_info[1], pg_name)
                self.available_local_vlans.remove(local_vlan_id)
        LOG.debug(_("OVSvApp Agent - port create finished"))
        return local_vlan_id

    def _add_ports_to_host_ports(self, ports, hosting=True):
        for port_id in ports:
            if hosting:
                if port_id in self.cluster_other_ports:
                    self.cluster_other_ports.remove(port_id)
                self.cluster_host_ports.add(port_id)
            else:
                if port_id in self.cluster_host_ports:
                    self.cluster_host_ports.remove(port_id)
                self.cluster_other_ports.add(port_id)

    def _notify_device_updated(self, vm, host):
        """Handle VM updated event."""
        try:
            if host == self.esx_hostname:
                for vnic in vm.vnics:
                    self._add_ports_to_host_ports([vnic.port_uuid])
                    LOG.debug(_("Invoking update_port_binding for port %s")
                              % vnic.port_uuid)
                    self.ovsvapp_rpc.update_port_binding(self.context,
                                                       agent_id=self.agent_id,
                                                       port_id=vnic.port_uuid,
                                                       host=self.hostname)
            else:
                for vnic in vm.vnics:
                    self._add_ports_to_host_ports([vnic.port_uuid], False)

        except Exception as e:
            LOG.exception(_("Failed to update port bindings for device: %s")
                          % vm.uuid)
            raise error.NeutronAgentError(e)

    def notify_device_added(self, vm, host, cluster_id):
        self.cluster_devices.add(vm.uuid)
        if len(vm.vnics) > 0:
            # This is for existing VM
            ovsvapplock.acquire()
            self.refresh_firewall_required = True
            for vnic in vm.vnics:
                self.devices_to_filter.add(vnic.port_uuid)
                self._add_ports_to_host_ports([vnic.port_uuid],
                                              host == self.esx_hostname)
            ovsvapplock.release()
        else:
            if host == self.esx_hostname:
                device = {'id': vm.uuid,
                          'host': host,
                          'cluster_id': cluster_id}
                retry = True
                iteration = 1
                while retry:
                    try:
                        status = self.ovsvapp_rpc.get_ports_for_device(
                            self.context, device, self.agent_id)
                        if status:
                            retry = False
                        else:
                            time.sleep(5 + iteration)
                            iteration += 1
                            # Stop if we reached 10 iterations.
                            if iteration > 10:
                                retry = False
                    except Exception as e:
                        LOG.exception(_("Failed to get port details for "
                                        "device: %s") % device['id'])
                        raise error.NeutronAgentError(e)

    def process_create_vlan(self, context, ports_list, host):
        ovsvapplock.acquire()
        try:
            self.sg_agent.add_devices_to_filter(ports_list)

            for element in ports_list:
                ports_dict[element['id']] = \
                    portInfo(element['segmentation_id'],
                             element['mac_address'],
                             element['security_groups'],
                             element['fixed_ips'],
                             element['admin_state_up'],
                             element['network_id'],
                             element['device_id'])
                if element['network_id'] not in network_port_count.keys():
                    network_port_count[element['network_id']] = 1
                else:
                    network_port_count[element['network_id']] += 1
        finally:
            LOG.debug(_("Port Count per network details after VM creation: "
                    "%s") % network_port_count)
            ovsvapplock.release()

        if host == self.esx_hostname:
            for element in ports_list:
                # Create a portgroup at vCenter and set it in enabled state
                self._create_port(element, host)
                LOG.debug(_("Invoking update_device_up for port %s"),
                          element['id'])
                try:
                    # set admin_state to True
                    self.plugin_rpc.update_device_up(
                        self.context,
                        element['id'],
                        self.agent_id,
                        self.agent_state['host'])
                except Exception as e:
                    LOG.exception(_("update device up failed for port: %s")
                                  % element['id'])
                    raise error.NeutronAgentError(e)
                self.update_port_bindings.append(element['id'])

    def process_create_vxlan(self, context, ports_list, host,
                             cluster_id, device_id):
        try:
            ovsvapplock.acquire()
            LOG.debug(_("Port Count per network details before VM creation: "
                        "%s") % network_port_count)
            LOG.debug(_("ports_dict info before VM creation: "
                        "%s") % ports_dict)
            self.sg_agent.add_devices_to_filter(ports_list)
        finally:
            ovsvapplock.release()

        vcenter_call = 0
        try:
            vm_ref = None
            pg_name = None
            for element in ports_list:
                if element['network_id'] not in self.local_vlan_map:
                    # Populate Global VNI - Local VLAN mapping cache
                    pg_name = str(element['network_id']) + "-" + cluster_id
                    # Fetch Local VLAN ID associated with tenant VM Port
                    # Group from vCenter Server
                    self.cluster_dvs_info[1] = self.cluster_dvs_info[1].strip()
                    vcenter_call = 1
                    lvid = self.net_mgr.get_driver().get_pg_vlanid(
                            self.cluster_dvs_info[1], pg_name)
                    vcenter_call = 0
                    if lvid == 0:
                        if host == self.esx_hostname:
                            ovsvapplock.acquire()
                            lvid = self.available_local_vlans.pop()
                        else:
                            vcenter_call = 1
                            vm_ref = self.net_mgr.get_driver(). \
                                get_vm_ref_uuid(device_id)
                            vcenter_call = 0
                            LOG.debug(_("Created VM reference %(vm_uuid)s "
                                        "for %(vm_ref)s"),
                                      {'vm_uuid': device_id,
                                       'vm_ref': vm_ref})
                            ovsvapplock.acquire()
                        network_type = element['network_type']
                        segmentation_id = element['segmentation_id']
                        LOG.info(_("LocalVLANMapping cache: lvid - %(lvid)s, "
                                   "VNI - %(segmentation_id)s"),
                                 {'lvid': lvid,
                                  'segmentation_id': segmentation_id})
                        self.local_vlan_map[element['network_id']] = \
                            LocalVLANMapping(lvid, network_type,
                                             segmentation_id,
                                             cluster_id)
                    else:
                        ovsvapplock.acquire()
                        if lvid in self.available_local_vlans:
                            self.available_local_vlans.remove(lvid)
                        network_type = element['network_type']
                        segmentation_id = element['segmentation_id']
                        LOG.info(_("LocalVLANMapping cache: lvid - %(lvid)s, "
                                   "VNI - %(segmentation_id)s"),
                                 {'lvid': lvid,
                                  'segmentation_id': segmentation_id})
                        self.local_vlan_map[element['network_id']] = \
                            LocalVLANMapping(lvid, network_type,
                                             segmentation_id,
                                             cluster_id)
                else:
                    ovsvapplock.acquire()
                    lvm = self.local_vlan_map[element['network_id']]
                    lvid = lvm.vlan

                ports_dict[element['id']] = \
                    portInfo(lvid,
                             element['mac_address'],
                             element['security_groups'],
                             element['fixed_ips'],
                             element['admin_state_up'],
                             element['network_id'],
                             element['device_id'])
                if element['network_id'] not in network_port_count.keys():
                    network_port_count[element['network_id']] = 1
                else:
                    network_port_count[element['network_id']] += 1
                LOG.debug(_("Port Count per network details after VM "
                            "creation: %s") % network_port_count)
                LOG.debug(_("ports_dict info after VM creation: "
                            "%s") % ports_dict)
        finally:
            if vcenter_call == 0:
                ovsvapplock.release()

        for element in ports_list:
            if host == self.esx_hostname:
                self.update_port_bindings.append(element['id'])
            ovsvapplock.acquire()
            lvm = self.local_vlan_map[element['network_id']]
            ovsvapplock.release()
            LOG.debug(_("Calling Create_port with vlan = %(lvid)d, "
                        "pg_name=%(pg_name)s, vm_ref=%(vm_ref)s"),
                      {'lvid': lvm.vlan,
                       'pg_name': pg_name,
                       'vm_ref': vm_ref})
            #over-write the local vlan id for a tenant VM on a non-hosted
            #OVSvApp VM by waiting for a portgroup created and determining
            #the local vlan id associated with the portgroup
            lvm.vlan = self._create_port(element, host, lvm.vlan,
                                         pg_name, vm_ref)
            if element['network_type'] in constants.TUNNEL_NETWORK_TYPES:
                ofports = ','.join(self.tun_br_ofports[
                    element['network_type']].values())
                if ofports:
                    self.tun_br.mod_flow(table=constants.FLOOD_TO_TUN,
                                         dl_vlan=lvm.vlan,
                                         actions="strip_vlan,"
                                         "set_tunnel:%s,output:%s" %
                                         (element['segmentation_id'],
                                         ofports))
                    # inbound from tunnels: set lvid in the right table
                    # and resubmit to Table LEARN_FROM_TUN for
                    # mac learning
                    self.tun_br.add_flow(table=constants.TUN_TABLE[
                        element['network_type']],
                        priority=1,
                        tun_id=element['segmentation_id'],
                        actions="mod_vlan_vid:%s,resubmit(,%s)" %
                        (lvm.vlan, constants.LEARN_FROM_TUN))

            if host == self.esx_hostname:
                try:
                    # set admin_state to True
                    self.plugin_rpc.update_device_up(
                        self.context,
                        element['id'],
                        self.agent_id,
                        self.agent_state['host'])
                except Exception as e:
                    LOG.exception(_("update device up failed for port: %s")
                                  % element['id'])
                    raise error.NeutronAgentError(e)

    def device_create(self, context, **kwargs):
        """
        Gets the port details from plugin using RPC call and updates device
        status to plugin
        """
        device = kwargs.get('device')
        device_id = device['id']
        cluster_id = device['cluster_id']
        LOG.debug(_("device_create notification for VM %s") % device_id)
        if cluster_id != self.cluster_id:
            LOG.debug('Cluster mismatch ..ignoring device_create rpc')
            return
        ports_list = kwargs.get('ports')
        sg_rules = kwargs.get("sg_rules")
        host = device['host']
        # Make RPC call to plugin to get port details
        LOG.debug(_("Received Port list: %s") % ports_list)
        port_ids = [port['id'] for port in ports_list]
        if host == self.esx_hostname:
            self._add_ports_to_host_ports(port_ids)
        else:
            self._add_ports_to_host_ports(port_ids, False)
            ovsvapplock.acquire()
            try:
                self.devices_to_filter = self.devices_to_filter | set(
                    port_ids)
            finally:
                ovsvapplock.release()
            self.refresh_firewall_required = True
        if self.tenant_network_type == p_const.TYPE_VLAN:
            self.process_create_vlan(context, ports_list, host)
        else:
            self.process_create_vxlan(context, ports_list, host,
                                      cluster_id, device_id)
        port_ids = [port['id'] for port in ports_list]
        if host == self.esx_hostname:
            if sg_rules:
                self.sg_agent.ovsvapp_sg_update(sg_rules[device_id])

    def _report_state(self):
        """
        Reporting agent state to neutron server
        """
        try:
            if self.agent_state.get("start_flag"):
                LOG.info(_("Subagent reporting state %s"), self.agent_state)
            self.agent_state['configurations']['cluster_id'] = self.cluster_id
            self.state_rpc.report_state(self.context, self.agent_state)
            self.agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception(_("Heartbeat failure - Failed reporting state!"))

    def setup_report_states(self):
        """
        Method to initiate the looping call which sents heartbeats to
        the neutron server
        """
        report_interval = CONF.OVSVAPPAGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)
        else:
            LOG.info(_("report interval is not defined.Cannot send "
                       "heartbeats"))

    def setup_rpc(self):
        # Ensure that the control exchange is set correctly
        self.agent_id = "ovsvapp-agent %s" % self.hostname
        self.topic = topics.AGENT
        self.context = context.get_admin_context_without_session()
        self.endpoints = [self]
        self.plugin_rpc = RpcPluginApi()
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        self.ovsvapp_rpc = OVSvAppPluginApi(OVSVAPP)

        # Define the listening consumers for the agent
        consumers = [
            [topics.PORT, topics.UPDATE],
            [DEVICE, topics.CREATE],
            [DEVICE, topics.UPDATE],
            [constants.TUNNEL, topics.UPDATE],
            [topics.SECURITY_GROUP, topics.UPDATE]
        ]
        self.connection = agent_rpc.create_consumers(self.endpoints,
                                                     self.topic,
                                                     consumers)
        LOG.debug(_("finished setup_rpc"))

    def start(self):
        LOG.info(_("Starting OVSvApp L2 Agent"))
        LOG.info(_("Starting configuration updates monitor"))
        t = eventlet.spawn(self._monitor_conf_updates)
        LOG.info(_("Waiting for node to be ACTIVE"))
        self.set_node_state(True)
        try:
            cluster_mor = resource_util.get_cluster_mor_by_path(
                    self.net_mgr.get_driver().session, self.cluster_path)
            self.cluster_id = resource_util.get_clusterid_for_cluster_mor(
                    self.net_mgr.get_driver().session, cluster_mor)
        except Exception:
            LOG.exception(_("Unable to get cluster_id"))
        eventlet.spawn(self.firewall_refresh_loop)
        #Wait OVSvApp thread forever till stop() is triggered
        if self.tenant_network_type == p_const.TYPE_VXLAN:
            t1 = eventlet.spawn(self.ovsvapp_vxlan_loop)
        t.wait()
        if self.tenant_network_type == p_const.TYPE_VXLAN:
            t1.wait()

    def stop(self):
        LOG.info(_("Stopping OVSvApp L2 Agent"))
        self.run_refresh_firewall_loop = False
        agent.Agent.stop(self)
        if self.connection:
            self.connection.close()

    @utils.require_state([agent.State.RUNNING])
    def device_update(self, context, **kwargs):
        device_data = kwargs.get('device_data')
        LOG.info(_("Received device_update RPC with %(data)s"),
                 {'data': device_data})
        if device_data:
            ovsvapp_vm = device_data.get('ovsvapp_agent')
            src_esx_host = device_data.get('esx_host_name')
            assigned_host = device_data.get('assigned_agent_host')
            if assigned_host == self.hostname:
                retry_count = 3
                while retry_count > 0:
                    try:
                        vm_mor = resource_util.get_vm_mor_by_name(
                            self.net_mgr.get_driver().session, ovsvapp_vm)
                        host_mor = resource_util.get_host_mor_by_name(
                            self.net_mgr.get_driver().session, src_esx_host)
                        if self.esx_maintenance_mode:
                            try:
                                LOG.info(_("Setting ovsvapp %s to poweroff "),
                                         ovsvapp_vm)
                                resource_util.set_vm_poweroff(
                                    self.net_mgr.get_driver().session, vm_mor)
                            except Exception:
                                LOG.exception(_("Unable to poweroff VM"))
                            LOG.info(_("Setting host %s to maintenance "
                                       "mode"), src_esx_host)
                            resource_util.set_host_into_maintenance_mode(
                                self.net_mgr.get_driver().session, host_mor)
                        else:
                            LOG.info(_("Setting host %s to shutdown mode"),
                                     src_esx_host)
                            resource_util.set_host_into_shutdown_mode(
                                self.net_mgr.get_driver().session, host_mor)
                        break
                    except Exception:
                        retry_count -= 1
                    if retry_count == 0:
                        LOG.exception(_("Exception occurred while setting "
                                        "host to maintenance mode or "
                                        "shutdown mode"))
                    time.sleep(2)
            else:
                LOG.debug("Ignoring the device_update RPC as it is for"
                          " a different host")

    def delete_network_object(self, del_port):
        network = model.Network(
            name=del_port.network_id,
            network_type=model.NetworkType.VLAN)
        retry_count = 3
        while retry_count > 0:
            try:
                LOG.debug("Deleting portgroup from vCenter :"
                          " %s" % del_port.network_id)
                self.net_mgr.get_driver().delete_network(network)
                break
            except Exception as e:
                LOG.exception(_("Failed to delete network %s")
                              % del_port.network_id)
                retry_count -= 1
                if retry_count == 0:
                    raise error.NeutronAgentError(e)
                time.sleep(2)

    def process_delete_vlan_novnic(self, host, vm):
        ovsvapplock.acquire()
        try:
            for port in ports_dict.keys():
                port_count = -1
                if ports_dict[port].vm_uuid == vm.uuid:
                    network_port_count[ports_dict[port].network_id] -= 1
                    port_count = \
                        network_port_count[ports_dict[port].network_id]
                    LOG.debug("Port Count per network details after VM "
                              "deletion: %s" % network_port_count)
                    #Clean up ports_dict for the deleted port
                    del_port = ports_dict[port]
                    if port in self.cluster_host_ports:
                        self.cluster_host_ports.remove(port)
                    elif port in self.cluster_other_ports:
                        self.cluster_other_ports.remove(port)
                    self.sg_agent.remove_devices_filter(port)
                    ports_dict.pop(port)
                    #Remove port count tracking per network when
                    #last VM associated with the network is deleted
                    if port_count == 0:
                        network_port_count.pop(del_port.network_id)
                        if host == self.esx_hostname:
                            self.delete_network_object(del_port)
                    break
            self.net_mgr.get_driver().post_delete_vm(vm)
        finally:
            ovsvapplock.release()

    def process_delete_vlan(self, host, vm, vnic, del_port):
        ovsvapplock.acquire()
        port_count = -1
        try:
            if del_port.network_id in network_port_count.keys():
                network_port_count[del_port.network_id] -= 1
                port_count = network_port_count[del_port.network_id]
                #Remove port count tracking per network when
                #last VM associated with the network is deleted
                if port_count == 0:
                    network_port_count.pop(del_port.network_id)
                LOG.debug("Port Count per network details after VM "
                          "deletion: %s" % network_port_count)
                #Clean up ports_dict for the deleted port
                ports_dict.pop(vnic.port_uuid)
            else:
                LOG.debug("Network %s does not exist in "
                          "network_port_count" % del_port.network_id)
        finally:
            ovsvapplock.release()
            self.net_mgr.get_driver().post_delete_vm(vm)
            if port_count == 0:
                if host == self.esx_hostname:
                    self.delete_network_object(del_port)

    def process_delete_vxlan(self, host, vm, vnic, del_port):
        ovsvapplock.acquire()
        port_count = -1
        try:
            LOG.debug(_("Port Count per network details before VM deletion: "
                        "%s") % network_port_count)
            if del_port.network_id in network_port_count.keys():
                network_port_count[del_port.network_id] -= 1
                port_count = network_port_count[del_port.network_id]
                #Remove port count tracking per network when
                #last VM associated with the network is deleted
                if port_count == 0:
                    network_port_count.pop(del_port.network_id)
                LOG.debug(_("Port Count per network details after VM "
                            "deletion: %s") % network_port_count)
                #Clean up ports_dict for the deleted port
                ports_dict.pop(vnic.port_uuid)
                LOG.debug(_("ports_dict info after VM deletion: "
                            "%s") % ports_dict)
        finally:
            ovsvapplock.release()
        self.net_mgr.get_driver().post_delete_vm(vm)
        if port_count == 0:
            if host == self.esx_hostname:
                lvm = \
                    self.local_vlan_map[del_port.network_id]
                network_id = str(del_port.network_id) + \
                    "-" + lvm.cluster_id
                network = model.Network(
                    name=del_port.network_id,
                    network_type=model.NetworkType.VXLAN)
                try:
                    LOG.debug(_("Deleting portgroup from vCenter :"
                                " %s") % del_port.network_id)
                    self.net_mgr.get_driver().delete_network(network)
                except Exception as e:
                    LOG.exception(_("Failed to delete network %s")
                                  % network_id)
        try:
            # Delete FLOWs which match entries:
            # network_id - local_vlan_id - segmentation_id
            LOG.debug(_("Reclaiming local vlan associated "
                        " with the network: %s")
                      % del_port.network_id)
            self.reclaim_local_vlan(del_port.network_id)
        except Exception as e:
            LOG.exception(_("Failed to reclaim local vlan "
                            " %d ") % lvm.vlan)
            raise error.NeutronAgentError(e)
        finally:
            ovsvapplock.release()

    @utils.require_state([agent.State.RUNNING])
    def _notify_device_deleted(self, vm, host):
        #When a last VM associated with a given network is deleted
        #then portgroup associated with the network is deleted and hence
        #network_delete RPC call is not consumed by the OVSvApp agent
        self.cluster_devices.remove(vm.uuid)
        LOG.warn(_(" Deleting VM %s") % vm.uuid)

        if not vm.vnics:
            LOG.debug("Deletion of VM with no vnics %s" % vm.uuid)
            self.process_delete_vlan_novnic(host, vm)
            return

        for vnic in vm.vnics:
            LOG.info(_("Deleting port %(port)s with macaddress %(mac)s"),
                     {'port': vnic.port_uuid, 'mac': vnic.mac_address})

            if not vnic.port_uuid:
                LOG.info(_("Port id for vnic with macaddress %s not present"),
                         vnic.mac_address)
            else:
                del_port = None
                if vnic.port_uuid in self.cluster_host_ports:
                    self.cluster_host_ports.remove(vnic.port_uuid)
                elif vnic.port_uuid in self.cluster_other_ports:
                    self.cluster_other_ports.remove(vnic.port_uuid)
                ovsvapplock.acquire()
                try:
                    if vnic.port_uuid in ports_dict.keys():
                        self.sg_agent.remove_devices_filter(vnic.port_uuid)
                        LOG.info(_("Delete port %(port)s with mac %(mac)s "
                                   "finished"), {'port': vnic.port_uuid,
                                                 'mac': vnic.mac_address})
                        del_port = ports_dict[vnic.port_uuid]
                    else:
                        LOG.debug("Port id %s is not available in "
                                  "ports_dict" % vnic.port_uuid)
                finally:
                    ovsvapplock.release()
                    if del_port is not None:
                        if self.tenant_network_type == p_const.TYPE_VLAN:
                            self.process_delete_vlan(host, vm, vnic, del_port)
                        else:
                            self.process_delete_vxlan(del_port, host, vnic)

    def _port_update_status_change(self, network_model, port_model):
        retry_count = 3
        while retry_count > 0:
            try:
                self.net_mgr.get_driver().update_port(network_model,
                                                      port_model,
                                                      None)
                break
            except Exception as e:
                LOG.exception(_("Failed to update port %s")
                              % port_model.uuid)
                retry_count -= 1
                if retry_count == 0:
                    raise error.NeutronAgentError(e)
                time.sleep(2)

    @utils.require_state([agent.State.RUNNING])
    def port_update(self, context, **kwargs):
        LOG.info(_("OVSvApp Agent - port update received"))
        LOG.debug(_("port_update arguments : %s"), kwargs)
        new_port = kwargs.get('port')
        local_vlan_id = kwargs.get('segmentation_id')
        if self.tenant_network_type == p_const.TYPE_VXLAN:
            ovsvapplock.acquire()
            lvm = self.local_vlan_map[new_port['network_id']]
            ovsvapplock.release()
            if lvm:
                local_vlan_id = lvm.vlan
            else:
                LOG.debug(_("Local VLAN mapping object missing for %s")
                          % new_port['network_id'])
                return
        ovsvapplock.acquire()
        old_port_object = None
        new_port_object = None
        try:
            if new_port['id'] in ports_dict.keys():
                old_port_object = ports_dict[new_port['id']]
                ports_dict[new_port['id']] = \
                    portInfo(local_vlan_id,
                             new_port['mac_address'],
                             new_port['security_groups'],
                             new_port['fixed_ips'],
                             new_port['admin_state_up'],
                             new_port['network_id'],
                             new_port['device_id'])
                new_port_object = ports_dict[new_port['id']]
        finally:
            ovsvapplock.release()

        if old_port_object and new_port_object:
            if cmp(old_port_object.admin_state_up,
                   new_port_object.admin_state_up) != 0:
                LOG.debug(_("Updating admin_state_up status for %s")
                          % new_port['id'])
                network, port = self._map_port_to_common_model(new_port,
                                                               local_vlan_id)
                self._port_update_status_change(network, port)

            self.sg_agent.devices_to_refilter.add(new_port['id'])
            try:
                if(new_port['admin_state_up']):
                    LOG.debug(_("Invoking update_device_up for %s")
                              % new_port['id'])
                    self.plugin_rpc.update_device_up(self.context,
                                                     new_port['id'],
                                                     self.agent_id,
                                                     self.hostname)
                else:
                    LOG.debug(_("Invoking update_device_down for %s")
                              % new_port['id'])
                    self.plugin_rpc.update_device_down(self.context,
                                                       new_port['id'],
                                                       self.agent_id,
                                                       self.hostname)
            except Exception as e:
                LOG.exception(_("update device up/down failed for port: %s")
                              % new_port['id'])
                raise error.NeutronAgentError(e)
        else:
            LOG.debug(_("old and new port objects not available for port %s")
                      % new_port['id'])
        LOG.info(_("OVSvApp Agent - port update finished"))


class RpcPluginApi(agent_rpc.PluginApi,
                   sg_rpc.SecurityGroupServerRpcApiMixin):

    def __init__(self):
        super(RpcPluginApi, self).__init__(topic=topics.PLUGIN)


class OVSvAppPluginApi(n_rpc.RpcProxy):

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic):
        super(OVSvAppPluginApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)

    def get_ports_for_device(self, context, device, agent_id):
        LOG.info(_(" RPC get_ports_for_device is called for device_id: %s"),
                 device['id'])
        return self.call(context,
                         self.make_msg('get_ports_for_device',
                                       device=device,
                                       agent_id=agent_id))

    def update_port_binding(self, context, agent_id, port_id, host):
        return self.call(context,
                         self.make_msg('update_port_binding',
                                       agent_id=agent_id,
                                       port_id=port_id,
                                       host=host))
