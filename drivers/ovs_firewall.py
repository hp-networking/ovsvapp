# Copyright 2014, Hewlett-Packard Development Company, L.P.
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

import itertools
import netaddr
from neutron.agent import firewall
from neutron.agent.linux import ovs_lib
from neutron.common import constants
from neutron.openstack.common import log as logging
from neutron.plugins.ovsvapp.agent import ovsvapp_agent
from oslo.config import cfg
import threading


SG_DROPALL_PRI = 0
SG_DEFAULT_PRI = 1
SG_LOW_PRI = 5
SG_RULES_PRI = 10
SG_TP_PRI = 20
SG_TCP_FLAG_PRI = 25
SG_DROP_HIGH_PRI = 50

SG_DEFAULT_TABLE_ID = 0
SG_IP_TABLE_ID = 2
SG_TCP_TABLE_ID = 2
SG_UDP_TABLE_ID = 2
SG_ICMP_TABLE_ID = 2
SG_LEARN_TABLE_ID = 5

ICMP_ECHO_REQ = 8
ICMP_ECHO_REP = 0
ICMP_TIME_EXCEEDED = 11
ICMP_TS_REQ = 13
ICMP_TS_REP = 14
ICMP_INFO_REQ = 15
ICMP_INFO_REP = 16
ICMP_AM_REQ = 17
ICMP_AM_REP = 18
ICMP_DEST_UNREACH = 3

LOG = logging.getLogger(__name__)
INGRESS_DIRECTION = 'ingress'
EGRESS_DIRECTION = 'egress'
PROTOCOLS = {constants.PROTO_NAME_TCP: constants.PROTO_NAME_TCP,
             constants.PROTO_NUM_TCP: constants.PROTO_NAME_TCP,
             constants.PROTO_NAME_UDP: constants.PROTO_NAME_UDP,
             constants.PROTO_NUM_UDP: constants.PROTO_NAME_UDP,
             constants.PROTO_NAME_ICMP: constants.PROTO_NAME_ICMP,
             constants.PROTO_NUM_ICMP: constants.PROTO_NAME_ICMP,
             constants.PROTO_NAME_ICMP_V6: constants.PROTO_NAME_ICMP_V6,
             constants.PROTO_NUM_ICMP_V6: constants.PROTO_NAME_ICMP_V6}

ETHERTYPE = {constants.IPv4: "ip",
             constants.IPv6: "ip6"}

sg_conf = cfg.CONF.SECURITYGROUP

PORT_KEYS = ['security_group_source_groups',
             'mac_address',
             'network_id',
             'id',
             'security_groups',
             'segmentation_id']


class OVSFirewallDriver(firewall.FirewallDriver):
    """Driver which enforces security groups through OVS flows."""

    def __init__(self):
        # list of port which has security group
        self.filtered_ports = {}
        self.root_helper = cfg.CONF.AGENT.root_helper

        if sg_conf.security_bridge is None:
            LOG.debug(_("Security_bridge not configured"))
            return
        secbr_list = (sg_conf.security_bridge).split(':')
        secbr_name = secbr_list[0]
        secbr_phyname = secbr_list[1]

        self.sg_br = OVSFBridge(secbr_name, self.root_helper,
                               ('del', 'mod', 'add'))
        self.phy_ofport = self.sg_br.get_port_ofport(secbr_phyname)
        self.patch_ofport = self.sg_br.get_port_ofport(
            ovsvapp_agent.SEC_TO_INT_PATCH)
        self.portCache = ovsvapp_agent.portCache()
        self._defer_apply = False
        if not cfg.CONF.OVSVAPPAGENT.agent_maintenance:
            self.setup_base_flows()
        self.locks = {}

    def get_lock(self, port_id):
        if port_id not in self.locks:
            LOG.debug(_("Creating lock for port %s") % port_id)
            self.locks[port_id] = threading.RLock()
        self.locks[port_id].acquire()

    def release_lock(self, port_id):
        if port_id in self.locks:
            self.locks[port_id].release()

    def remove_lock(self, port_id):
        if port_id in self.locks:
            self.locks.pop(port_id, None)

    @property
    def ports(self):
        return self.filtered_ports

    def setup_base_flows(self):
        self.sg_br.add_flow(priority=SG_DEFAULT_PRI,
                            table=SG_DEFAULT_TABLE_ID,
                            actions="resubmit(,%s)" % SG_LEARN_TABLE_ID)
        self.sg_br.add_flow(priority=SG_DROPALL_PRI,
                            table=SG_LEARN_TABLE_ID,
                            actions="drop")
        # Allow all ARP, parity with iptables
        self.sg_br.add_flow(priority=SG_RULES_PRI,
                            table=SG_DEFAULT_TABLE_ID,
                            proto="arp",
                            actions="normal")
        # Allow all RARP, parity with iptables
        self.sg_br.add_flow(priority=SG_RULES_PRI,
                            table=SG_DEFAULT_TABLE_ID,
                            proto="rarp",
                            actions="normal")

        # Allow VMs to send DHCP requests (udp)
        self.sg_br.add_flow(priority=SG_RULES_PRI,
                            table=SG_DEFAULT_TABLE_ID,
                            proto="udp",
                            tp_src="68",
                            tp_dst="67",
                            actions="normal")

        # Always allow ICMP DestUnreach
        self.sg_br.add_flow(priority=SG_TP_PRI,
                            table=SG_DEFAULT_TABLE_ID,
                            proto=constants.PROTO_NAME_ICMP,
                            icmp_type=ICMP_DEST_UNREACH,
                            actions="normal")

        # Always allow ICMP TTL Exceeded
        self.sg_br.add_flow(priority=SG_TP_PRI,
                            table=SG_DEFAULT_TABLE_ID,
                            proto=constants.PROTO_NAME_ICMP,
                            icmp_type=ICMP_TIME_EXCEEDED,
                            actions="normal")

        # Always resubmit FIN pkts to learn table
        self.sg_br.add_flow(priority=SG_TCP_FLAG_PRI,
                            table=SG_DEFAULT_TABLE_ID,
                            proto=constants.PROTO_NAME_TCP,
                            tcp_flags='+fin',
                            actions="resubmit(,%s),normal" %
                            SG_LEARN_TABLE_ID)

        # Always resubmit RST pkts to learn table
        self.sg_br.add_flow(priority=SG_TCP_FLAG_PRI,
                            table=SG_DEFAULT_TABLE_ID,
                            proto=constants.PROTO_NAME_TCP,
                            tcp_flags='+rst',
                            actions="resubmit(,%s),normal" %
                            (SG_LEARN_TABLE_ID))

        # Following three Tables are to catch all TCP/UDP/ICMP flows
        # Pkts are already forwarded, these table just add
        # a learning flows.

        # First we chain the tables
        self.sg_br.add_flow(priority=SG_DEFAULT_PRI,
                            table=SG_ICMP_TABLE_ID,
                            actions="drop")
        # If DMAC is bcast or mcast, don't learn
        self.sg_br.add_flow(priority=SG_DROP_HIGH_PRI,
                            table=SG_IP_TABLE_ID,
                            dl_dst="01:00:00:00:00:00/01:00:00:00:00:00",
                            actions="drop")

        # Now we add learning flows
        learned_tcp_flow = ("table=%s,"
                            "priority=%s,"
                            "fin_idle_timeout=1,"
                            "idle_timeout=7200,"
                            "NXM_OF_ETH_SRC[]=NXM_OF_ETH_DST[],"
                            "NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],"
                            "dl_type=0x0800,"
                            "NXM_OF_VLAN_TCI[0..11],"
                            "nw_proto=%s,"
                            "NXM_OF_IP_SRC[]=NXM_OF_IP_DST[],"
                            "NXM_OF_IP_DST[]=NXM_OF_IP_SRC[],"
                            "NXM_OF_TCP_SRC[]=NXM_OF_TCP_DST[],"
                            "NXM_OF_TCP_DST[]=NXM_OF_TCP_SRC[],"
                            "output:NXM_OF_IN_PORT[]" %
                            (SG_LEARN_TABLE_ID,
                            SG_TP_PRI,
                            constants.PROTO_NUM_TCP))
        self.sg_br.add_flow(priority=SG_TP_PRI,
                            table=SG_TCP_TABLE_ID,
                            proto=constants.PROTO_NAME_TCP,
                            actions="learn(%s)" % learned_tcp_flow)

        learned_udp_flow = ("table=%s,"
                            "priority=%s,"
                            "idle_timeout=300,"
                            "NXM_OF_ETH_SRC[]=NXM_OF_ETH_DST[],"
                            "NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],"
                            "dl_type=0x0800,"
                            "NXM_OF_VLAN_TCI[0..11],"
                            "nw_proto=%s,"
                            "NXM_OF_IP_SRC[]=NXM_OF_IP_DST[],"
                            "NXM_OF_IP_DST[]=NXM_OF_IP_SRC[],"
                            "NXM_OF_UDP_SRC[]=NXM_OF_UDP_DST[],"
                            "NXM_OF_UDP_DST[]=NXM_OF_UDP_SRC[],"
                            "output:NXM_OF_IN_PORT[]" %
                            (SG_LEARN_TABLE_ID,
                            SG_TP_PRI,
                            constants.PROTO_NUM_UDP))
        self.sg_br.add_flow(priority=SG_TP_PRI,
                            table=SG_UDP_TABLE_ID,
                            proto=constants.PROTO_NAME_UDP,
                            actions="learn(%s)" % learned_udp_flow)

# We'll only allow specific ICMP packets to be learnt.
# All others will be blocked. This is restrictive, but more secure.
#        learned_icmp_flow = ("table=%s,"
#                             "priority=%s,"
#                             "idle_timeout=300,"
#                             "NXM_OF_ETH_SRC[]=NXM_OF_ETH_DST[],"
#                             "NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],"
#                             "dl_type=0x0800,"
#                             "NXM_OF_VLAN_TCI[0..11],"
#                             "nw_proto=%s,"
#                             "NXM_OF_IP_SRC[]=NXM_OF_IP_DST[],"
#                             "NXM_OF_IP_DST[]=NXM_OF_IP_SRC[],"
#                             "output:NXM_OF_IN_PORT[]" %
#                             (SG_LEARN_TABLE_ID,
#                             SG_RULES_PRI,
#                             constants.PROTO_NUM_ICMP))
#        self.sg_br.add_flow(priority=SG_RULES_PRI,
#                            table=SG_ICMP_TABLE_ID,
#                            proto=constants.PROTO_NAME_ICMP,
#                            actions="learn(%s)" % learned_icmp_flow)
        self.sg_br.add_flow(priority=SG_TP_PRI,
                            table=SG_ICMP_TABLE_ID,
                            proto=constants.PROTO_NAME_ICMP,
                            icmp_type=ICMP_ECHO_REQ,
                            actions="learn(%s)" %
                            (self.get_icmp_learn_flow(ICMP_ECHO_REP)))

        self.add_icmp_learn_flow(ICMP_TS_REQ, ICMP_TS_REP)
        self.add_icmp_learn_flow(ICMP_INFO_REQ, ICMP_INFO_REP)
        self.add_icmp_learn_flow(ICMP_AM_REQ, ICMP_AM_REP)

    def add_icmp_learn_flow(self, reqType, resType, pri=SG_TP_PRI):
        self.sg_br.add_flow(priority=pri,
                            table=SG_ICMP_TABLE_ID,
                            proto=constants.PROTO_NAME_ICMP,
                            icmp_type=reqType,
                            actions="learn(%s)" %
                            self.get_icmp_learn_flow(resType))

    def get_icmp_learn_flow(self, resType):
        if resType is ICMP_DEST_UNREACH:
            ip_str = ""
        else:
            ip_str = "NXM_OF_IP_SRC[]=NXM_OF_IP_DST[],"
        return ("table=%s,"
                "priority=%s,"
                "idle_timeout=30,"
                "dl_type=0x0800,"
                "NXM_OF_VLAN_TCI[0..11],"
                "nw_proto=%s,"
                "icmp_type=%s,"
                "%s"
                "NXM_OF_IP_DST[]=NXM_OF_IP_SRC[],"
                "output:NXM_OF_IN_PORT[]" %
                (SG_LEARN_TABLE_ID,
                 SG_TP_PRI,
                 constants.PROTO_NUM_ICMP,
                 resType, ip_str))

    def _get_mini_port(self, port):
        new_port = {}
        new_port['device'] = port['id']
        for key in PORT_KEYS:
            if key in port:
                new_port[key] = port[key]
        return new_port

    def prepare_port_filter(self, port):
        LOG.debug("OVSF Preparing port %s filter", port['id'])
        self.get_lock(port['id'])
        try:
            with self.sg_br.deferred(full_ordered=True, order=(
                'del', 'mod', 'add')) as deferred_br:
                self._setup_flows(deferred_br, port)
                self._add_flows(deferred_br, port)
            self.filtered_ports[port['id']] = self._get_mini_port(port)

        except Exception:
            LOG.exception(_("Unabled to add flows for %s") % port['id'])
        finally:
            self.release_lock(port['id'])

    def add_ports_to_filter(self, ports):
        for port in ports:
            LOG.debug("OVSF Adding port %s to filter", port['id'])
            self.filtered_ports[port['id']] = self._get_mini_port(port)

    def update_port_filter(self, port):
        LOG.debug(_("OVSF Updating port %s filter") % port['id'])
        if port['id'] not in self.filtered_ports:
            LOG.debug(_("Attempted to update port filter which is not "
                        "filtered %s") % port['id'])
            return

        self.get_lock(port['id'])
        try:
            with self.sg_br.deferred(full_ordered=True, order=(
                'del', 'mod', 'add')) as deferred_br:
                self._remove_flows(deferred_br, port)
                self._setup_flows(deferred_br, port)
                self._add_flows(deferred_br, port)
            self.filtered_ports[port['id']] = self._get_mini_port(port)
        except Exception:
            LOG.exception(_("Unable to update flows for %s") % port['id'])
        finally:
            self.release_lock(port['id'])

    def clean_port_filters(self, ports, remove_port=False):
        LOG.debug("OVSF Cleaning filters for  %s ports", len(ports))
        if not ports:
            return
        with self.sg_br.deferred() as deferred_sec_br:
            for port_id in ports:
                self.get_lock(port_id)
                try:
                    if not self.filtered_ports.get(port_id):
                        LOG.debug("Attempted to remove port filter "
                              "which is not in filtered %s", port_id)
                        continue
                    self._remove_flows(deferred_sec_br,
                                       self.filtered_ports.get(port_id))
                    if remove_port:
                        self.filtered_ports.pop(port_id, None)
                except Exception:
                    LOG.exception(_("Unable to delete flows for %s") % port_id)
                finally:
                    self.release_lock(port_id)
                    self.remove_lock(port_id)

    def remove_port_filter(self, port_id):
        LOG.debug("OVSF Removing port %s filter", port_id)
        if not self.filtered_ports.get(port_id):
            LOG.debug("Attempted to remove port filter which is not "
                      "filtered %s", port_id)
            return
        self.get_lock(port_id)
        try:
            with self.sg_br.deferred() as deferred_sec_br:
                self._remove_flows(deferred_sec_br,
                                   self.filtered_ports.get(port_id))
            self.filtered_ports.pop(port_id, None)
        except Exception:
            LOG.exception(_("Unable to delete flows for %s") % port_id)
        finally:
            self.release_lock(port_id)
            self.remove_lock(port_id)

    def _get_port_vlan(self, port_id):
        if port_id:
            port = self.filtered_ports.get(port_id)
            if port and 'segmentation_id' in port:
                return port['segmentation_id']
            else:
                return self.portCache.getPortVlan(port_id)

    def _setup_flows(self, deferred_sec_br, port):
        """
        Setup base flows for a port. Default rule is to drop
        all.
        """
        vlan = self._get_port_vlan(port['id'])
        if not vlan:
            LOG.warn(_('Missing VLAN information for port %s') % port['id'])
            return
        if isinstance(port.get('allowed_address_pairs'), list):
            for address_pair in port['allowed_address_pairs']:
                if netaddr.IPNetwork(address_pair["ip_address"]).version == 4:
                    ap_proto = "ip"
                else:
                    ap_proto = "ipv6"
                deferred_sec_br.add_flow(priority=SG_RULES_PRI,
                                table=SG_DEFAULT_TABLE_ID,
                                cookie=self.get_cookie(port),
                                dl_dst=port["mac_address"],
                                in_port=self.patch_ofport,
                                dl_src=address_pair["mac_address"],
                                dl_vlan=vlan,
                                proto=ap_proto,
                                nw_src=address_pair["ip_address"],
                                actions="resubmit(,%s),output:%s" %
                                (SG_IP_TABLE_ID, self.phy_ofport))

    def _remove_flows(self, deferred_sec_br, port):
        """Remove all flows for a port."""
        LOG.debug("OVSF Removing flows start  %s ", port['id'])
        try:
            deferred_sec_br.delete_flows(cookie="%s/-1"
                % self.get_cookie(port))
            port = self.filtered_ports.get(port['id'])
            vlan = self._get_port_vlan(port['id'])
            if 'mac_address' not in port or not vlan:
                LOG.debug("OVSF Removing flows stop  %s ", port['id'])
                return
            deferred_sec_br.delete_flows(table=SG_LEARN_TABLE_ID,
                                dl_src=port['mac_address'],
                                vlan_tci="0x%04x/0x0fff" % vlan)
            deferred_sec_br.delete_flows(table=SG_LEARN_TABLE_ID,
                                dl_dst=port['mac_address'],
                                vlan_tci="0x%04x/0x0fff" % vlan)
            deferred_sec_br.delete_flows(table=SG_DEFAULT_TABLE_ID,
                                dl_src=port['mac_address'],
                                vlan_tci="0x%04x/0x0fff" % vlan)
            deferred_sec_br.delete_flows(table=SG_DEFAULT_TABLE_ID,
                                dl_dst=port['mac_address'],
                                vlan_tci="0x%04x/0x0fff" % vlan)
        except Exception:
            LOG.exception(_("Unable to remove flows %s") % port['id'])

    def _add_flows(self, deferred_sec_br, port, rules=None):
        egress_action = 'normal'
        ingress_action = 'output:%s' % self.phy_ofport

        if not rules:
            rules = port["security_group_rules"]

        vlan = self._get_port_vlan(port['id'])
        if not vlan:
            LOG.warn(_('Missing VLAN for port %s') % port['id'])
            return
        for rule in rules:
            direction = rule.get('direction')
            proto = rule.get('protocol')
            pr_min = rule.get('port_range_min')
            pr_max = rule.get('port_range_max')
            spr_min = rule.get('source_port_range_min')
            spr_max = rule.get('source_port_range_max')
            ethertype = rule.get('ethertype')
            src_ip_prefix = rule.get('source_ip_prefix')
            dest_ip_prefix = rule.get('dest_ip_prefix')
            flow = dict(priority=SG_RULES_PRI)
            flow["table"] = SG_DEFAULT_TABLE_ID
            # Lets try using port id as cookie
            flow["cookie"] = self.get_cookie(port)
            flow["dl_vlan"] = vlan

            src_ip_prefixlen = 0
            dest_ip_prefixlen = 0
            if src_ip_prefix:
                src_ip_prefixlen = netaddr.IPNetwork(src_ip_prefix).prefixlen
            if dest_ip_prefix:
                dest_ip_prefixlen = netaddr.IPNetwork(dest_ip_prefix).prefixlen

            if src_ip_prefixlen > 0:
                flow["nw_src"] = src_ip_prefix

            if dest_ip_prefixlen > 0:
                flow["nw_dst"] = dest_ip_prefix

            if ethertype == constants.IPv6 and proto == constants. \
                PROTO_NAME_ICMP:
                flow["proto"] = 'icmp6'
            elif proto is not None:
                protocol = PROTOCOLS.get(proto)
                if protocol is None:
                    flow["proto"] = ETHERTYPE.get(ethertype)
                    flow["nw_proto"] = proto
                else:
                    proto = protocol
                    flow["proto"] = proto
            elif ethertype == constants.IPv4:
                flow["proto"] = 'ip'
            elif ethertype == constants.IPv6:
                flow["proto"] = 'ipv6'

            if direction == INGRESS_DIRECTION:
                flow["dl_dst"] = port["mac_address"]
                flow["in_port"] = self.patch_ofport
                action = ingress_action
            elif direction == EGRESS_DIRECTION:
                flow["dl_src"] = port["mac_address"]
                flow["in_port"] = self.phy_ofport
                action = egress_action

            if proto == constants.PROTO_NAME_TCP:
                flow["proto"] = "tcp"
                flow["priority"] = SG_TP_PRI
                flow["actions"] = ("resubmit(,%s),%s" %
                                   (SG_TCP_TABLE_ID, action))
                self.add_flow_with_range(deferred_sec_br, flow,
                                         pr_min, pr_max,
                                         spr_min, spr_max)

            elif proto == constants.PROTO_NAME_UDP:
                flow["proto"] = "udp"
                flow["priority"] = SG_TP_PRI
                flow["actions"] = ("resubmit(,%s),%s" %
                                   (SG_UDP_TABLE_ID, action))
                self.add_flow_with_range(deferred_sec_br,
                                         flow,
                                         pr_min, pr_max,
                                         spr_min, spr_max)

            elif proto == constants.PROTO_NAME_ICMP:
                flow["proto"] = "icmp"
                flow["priority"] = SG_TP_PRI
                if pr_min is not None:
                    flow["icmp_type"] = pr_min
                if pr_max is not None:
                    flow["icmp_code"] = pr_max
                flow["actions"] = ("resubmit(,%s),%s" %
                                   (SG_ICMP_TABLE_ID, action))
                deferred_sec_br.add_flow(**flow)

            else:
                flow["actions"] = ("resubmit(,%s),%s" % (SG_IP_TABLE_ID,
                                                        action))
                deferred_sec_br.add_flow(**flow)
            LOG.debug("OVSF adding flow: %s", flow)

    def _get_device_name(self, port):
        return port['id']

    def filter_defer_apply_on(self):
        if not self._defer_apply:
            self._defer_apply = True

    def filter_defer_apply_off(self):
        if self._defer_apply:
            self._defer_apply = False

    def get_cookie(self, port):
        return ("0x%x" % (hash(port['id']) & 0xffffffffffffffff))

    def add_flow_with_range(self, deferred_sec_br, flow,
                            pr_min=None, pr_max=None,
                            spr_min=None, spr_max=None):
        if pr_min is None and pr_max is None:
            pr_min = -1
            pr_max = -1
        if spr_min is None and spr_max is None:
            spr_min = -1
            spr_max = -1

        for dport, sport in itertools.product(xrange(pr_min, pr_max + 1),
                                              xrange(spr_min, spr_max + 1)):
            if dport >= 0:
                flow["tp_dst"] = dport
            if sport >= 0:
                flow["tp_src"] = sport
            deferred_sec_br.add_flow(**flow)


class OVSFBridge(ovs_lib.OVSBridge):
    def __init__(self, br_name, root_helper, defer_order):
        super(OVSFBridge, self).__init__(br_name, root_helper)
        self.defer_order = defer_order
