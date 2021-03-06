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

import uuid as uuid1


# Network Types
class NetworkType(object):
    VLAN = 'VLAN'
    VXLAN = 'VXLAN'
    NVGRE = 'NVGRE'


#Address Type
class IPAddressType(object):
    IPV4 = 'IPV4'
    IPV6 = 'IPV6'


#Post Status
class PortStatus(object):
    UP = 'UP'
    DOWN = 'DOWN'


#IP Configuration
class IPConfig(object):

    def __init__(self, ip_address, subnet_mask, gateway, **kwargs):
        self.uuid = uuid1.uuid1()
        self.ip_address = ip_address
        self.subnet_mask = subnet_mask
        self.gateway = gateway
        self.dhcp_enabled = True
        self.address_type = IPAddressType.IPV4


#Network configuration
class NetworkConfig(object):

    def __init__(self, vlan):
        self.vlan = vlan


#VLAN configuration
class Vlan(object):

    def __init__(self, vlanIds=[], operation_mode=None, vlan_type="Native"):
        self.vlan_type = vlan_type
        self.operation_mode = operation_mode
        self.vlanIds = vlanIds


class Model(dict):

    """Defines some necessary structures for most of the network models."""

    def __repr__(self):
        return (self.__class__.__name__ +
                dict.__repr__(self.__dict__))

    def __eq__(self, other):
        return (isinstance(other, self.__class__)
                and self.__dict__ == other.__dict__)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.__class__.__name__)

    def __len__(self):
        return 1


class ResourceEntity(Model):

    def __init__(self, key=None, uuid=None):
        super(ResourceEntity, self).__init__()
        if not uuid:
            uuid = uuid1.uuid1()
        self.uuid = str(uuid)
        self.key = key


class Host(ResourceEntity):

    def __init__(self, name=None, key=None):
        super(Host, self).__init__(key)
        self.name = name


class PhysicalNic(ResourceEntity):

    def __init__(self, name, mac_address, config, key=None):
        super(PhysicalNic, self).__init__(key)
        self.name = name
        self.mac_address = mac_address
        self.config = config


class VirtualSwitch(ResourceEntity):

    def __init__(self, name, pnics=None, networks=None, hosts=None, key=None):
        super(VirtualSwitch, self).__init__(key)
        self.name = name
        self.pnics = pnics or []
        self.networks = networks or []
        self.hosts = hosts or []


class Network(ResourceEntity):

    def __init__(self, name, network_type, config=None,
                 vswitches=None, ports=None, key=None):
        super(Network, self).__init__(key)
        self.name = name
        self.network_type = network_type
        self.config = config
        self.vswitches = vswitches or []
        self.ports = ports or []


class Port(ResourceEntity):

    def __init__(self, name=None, mac_address=None,
                 ipaddresses=None, vswitch_uuid=None,
                 vm_id=None, network_uuid=None, port_config=None,
                 port_status=None, key=None,
                 uuid=None):
        super(Port, self).__init__(key, uuid)
        self.name = name
        self.mac_address = mac_address
        self.ipaddresses = ipaddresses
        self.vswitch_uuid = vswitch_uuid
        self.vm_id = vm_id
        self.network_uuid = network_uuid
        self.port_config = port_config
        self.port_status = port_status


class VirtualNic(ResourceEntity):

    def __init__(self, mac_address, port_uuid,
                 vm_id, vm_name, nic_type, key=None):
        super(VirtualNic, self).__init__(key)
        self.mac_address = mac_address
        self.port_uuid = port_uuid
        self.vm_id = vm_id
        self.vm_name = vm_name
        self.nic_type = nic_type


class VirtualMachine(ResourceEntity):

    def __init__(self, name, vnics, uuid=None, key=None):
        if uuid:
            super(VirtualMachine, self).__init__(key, uuid)
        else:
            super(VirtualMachine, self).__init__(key)
        # Currently this field may not be filled as it requires caching
        self.name = name
        self.vnics = vnics  # List of type VirtualNic


class EventType(object):
    VM_CREATED = 'VM_CREATED'
    VM_UPDATED = 'VM_UPDATED'
    VM_DELETED = 'VM_DELETED'
    VNIC_ADDED = 'VNIC_ADDED'
    VNIC_REMOVED = 'VNIC_REMOVED'


class Event(Model):

    def __init__(self, event_type, src_obj, changes, host_name,
                 cluster_name, cluster_id):
        self.event_type = event_type  # One of EventType
        self.src_obj = src_obj
        # Dictionary of field name to
        # a tuple having (old value, new value)
        # Currently this field is not filled as it requires caching
        self.changes = changes
        self.host_name = host_name
        self.cluster_name = cluster_name
        self.cluster_id = cluster_id
