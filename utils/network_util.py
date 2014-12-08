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

from eventlet import greenthread
from neutron.openstack.common import log as logging
from neutron.plugins.ovsvapp.utils import common_util
from neutron.plugins.ovsvapp.utils import error_util
from neutron.plugins.ovsvapp.utils import resource_util
from neutron.plugins.ovsvapp.utils import vim_util
from oslo.config import cfg


LOG = logging.getLogger(__name__)

# Registered esx_hostname temporarily to pass py27 issues
# To be removed when subagent.py will be added to the repo
VMWARE_OPTS = [
    cfg.StrOpt('esx_hostname', default="default",
               help=_('ESX host name where this OVSvApp is hosted')),
]

cfg.CONF.register_opts(VMWARE_OPTS, "VMWARE")


def get_dvs_mor_by_uuid(session, uuid):
    """
        Return vDS mor by UUID
    """
    return session._call_method(vim_util,
                                "get_dvs_mor_by_uuid",
                                uuid)


def get_dvs_mor_by_name(session, dvs_name):
    """
    Return DVS mor from its name
    """
    dvs_mors = session._call_method(
        vim_util, "get_objects", "DistributedVirtualSwitch", ["name"])
    for dvs_mor in dvs_mors:
        propset_dict = common_util.convert_propset_to_dict(dvs_mor.propSet)
        if propset_dict['name'] == dvs_name:
            return dvs_mor.obj
    return None


def is_valid_dvswitch(session, cluster_mor, dvs_name):
    """
       Check if DVS is present for the cluster specified in conf.
       Also validate if DVS is attached to all the hosts in the cluster.
    """
    dvs_mor = get_dvs_mor_by_name(session, dvs_name)
    if dvs_mor:
        dvs_config = session._call_method(
            vim_util, "get_dynamic_property", dvs_mor,
            "DistributedVirtualSwitch", "config.host")
        # Get all the host attached to given VDS
        dvs_host_members = dvs_config[0]
        dvs_attached_host_ids = []
        for dvs_host_member in dvs_host_members:
            dvs_attached_host_ids.append(dvs_host_member.config.host.value)

        # Get all the hosts present in the cluster
        hosts_in_cluster = resource_util.get_host_mors_for_cluster(
            session, cluster_mor)

        # Check if the host on which OVSvApp VM is hosted is a part of DVSwitch
        if hosts_in_cluster:
            for host in hosts_in_cluster:
                hostname = resource_util.get_hostname_for_host_mor(
                    session, host)
                if hostname == cfg.CONF.VMWARE.esx_hostname:
                    if host.value not in dvs_attached_host_ids:
                        LOG.error(_("DVS not present on host %s") % host.value)
                        return
            return hosts_in_cluster
    else:
        LOG.error(_("Switch not present"))


def get_all_portgroup_mors_for_switch(session, dvs_name):
    """
    Returns a list Managed Object Reference for all the portgroups
    attached to the specified dvs
    """
    dvs_mor = get_dvs_mor_by_name(session, dvs_name)
    if dvs_mor:
        dvs_config = session._call_method(
            vim_util, "get_dynamic_property", dvs_mor,
            "DistributedVirtualSwitch", "portgroup")
        port_group_mors = dvs_config.ManagedObjectReference
        return port_group_mors
    return None


def get_unused_portgroup_names(session, dvs_name):
    """
    Returns a list Managed Object Reference for all the portgroups
    attached to the specified dvs and are not connected to any virtual Machine.
    """
    unsed_port_group_names = []
    port_group_mors = get_all_portgroup_mors_for_switch(session, dvs_name)
    if port_group_mors:
        port_groups = session._call_method(
            vim_util, "get_properties_for_a_collection_of_objects",
            "DistributedVirtualPortgroup", port_group_mors,
            ["summary.name", "tag", "vm"])
        for port_group in port_groups:
            propset_dict = common_util.convert_propset_to_dict(
                port_group.propSet)
            if not propset_dict['vm'] and not propset_dict['tag']:
                unsed_port_group_names.append(propset_dict['summary.name'])
    return unsed_port_group_names


def get_portgroup_mor_by_name(session, dvs_name, port_group_name):
    """
       check if portgroup exists on the DV switch.
    """
    port_group_mors = get_all_portgroup_mors_for_switch(session, dvs_name)
    if port_group_mors:
        port_groups = session._call_method(
            vim_util, "get_properties_for_a_collection_of_objects",
            "DistributedVirtualPortgroup", port_group_mors, ["summary.name"])
        for port_group in port_groups:
            if port_group.propSet[0].val == port_group_name:
                return port_group.obj
    return None


def _get_add_vswitch_port_group_spec(client_factory,
                                     port_group_name, vlan_id):
    """Builds the virtual switch port group add spec."""
    vswitch_port_group_spec = client_factory.create(
        'ns0:DVPortgroupConfigSpec')
    vswitch_port_group_spec.name = port_group_name

    # VLAN ID of 0 means that VLAN tagging is not to be done for the network.
    portSettingSpec = client_factory.create('ns0:VMwareDVSPortSetting')
    vlanSpec = client_factory.create(
        'ns0:VmwareDistributedVirtualSwitchVlanIdSpec')
    vlanSpec.inherited = False
    vlanSpec.vlanId = vlan_id
    portSettingSpec.vlan = vlanSpec

    vswitch_port_group_spec.autoExpand = True
    vswitch_port_group_spec.type = "earlyBinding"
    vswitch_port_group_spec.defaultPortConfig = portSettingSpec
    return vswitch_port_group_spec


def get_portgroup_and_datacenter_id_by_name(session, dvs_name,
                                            port_group_name):
        """
           Returns portgroup and datacenter mor id .
        """
        portgroup_id = None
        datacenter_id = None
        port_group_mors = get_all_portgroup_mors_for_switch(session, dvs_name)
        if port_group_mors:
            port_groups = session._call_method(
                vim_util, "get_properties_for_a_collection_of_objects",
                "DistributedVirtualPortgroup", port_group_mors,
                ["summary.name", 'parent'])

            folder_mor = None
            for port_group in port_groups:
                propset_dict = common_util.convert_propset_to_dict(
                    port_group.propSet)
                if propset_dict["summary.name"] == port_group_name:
                    portgroup_id = port_group.obj.value
                    folder_mor = propset_dict["parent"]
                    break

            if folder_mor is not None:
                props = session._call_method(vim_util,
                                             "get_dynamic_properties",
                                             folder_mor,
                                             ["parent"])
                datacenter_id = props['parent'].value

        return (portgroup_id, datacenter_id)


def get_portgroup_details(session, dvs_name, pg_name):
    """
    Get VLAN id associated with a portgroup on a DVS
    """
    LOG.debug("Entered get_portgroup_details:"
              " (dvs name, portgroup name) : (%s, %s)" %
              (dvs_name, pg_name))
    port_group_mor = get_portgroup_mor_by_name(session, dvs_name, pg_name)
    if port_group_mor:
        # check if vlan-id is correct for the portgroup
        port_group_config = session._call_method(
            vim_util, "get_dynamic_property", port_group_mor,
            "DistributedVirtualPortgroup", "config")
        vlan_id = port_group_config.defaultPortConfig.vlan.vlanId
        LOG.info(_("Portgroup %(pg)s is associated with vlan id %(vid)s "),
                 {'pg': pg_name, 'vid': vlan_id})
    else:
        vlan_id = 0
    return vlan_id


def wait_on_dvs_portgroup(session, vm_ref, pg_name):
    """
    Wait for a portgroup creation on a dvswitch
    """
    # max_counts - taken as reference from vmwareapi_nic_attach_retry_count
    max_counts = 25
    count = 0
    while count < max_counts:
        host = session._call_method(vim_util, "get_dynamic_property",
                                    vm_ref, "VirtualMachine", "runtime.host")
        vm_networks_ret = session._call_method(vim_util,
                                               "get_dynamic_property", host,
                                               "HostSystem", "network")
        if vm_networks_ret:
            vm_networks = vm_networks_ret.ManagedObjectReference
            for network in vm_networks:
                # Get network properties
                if network._type == 'DistributedVirtualPortgroup':
                    props = session._call_method(vim_util,
                                                 "get_dynamic_property",
                                                 network,
                                                 network._type,
                                                 "config")
                    if props.name in pg_name:
                        LOG.debug(_("DistributedVirtualPortgroup %s "
                                    "created") % pg_name)
                        return True
        count += 1
        LOG.debug(_("Portgroup %s not created yet. Retrying again "
                    "after 2 seconds") % pg_name)
        greenthread.sleep(2)
    if count == max_counts:
        LOG.debug(_("Tried max times, but portgroup %s not created") % pg_name)
    return False


def create_port_group(session, dvs_name, pg_name, vlan_id):
    """
    Creates a dvport group on the specified
    Distributed Virtual Switch with the vlan tags supplied.
    """
    LOG.debug("Entered create_port_group :"
              " (dvs name, portgroup name, vlanid) : (%s, %s, %s)" %
              (dvs_name, pg_name, vlan_id))
    port_group_mor = get_portgroup_mor_by_name(session, dvs_name, pg_name)
    if port_group_mor:
        # check if vlan-id is correct for the portgroup
        port_group_config = session._call_method(
            vim_util, "get_dynamic_property", port_group_mor,
            "DistributedVirtualPortgroup", "config")
        if vlan_id == port_group_config.defaultPortConfig.vlan.vlanId:
            LOG.info(_("Portgroup %(pg)s with vlan id %(vid)s already exists"),
                     {'pg': pg_name, 'vid': vlan_id})
            return
        else:
            LOG.info(_("portgroup %(pg)s already exists "
                     "but with vlan id %(vid)s"),
                     {'pg': pg_name,
                      'vid': port_group_config.defaultPortConfig.vlan.vlanId})
            raise error_util.RunTimeError("Inconsistent vlan id for portgroup"
                                          " %s", pg_name)
    else:
        client_factory = session._get_vim().client.factory
        add_prt_grp_spec = _get_add_vswitch_port_group_spec(
            client_factory, pg_name, vlan_id)
        # All the ports are blocked by default on creation of port group
        # the ports will be enabled after its security groups are applied
        blocked = client_factory.create('ns0:BoolPolicy')
        blocked.value = False
        blocked.inherited = False
        add_prt_grp_spec.defaultPortConfig.blocked = blocked
        dvs_mor = get_dvs_mor_by_name(session, dvs_name)

        try:
            task_ref = session._call_method(
                session._get_vim(), "AddDVPortgroup_Task", dvs_mor,
                spec=add_prt_grp_spec)
            session._wait_for_task(task_ref)
            LOG.info(_("Successfully created portgroup "
                     "%(pg)s with vlan id %(vid)s"),
                     {'pg': pg_name, 'vid': vlan_id})
        except Exception as e:
            LOG.exception(_("Failed to create portgroup %(pg)s with "
                          "vlan id %(vid)s on vCenter. Cause : %(err)s"),
                          {'pg': pg_name, 'vid': vlan_id, 'err': e})
            raise error_util.RunTimeError("Failed to create portgroup %s "
                                          "with vlan id %s on vCenter.Cause"
                                          " : %s" % (pg_name, vlan_id, e))


def delete_port_group(session, dvs_name, pg_name):
    """
    Deletes a dvport group on the specified Distributed
    Virtual Switch.
    """
    LOG.debug("Deleting portgroup %s from dvs %s" % (pg_name, dvs_name))
    port_group_mor = get_portgroup_mor_by_name(session, dvs_name, pg_name)
    if port_group_mor:
        try:
            destroy_task = session._call_method(session._get_vim(),
                                                "Destroy_Task", port_group_mor)
            session._wait_for_task(destroy_task)
            LOG.info(_("Successfully deleted portgroup %(pg)s from "
                     "dvs %(dvs)s"),
                     {'pg': pg_name, 'dvs': dvs_name})
        except Exception as e:
            LOG.exception(_("Failed to delete portgroup %(pg)s from "
                          "dvs %(dvs)s .Cause : %(err)s"),
                          {'pg': pg_name, 'dvs': dvs_name, 'err': e})
            #raise Exception("Failed to delete portgroup %s from dvs %s ."
            #                "Cause : %s" % (pg_name, dvs_name, e))
    else:
        LOG.info(_("portgroup %(pg)s not present on dvs %(dvs)s"),
                 {'pg': pg_name, 'dvs': dvs_name})


def enable_disable_port_of_vm(session, vm_mor, mac_address, enabled):
    """Enable/disable a port of the VM having particular mac_address.

    Arguments:
        vm_mor - MOR of the VM
        mac_address - mac address of the port
        enabled - True for enabling, False for disabling the port
    """
    props = session._call_method(vim_util,
                                 "get_dynamic_properties",
                                 vm_mor,
                                 ["config.hardware.device"])
    devices = props["config.hardware.device"]
    LOG.debug("Found %s devices on VM %s" %
              (len(devices.VirtualDevice), vm_mor.value))
    vnics = get_vnics_from_devices(devices)
    for device in vnics:
        if (hasattr(device, "macAddress") and
                device.macAddress == mac_address):
            port = device.backing.port
            pgkey = port.portgroupKey
            portkey = port.portKey
            swuuid = port.switchUuid
            enable_disable_port(session, swuuid, pgkey, portkey, enabled)
            return True
    return False


def get_vnics_from_devices(devices):
    vnics = None
    if (devices and hasattr(devices, "VirtualDevice")):
        vnics = []
        devices = devices.VirtualDevice
        for device in devices:
            if (device.__class__.__name__ in
                ("VirtualEthernetCard",
                 "VirtualE1000", "VirtualE1000e",
                 "VirtualPCNet32", "VirtualVmxnet",
                 "VirtualVmxnet2", "VirtualVmxnet3")):
                vnics.append(device)
    return vnics


def enable_disable_port(session, swuuid, pgkey, portkey, enabled):
    action = "Enabling" if enabled else "Disabling"
    LOG.debug("%s port %s on %s" % (action, portkey, pgkey))
    vds_mor = get_dvs_mor_by_uuid(session, swuuid)
    client_factory = session._get_vim().client.factory
    spec = client_factory.create('ns0:DVPortConfigSpec')
    spec.key = portkey
    spec.operation = "edit"
    setting = client_factory.create('ns0:DVPortSetting')
    blocked = client_factory.create('ns0:BoolPolicy')
    blocked.value = not enabled
    blocked.inherited = False
    setting.blocked = blocked
    spec.setting = setting
    reconfig_task = session._call_method(session._get_vim(),
                                         "ReconfigureDVPort_Task",
                                         vds_mor,
                                         port=[spec])
    session._wait_for_task(reconfig_task)
    action = "enabled" if enabled else "disabled"
    LOG.debug("Successfully %s port %s on port group %s on dvs '%s'" %
              (action, portkey, pgkey, swuuid))


def port_block_status_on_vm(session, vm_id, mac_address):
    block_status = True
    vm_mor = resource_util.get_vm_mor_for_uuid(session,
                                               vm_id)
    props = session._call_method(vim_util,
                                 "get_dynamic_properties",
                                 vm_mor,
                                 ["config.hardware.device"])
    devices = props["config.hardware.device"]
    LOG.debug("Found %s devices on VM %s" %
              (len(devices.VirtualDevice), vm_mor.value))
    vnics = get_vnics_from_devices(devices)
    for device in vnics:
        if (hasattr(device, "macAddress") and
                device.macAddress == mac_address):
            port = device.backing.port
            pgkey = port.portgroupKey
            portkey = port.portKey
            swuuid = port.switchUuid
            block_status = port_block_status(session,
                                             swuuid, pgkey,
                                             portkey)
            LOG.info(_("Block status of port %(pkey)s on port group %(pgkey)s"
                     "on dvs %(uuid)s is %(status)s"),
                     {'pkey': portkey, 'pgkey': pgkey,
                      'uuid': swuuid, 'status': str(block_status)})
            break
    return block_status


def port_block_status(session, swuuid, pgkey, portkey):
    vds_mor = get_dvs_mor_by_uuid(session, swuuid)
    client_factory = session._get_vim().client.factory
    vswitch_port_criteria = client_factory.create(
        'ns0:DistributedVirtualSwitchPortCriteria')
    vswitch_port_criteria.portKey = portkey
    vswitch_port_criteria.portgroupKey = pgkey
    dvport = session._call_method(
        session._get_vim(
        ), "FetchDVPorts", vds_mor,
        criteria=vswitch_port_criteria)
    if dvport and len(dvport) == 1:
        return dvport[0].config.setting.blocked.value
