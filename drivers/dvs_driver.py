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
'''
Implements methods defined in common driver
and supports vmware distributed virtual switch.
'''

from neutron.openstack.common import log as logging
from neutron.plugins.ovsvapp.common import error
from neutron.plugins.ovsvapp.common import model
from neutron.plugins.ovsvapp.common import utils
from neutron.plugins.ovsvapp.drivers import driver
from neutron.plugins.ovsvapp.drivers import vc_driver
from neutron.plugins.ovsvapp.utils import cache
from neutron.plugins.ovsvapp.utils import common_util
from neutron.plugins.ovsvapp.utils import error_util
from neutron.plugins.ovsvapp.utils import network_util
from neutron.plugins.ovsvapp.utils import resource_util
from neutron.plugins.ovsvapp.utils import vim_util

LOG = logging.getLogger(__name__)


class DvsNetworkDriver(vc_driver.VCNetworkDriver):

    def __init__(self):
        vc_driver.VCNetworkDriver.__init__(self)

    def get_unused_portgroups(self, switch):
        return network_util.\
            get_unused_portgroup_names(self.session, switch)

    def delete_portgroup(self, switch, pg):
        network_util.delete_port_group(self.session,
                                       dvs_name=switch,
                                       pg_name=pg)

    def is_valid_switch(self, cluster_mor, switch):
        return network_util.is_valid_dvswitch(self.session,
                                              cluster_mor,
                                              switch)

    def _register_vm_for_updates(self, vm_mor, collector):
        vm_properties = ['name',
                         'config.hardware.device']
        propertyDict = {"VirtualMachine": vm_properties}
        property_filter_spec = \
            self.session._call_method(vim_util,
                                      "get_property_filter_specs",
                                      propertyDict,
                                      [vm_mor])
        self.session._call_method(vim_util,
                                  "create_filter",
                                  property_filter_spec,
                                  collector)

    def _wait_for_port_update_on_vm(self, vm_mor, pgmor):
        property_collector = None
        try:
            LOG.debug("Creating new property collector")
            property_collector = self.\
                session._call_method(vim_util,
                                     "create_property_collector")
            self._register_vm_for_updates(vm_mor, property_collector)
            version = ""
            pg_key, port_key, swuuid = (None, None, None)
            while self.state == driver.State.RUNNING:
                LOG.debug("Waiting for VM %s to connect to "
                          "port group %s" %
                          (vm_mor.value, pgmor.value))
                try:
                    update_set = self.session.\
                        _call_method(vim_util,
                                     "wait_for_updates_ex",
                                     version,
                                     collector=property_collector)
                except error_util.SocketTimeoutException:
                    # Ignore timeout
                    continue
                if update_set:
                    version = update_set.version
                    filterSet = update_set.filterSet
                    if not filterSet:
                        continue
                    for propFilterUpdate in filterSet:
                        objectSet = propFilterUpdate.objectSet
                        if not objectSet:
                            continue
                        for objectUpdate in objectSet:
                            if objectUpdate.kind == "leave":
                                LOG.warn(_("VM %(vm)s got deleted while "
                                         "waiting for it to connect to "
                                         "port group %(pg)s"),
                                         {'vm': vm_mor.value,
                                          'pg': pgmor.value})
                                return (pg_key, port_key, swuuid)
                            changes = common_util.\
                                convert_objectupdate_to_dict(objectUpdate)
                            devices = changes.get('config.hardware.device')
                            nicdvs = network_util.\
                                get_vnics_from_devices(devices)
                            if not nicdvs:
                                continue
                            for device in nicdvs:
                                if (hasattr(device, "backing") and
                                        hasattr(device.backing, "port") and
                                        device.backing.port):
                                    port = device.backing.port
                                    if (hasattr(port, "portgroupKey")):
                                        pg_key = port.portgroupKey
                                        if (pg_key == pgmor.value and
                                                hasattr(port, "portKey")):
                                            port_key = port.portKey
                                            swuuid = port.switchUuid
                                            LOG.info(_("VM %(vm)s connected to"
                                                     " port group %(pg)s"),
                                                     {'vm': vm_mor.value,
                                                      'pg': pgmor.value})
                                            return (pg_key, port_key, swuuid)
        except Exception as e:
            LOG.exception(_("Exception while waiting for VM %(vm)s"
                          " to connect to port group %(pg)s: %(err)s"),
                          {'vm': vm_mor.value, 'pg': pgmor.value, 'err': e})
            raise e
        finally:
            LOG.debug("Destroying the property collector created")
            self.session._call_method(vim_util,
                                      "destroy_property_collector",
                                      property_collector)

    @utils.require_state(state=[driver.State.READY, driver.State.RUNNING])
    def create_network(self, network, virtual_switch):
        LOG.info(_("Creating portgroup %(nm)s with vlan id %(vid)s "
                 "on virtual switch %(sw)s"),
                 {'nm': network.name, 'vid': network.config.vlan.vlanIds[0],
                 'sw': virtual_switch.name})
        network_util.\
            create_port_group(self.session,
                              dvs_name=virtual_switch.name,
                              pg_name=network.name,
                              vlan_id=network.config.vlan.vlanIds[0])

    @utils.require_state(state=[driver.State.READY, driver.State.RUNNING])
    def get_pg_vlanid(self, dvs_name, pg_name):
        LOG.info(_("Fetching details of %(pg)s on %(dvs)s"),
                 {'pg': pg_name, 'dvs': dvs_name})
        local_vlan_id = network_util.\
            get_portgroup_details(self.session, dvs_name, pg_name)
        return local_vlan_id

    @utils.require_state(state=[driver.State.READY, driver.State.RUNNING])
    def get_vm_ref_uuid(self, vm_uuid):
        LOG.info(_("Fetching reference for %s") % vm_uuid)
        vm_ref = resource_util.\
            get_vm_reference(self.session, vm_uuid)
        return vm_ref

    @utils.require_state(state=[driver.State.READY, driver.State.RUNNING])
    def wait_for_portgroup(self, vm_ref, pg_name):
        LOG.info(_("Wait for portgroup %s") % pg_name)
        pg_exists = network_util.\
            wait_on_dvs_portgroup(self.session, vm_ref, pg_name)
        return pg_exists

    @utils.require_state(state=[driver.State.READY, driver.State.RUNNING])
    def delete_network(self, network, virtual_switch=None):
        if not virtual_switch:
            dvs_list = cache.VCCache.get_cluster_switch_mapping().values()
            for dvs in dvs_list:
                self.delete_portgroup(switch=dvs,
                                      pg=network.name)
        else:
            "Handle delete_network for controllers other than Aurora"
            pass

    @utils.require_state(state=[driver.State.READY, driver.State.RUNNING])
    def update_port(self, network=None, port=None, virtual_nic=None):
        device_id = port.vm_id
        mac_address = port.mac_address
        vm_mor = resource_util.get_vm_mor_for_uuid(self.session, device_id)
        if not vm_mor:
            LOG.warn(_("VM %(vm)s with mac address %(mac)s for port %(uuid)s "
                     "not found on this node"),
                     {'vm': device_id, 'mac': mac_address, 'uuid': port.uuid})
            return False
        if port.port_status == model.PortStatus.UP:
            enabled = True
        elif port.port_status == model.PortStatus.DOWN:
            enabled = False
        else:
            raise error.NeutronAgentError("Invalid port status %s "
                                          "in update for port %s" %
                                          (port.port_status, port.uuid))
        action = "Enabling" if enabled else "Disabling"
        LOG.debug("%s port used by VM "
                  "%s for VNIC with macaddress %s" %
                  (action, device_id, mac_address))
        done = network_util.enable_disable_port_of_vm(self.session,
                                                      vm_mor,
                                                      mac_address,
                                                      enabled)
        return done

    @utils.require_state(state=[driver.State.READY, driver.State.RUNNING])
    def post_create_port(self, port):
        if port.port_status == model.PortStatus.UP:
            device_id = port.vm_id
            _clu_mor, _clu_path, vds_name = self.\
                _find_cluster_switch_for_vm(device_id)
            pg_mor = network_util.get_portgroup_mor_by_name(
                self.session,
                vds_name,
                port.network_uuid)
            if pg_mor is None:
                raise error_util.RunTimeError("Port group  %s not created "
                                "on virtual switch %s"
                                % (port.network_uuid, vds_name))
            vm_mor = resource_util.get_vm_mor_for_uuid(self.session,
                                                       device_id)
            if vm_mor is None:
                raise error_util.RunTimeError("Virtual machine %s with port "
                                " %s not created "
                                % (device_id, port.uuid))
            (pg_key, port_key, swuuid) = self.\
                _wait_for_port_update_on_vm(vm_mor, pg_mor)
            if None not in (pg_key, port_key, swuuid):
                # enable the port on virtual switch
                network_util.enable_disable_port(self.session, swuuid,
                                                 pg_key, port_key, True)
