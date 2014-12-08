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

from neutron.plugins.ovsvapp.common import error


class State:
    # State of the driver when there is not enough info
    # to connect to hypervisor or monitor hypervisor
    # In this state the driver won't be ale to process the common model APIs
    IDLE = "IDLE"

    # The driver is ready for monitoring hypervisor
    READY = "READY"

    # The driver is in running state and monitoring hypervisor
    RUNNING = "RUNNING"

    # The driver is in stopped state
    STOPPED = "STOPPED"


class NetworkDriver(object):

    """
        Base class defining interface for all L2 network drivers
    """

    def __init__(self):
        # Reference to NetworkDriverCallback impl
        self.callback_impl = None

    def set_callback(self, callback_impl):
        """
            Sets the implementation of
            neutron.plugins.ovsvapp.drivers.NetworkDriverCallback
        """
        if not isinstance(callback_impl, NetworkDriverCallback):
            raise error.NeutronAgentError("Invalid NetworkDriverCallback")
        self.callback_impl = callback_impl

    def monitor_events(self):
        """
            Common model API - monitor for events
        """
        raise NotImplementedError()

    def pause(self):
        """
            Common model API - Driver will stop the
            processing and go to waiting
        """
        return

    def stop(self):
        """
            Common model API - To be called when the process is shutting down
            Implements any cleanups that are required.
        """
        return

    def is_connected(self):
        """
            Common model API - Gives the state of the driver.
                               Whether its connected to hypervisor or not.
        """
        raise NotImplementedError()

    def create_network(self, network, virtual_switch):
        """
            Common model API - creates l2 network on the compute node
            Arg:
                network - Type model.Network
                virtual_switch - Type model.VirtualSwitch
        """
        raise NotImplementedError()

    def delete_network(self, network, virtual_switch=None):
        """
            Common model API - deletes l2 network on the compute node
            Arg:
                network - Type model.Network
                virtual_switch - Type model.VirtualSwitch
        """
        raise NotImplementedError()

    def create_port(self, network, port, virtual_nic):
        """
            Common model API - creates switch port with specified
                port configuration on the virtual switch.
                Call create_network if network not existing
            Arg:
                network - Type model.Network
                port - Type model.Port
                virtual_nic - Type model.VirtualNic
        """
        raise NotImplementedError()

    def update_port(self, network, port, virtual_nic):
        """
            Common model API - Update the switch port
                port configuration on the virtual switch.
            Arg:
                network - Type model.Network
                port - Type model.Port
                virtual_nic - Type model.VirtualNic
        """
        raise NotImplementedError()

    def get_pg_vlanid(self, dvs_name, pg_name):
        """
         Obtain VLAN id associated with a DVS portgroup
        """
        raise NotImplementedError()

    def get_vm_ref_uuid(self, vm_uuid):
        """
         Obtain vm reference from uuid
        """
        raise NotImplementedError()

    def wait_for_portgroup(self, vm_ref, pg_name):
        """
         Wait on a portgroup on a dvswitch for a vm
        """
        raise NotImplementedError()

    def post_create_port(self, port):
        """
         Common model API - enables the specified switch
         port to allow the traffic
        Arg:
                port - Type model.Port
        """
        raise NotImplementedError()

    def post_delete_vm(self, vm):
        """Post process for a VM_DELETE task
        """
        raise NotImplementedError()

    def dispatch_events(self, events):
        """Dispatch the events to the callback on
           different green threads
        """
        for event in events:
            eventlet.spawn_n(self.callback_impl.process_event, event)


class NetworkDriverCallback(object):

    """
        Base class defining callback interface
        which the network driver will call on each hypervisor event
    """

    def process_event(self, event):
        """
            NetworkDriver calls this method when a event
            is detected on the hypervisor
            Arg:
                event - model.Event type object
                    which represents a hypervisor event
        """
        raise NotImplementedError()
