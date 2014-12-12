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

import eventlet
import os
import time

from neutron.openstack.common import log as logging
from neutron.plugins.ovsvapp.common import config
from neutron.plugins.ovsvapp.common import utils
from neutron.plugins.ovsvapp.drivers import base_manager as manager
from neutron.plugins.ovsvapp.drivers import driver
from oslo.config import cfg

opts = [cfg.StrOpt('network_manager',
                   help=_("DriverManager implementation for NetworkDriver"),
                   default=_("neutron.plugins.ovsvapp.drivers."
                             "manager.VcenterManager")),
        cfg.StrOpt('firewall_driver',
                   help=_("DriverManager implementation for "
                          "OVS based Firewall"),
                   default=_("neutron.agent.linux.ovs_firewall."
                             "OVSFirewallDriver")),
        cfg.IntOpt('conf_file_poll_interval',
                   help=_("Interval in sec at which the conf"
                          " file is checked for updates"),
                   default=60),
        ]
CONF = cfg.CONF
CONF.register_opts(opts)

LOG = logging.getLogger(__name__)


class State:
    INITIALIZING = "INITIALIZING"
    INITIALIZED = "INITIALIZED"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"


class Agent(driver.NetworkDriverCallback):

    """
        Base class for agents which takes care of common functionalities
        like - initializing driver managers and monitoring for conf updates.
    """

    def __init__(self):
        self.net_mgr = None
        self.state = State.INITIALIZING
        self.node_up = False

    def start(self):
        LOG.debug(_("Starting L2 agent"))
        LOG.info(_("Starting configuration updates monitor"))
        t = eventlet.spawn(self._monitor_conf_updates)
        LOG.info(_("Waiting for node ACTIVE"))
        t.wait()

    def stop(self):
        LOG.debug(_("Stopping L2 agent"))
        self.state = State.STOPPING
        self._stop_managers()
        self.state = State.STOPPED

    def _stop_managers(self):
        LOG.debug(_("Stopping managers"))
        if self.net_mgr:
            self.net_mgr.stop()

    def _monitor_conf_updates(self):
        """
            Monitor all config files for any change
        """
        LOG.info(_("Started configuration updates monitor"))
        old_timestamp = {}
        config_files = CONF.config_file
        try:
            for config_file in config_files:
                old_timestamp[config_file] = self.\
                    _get_lastmodifiedtime(config_file)
            while self.state not in (State.STOPPED, State.STOPPING):
                try:
                    for config_file in config_files:
                        current_timestamp = self.\
                            _get_lastmodifiedtime(config_file)
                        if current_timestamp != old_timestamp[config_file]:
                            LOG.info(_("%s updated.") % config_file)
                            # reload all oslo config files
                            LOG.debug(_("Reloading oslo-config opts."))
                            config.parse(["--config-file=%s" %
                                          f for f in config_files])
                            old_timestamp[config_file] = current_timestamp
                            eventlet.spawn_n(self._handle_conf_updates)
                except OSError as e:
                    LOG.error(_("Failed to monitor file %(config_file)s."
                              "Cause %(error)s "), {'config_file': config_file,
                              'error': e})
                time.sleep(CONF.conf_file_poll_interval)
        except OSError as e:
            LOG.error(_("Failed to monitor file %(config_file)s."
                      "Cause %(error)s "), {'config_file': config_file,
                      'error': e})

    def _get_lastmodifiedtime(self, config_file):
        return os.stat(config_file).st_mtime

    def _handle_conf_updates(self):
        try:
            if not self.node_up:
                # handle conf updates only when node is up
                return
            self.state = State.INITIALIZING
            if self.net_mgr:
                self.net_mgr.handle_conf_update()
            self.state = State.INITIALIZED
            # Could be possible that the managers were idle
            # before this conf update. So start them
            self._start_managers()
        except Exception as e:
            LOG.exception(_("Error while handling conf update: %s"), e)

    def _initialize_managers(self):
        self.state = State.INITIALIZING
        LOG.info(_("Loading network driver manager %s"),
                 CONF.network_manager)
        self.net_mgr = utils.load_object(CONF.network_manager,
                                         manager.DriverManager,
                                         self)
        self.net_mgr.initialize_driver()
        self.state = State.INITIALIZED

    def _start_managers(self):
        if self.state == State.INITIALIZED and self.node_up:
            LOG.info(_("Starting managers"))
            if self.net_mgr:
                self.net_mgr.start()
            self.state = State.RUNNING

    def set_node_state(self, is_up):
        if is_up != self.node_up:
            self.node_up = is_up
            if is_up:
                LOG.info(_("Making node up"))
                self._initialize_managers()
                self._start_managers()
            else:
                self.state = State.INITIALIZING
                self._stop_managers()
        else:
            LOG.info(_("Ignoring node update as agent"
                     " is already %s"),
                     "ACTIVE" if self.node_up else "DOWN")
