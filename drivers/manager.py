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

import copy
import eventlet
import greenlet
from neutron.openstack.common import log as logging
from neutron.plugins.ovsvapp.drivers import base_manager
from neutron.plugins.ovsvapp.drivers import dvs_driver
from neutron.plugins.ovsvapp.utils import vim_session
from oslo.config import cfg

LOG = logging.getLogger(__name__)

vmware_opts = [cfg.StrOpt('vcenter_ip',
                          help=_("vmware vCenter IP"),
                          default=None),
               cfg.IntOpt('https_port',
                          help=_('Customized https_port for vCenter'
                                 'communication'),
                          default=443),
               cfg.StrOpt('vcenter_username',
                          help=_("vmware vCenter user name"),
                          default=None),
               cfg.StrOpt('vcenter_password',
                          help=_("vmware vCenter user password"),
                          default=None),
               cfg.StrOpt('vcenter_api_retry_count',
                          help=_("Number of retries while"
                                 " connecting to vcenter"),
                          default=5),
               cfg.StrOpt('wsdl_location',
                          help=_("vmware wsdl location."),
                          default=None),
               cfg.MultiStrOpt('cluster_dvs_mapping',
                               help=_("vCenter cluster to vDS mapping"),
                               default=[]),
               cfg.BoolOpt('is_enterprise',
                           help=_("Flag set to false for supporting"
                                  " non-enterprise vSphere"),
                           default=True)
               ]

cfg.CONF.register_opts(vmware_opts, "VMWARE")
CONF = cfg.CONF


def get_cluster_dvs_mapping():
    return CONF.VMWARE.cluster_dvs_mapping


class VcenterManager(base_manager.DriverManager):

    def __init__(self, netcallback):
        base_manager.DriverManager.__init__(self)
        self.netcallback = netcallback
        self.vcenter_ip = None
        self.vcenter_username = None
        self.vcenter_password = None
        self.vcenter_api_retry_count = None
        self.wsdl_location = None
        self.cluster_switch_mapping = {}
        self.connection_thread = None
        self.started = False
        self.is_enterprise = CONF.VMWARE.is_enterprise
        self.https_port = CONF.VMWARE.https_port

    def _parse_mapping(self, entry):
        """
            Parse an entry of cluster_dvs_mapping
            Arg:
                entry - String value which is an entry in conf file
                          for cluster_dvs_mapping.
                          This could be simple mapping in the form
                          clusterpath:vdsname or a comma separated one like
                          clusterpath1:vdsname1,clusterpath2:vdsname2
            Returns:
                A list of (cluster, dvs) tuples
        """
        try:
            tuples = []
            LOG.debug(_("Parsing cluster_dvs_mapping %s"), entry)
            mappings = entry.split(",")
            for mapping in mappings:
                cluster = None
                vds = None
                if ":" in mapping:
                    cluster, vds = mapping.split(":", 1)
                    cluster = cluster.strip()
                    vds = vds.strip()
                if not cluster or not vds:
                    LOG.error(_("Invalid value %s "
                                "for opt cluster_dvs_mapping"),
                              mapping)
                else:
                    tuples.append((cluster, vds))
        except Exception:
            LOG.exception(_("Invalid value %s for opt cluster_dvs_mapping"),
                          entry)
        return tuples

    def _add_cluster(self, cluster, vds):
        try:
            self.driver.add_cluster(cluster, vds)
        except Exception:
            LOG.exception(_("Adding cluster %(cluster)s:%(vds)s failed"),
                          {'cluster': cluster, 'vds': vds})
        else:
            self.cluster_switch_mapping[cluster] = vds

    def _remove_cluster(self, cluster, vds):
        try:
            self.driver.remove_cluster(cluster, vds)
        except Exception:
            LOG.exception(_("Removing cluster %(cluster)s:%(vds)s failed"),
                          {'cluster': cluster, 'vds': vds})
        else:
            del self.cluster_switch_mapping[cluster]

    def initialize_driver(self):
        """
            Initialize the VcNetworkDriver
        """
        self.stop()
        self.driver = None
        self.is_enterprise = CONF.VMWARE.is_enterprise
        self.vcenter_ip = CONF.VMWARE.vcenter_ip
        self.vcenter_username = CONF.VMWARE.vcenter_username
        self.vcenter_password = CONF.VMWARE.vcenter_password
        self.vcenter_api_retry_count = CONF.VMWARE.vcenter_api_retry_count
        self.wsdl_location = CONF.VMWARE.wsdl_location
        self.https_port = CONF.VMWARE.https_port
        if self.vcenter_ip and self.vcenter_username \
                and self.vcenter_password and self.wsdl_location:
            vim_session.ConnectionHandler.\
                set_vc_details(self.vcenter_ip,
                               self.vcenter_username,
                               self.vcenter_password,
                               self.vcenter_api_retry_count,
                               self.wsdl_location,
                               self.https_port)
            vim_session.ConnectionHandler.start()
            if self.connection_thread:
                # Kill the older thread
                self.connection_thread.kill()
            # This will indefinitely try for VI SDK connection
            # till successful or interrupted by a subsequent conf update
            self.connection_thread = \
                eventlet.spawn(vim_session.ConnectionHandler.try_connection)
            try:
                self.connection_thread.wait()
            except greenlet.GreenletExit:
                LOG.warn(_("Thread waiting on vCenter connection exited. "
                         "Probably caused by a concurrent update to conf."))
                return
        else:
            LOG.error(_("Must specify vcenter_ip, "
                        "vcenter_username, "
                        "vcenter_password and "
                        "wsdl_location to use "
                        "vmware driver"))
        if self.is_enterprise:
            self.driver = dvs_driver.DvsNetworkDriver()
        self.driver.set_callback(self.netcallback)
        for mapping in CONF.VMWARE.cluster_dvs_mapping:
            tuples = self._parse_mapping(mapping)
            for cluster, vds in tuples:
                self._add_cluster(cluster, vds)

    def handle_conf_update(self):
        """
            Handle configuration changes
        """
        try:
            LOG.info(_("vCenter manager handling configuration changes"))
            if self.vcenter_ip != CONF.VMWARE.vcenter_ip or \
                    self.vcenter_username != CONF.VMWARE.vcenter_username or \
                    self.vcenter_password != CONF.VMWARE.vcenter_password or \
                    self.wsdl_location != CONF.VMWARE.wsdl_location or \
                    self.is_enterprise != CONF.VMWARE.is_enterprise or \
                    self.https_port != CONF.VMWARE.https_port:
                LOG.info(_("vCenter connection parameters changed - "
                           "Reinitializing driver."))
                self.initialize_driver()
            else:
                # Check for cluster mapping changes
                old_mappings = copy.deepcopy(self.cluster_switch_mapping)
                new_mappings = {}
                for mapping in CONF.VMWARE.cluster_dvs_mapping:
                    tuples = self._parse_mapping(mapping)
                    for cluster, vds in tuples:
                        new_mappings[cluster] = vds
                        if cluster not in old_mappings or \
                                old_mappings[cluster] != vds:
                            LOG.info(_("Adding new cluster vds mapping - "
                                     "%(cluster)s:%(vds)s"),
                                     {'cluster': cluster, 'vds': vds})
                            self._add_cluster(cluster, vds)
                for cluster in old_mappings:
                    if cluster not in new_mappings:
                        LOG.info(_("Removing cluster vds mapping - "
                                 "%(cluster)s:%(old)s"),
                                 {'cluster': cluster,
                                  'old': old_mappings[cluster]})
                        self._remove_cluster(cluster, old_mappings[cluster])
        except Exception as e:
            LOG.exception(_("Error in vCenter manager "
                            "handling configuration changes : %s"), e)

    def start(self):
        """
            Start the driver event monitoring
        """
        if self.driver:
            eventlet.spawn_n(self.driver.monitor_events)

    def pause(self):
        """
            Pause the driver
        """
        if self.driver:
            self.driver.pause()

    def stop(self):
        """
            Start the driver and connection
        """
        if self.driver:
            self.driver.stop()
        vim_session.ConnectionHandler.stop()
