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
import signal
import sys

from neutron.common import config as neutron_config
from neutron.openstack.common import log as logging
from neutron.plugins.ovsvapp.agent import agent
from neutron.plugins.ovsvapp.common import config
from neutron.plugins.ovsvapp.common import utils
from oslo.config import cfg

LOG = logging.getLogger(__name__)

opts = [cfg.StrOpt('agent_driver',
                   help=_("OVSvApp Agent implementation"),
                   default=_("neutron.plugins.ovsvapp.agent.ovsvapp_agent"
                             ".OVSvAppL2Agent"))]
CONF = cfg.CONF
CONF.register_opts(opts)

agent_obj = None


def dummy():
    neutron_config.setup_logging(cfg.CONF)


def main():
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    eventlet.monkey_patch()
    config.parse(sys.argv[1:])
    if not CONF.config_file:
        sys.exit(_("ERROR: Unable to find configuration file"))
    agent_obj = None
    try:
        config.setup_logging()
        LOG.info(_("Loading agent %s"), CONF.agent_driver)
        agent_obj = utils.load_object(CONF.agent_driver, agent.Agent)
        agent_obj.start()
    except Exception as e:
        LOG.exception(_("Error in L2 agent service"))
        if agent_obj:
            agent_obj.stop()
        sys.exit(_("ERROR: %s") % e)


def signal_handler(signum, frame):
    signals_to_names = {}
    for n in dir(signal):
        if n.startswith('SIG') and not n.startswith('SIG_'):
            signals_to_names[getattr(signal, n)] = n
    LOG.info(_("Caught %s, exiting"), signals_to_names[signum])
    if agent_obj:
        try:
            agent_obj.stop()
        except Exception:
            # Ignore any exceptions while exiting
            pass
    signal.signal(signum, signal.SIG_DFL)
    sys.exit(0)


if __name__ == '__main__':
    main()
