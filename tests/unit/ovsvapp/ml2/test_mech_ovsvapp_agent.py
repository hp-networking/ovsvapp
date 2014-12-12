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
#Unit test for hpvcn_neutron_agent Mechanism Driver

from neutron.extensions import portbindings
from neutron.plugins.ovsvapp.ml2 import mech_ovsvapp_agent
from neutron.tests.unit.ml2 import _test_mech_agent as base


class OVSvAppAgentMechanismBaseTestCase(base.AgentMechanismBaseTestCase):
    VIF_TYPE = portbindings.VIF_TYPE_OTHER
    CAP_PORT_FILTER = True
    AGENT_TYPE = 'OVSvApp L2 Agent'

    GOOD_CONFIGS = {}
    AGENTS = [{'alive': True,
               'configurations': GOOD_CONFIGS}]
    AGENTS_BAD = [{'alive': False,
                   'configurations': GOOD_CONFIGS}]

    def setUp(self):
        super(OVSvAppAgentMechanismBaseTestCase, self).setUp()
        self.driver = mech_ovsvapp_agent.\
            HpvcnNeutronAgentMechanismDriver()
        self.driver.initialize()


class HpvcnNeutonAgentMechanismGenericTestCase(
    OVSvAppAgentMechanismBaseTestCase,
    base.AgentMechanismGenericTestCase):
    pass


class HpvcnNeutonAgentMechanismVlanTestCase(
    OVSvAppAgentMechanismBaseTestCase,
    base.AgentMechanismVlanTestCase):
    pass
