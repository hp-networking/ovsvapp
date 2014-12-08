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

from neutron.plugins.ovsvapp.utils import vim_util
from neutron.tests.unit.ovsvapp import test
from neutron.tests.unit.ovsvapp.utils import fake_vmware_api
from neutron.tests.unit.ovsvapp.utils import stubs


class VimUtilsTestCase(test.TestCase):

    def setUp(self):
        super(VimUtilsTestCase, self).setUp()
        self.fake_visdk = self.useFixture(stubs.FakeVmware())
        self.session = self.fake_visdk.session

    def test_build_recursive_traversal_spec(self):
        client_factory = self.session._get_vim().client.factory
        trav_specs = vim_util.\
            build_recursive_traversal_spec(client_factory)
        spec_names = ["rpToRp", "rpToVm", "crToRp", "crToH",
                      "dcToHf", "dcToVmf", "dcToDs", "hToVm",
                      "dsToVm", "visitFolders"]
        for spec in trav_specs:
            self.assertIn(spec.name, spec_names)

    def test_build_property_spec(self):
        client_factory = self.session._get_vim().client.factory
        prop_spec = vim_util.\
            build_property_spec(client_factory,
                                "VirtualMachine", None, False)
        self.assertFalse(prop_spec.all)
        self.assertEqual(prop_spec.type, "VirtualMachine")
        self.assertIn("name", prop_spec.pathSet)

    def test_get_property_filter_specs_none_obj(self):
        vim = self.session._get_vim()
        property_dict = {"virtualmachine":
                         ["name", "config"]}
        property_filter_spec = vim_util.\
            get_property_filter_specs(vim, property_dict, None)
        objSpec = property_filter_spec.objectSet[0]
        self.assertEqual(objSpec.obj, vim.get_service_content().rootFolder)

    def test_get_properties_for_a_collection_of_objects(self):
        vim = self.session._get_vim()
        obj_list = [fake_vmware_api._db_content["VirtualMachine"].values()[0]]
        properties = ["name", "config"]
        objs = vim_util.\
            get_properties_for_a_collection_of_objects(vim, "VirtualMachine",
                                                       obj_list,
                                                       properties)
        self.assertEqual(len(objs), 1)
        for obj in objs:
            for prop in obj.propSet:
                self.assertIn(prop.name, properties)

    def test_get_properties_for_a_collection_empty(self):
        vim = self.session._get_vim()
        obj_list = []
        properties = ["name", "config"]
        objs = vim_util.\
            get_properties_for_a_collection_of_objects(vim, "VirtualMachine",
                                                       obj_list,
                                                       properties)
        self.assertEqual(len(objs), 0)

    def test_build_object_spec_none_traversal(self):
        client_factory = self.session._get_vim().client.factory
        obj = fake_vmware_api.DataObject()
        obj_spec = vim_util.build_object_spec(client_factory, obj, None)
        self.assertFalse(obj_spec.skip)
        self.assertEqual(obj_spec.obj, obj)
        self.assertFalse(hasattr(obj_spec, "selectSet"))
