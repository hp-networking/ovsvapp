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

import time

from neutron.openstack.common import log as logging
from oslo.vmware import api
from oslo.vmware import vim

LOG = logging.getLogger(__name__)

TIME_BETWEEN_API_CALL_RETRIES = 2.0


class ConnectionHandler:
    session = None
    host_ip = None
    host_username = None
    host_password = None
    api_retry_count = None
    wsdl_url = None
    scheme = None
    stopped = False

    @classmethod
    def set_vc_details(cls, host_ip, host_username, host_password,
                       api_retry_count, wsdl_url, https_port=443,
                       scheme="https"):
        cls.session = None
        cls.host_ip = host_ip
        cls.host_username = host_username
        cls.host_password = host_password
        cls.api_retry_count = api_retry_count
        cls.wsdl_url = wsdl_url
        cls.scheme = scheme
        cls.https_port = https_port
        cls.stopped = False

    @classmethod
    def stop(cls):
        cls.stopped = True
        if cls.session:
            cls.session.logout()
        cls.session = None

    @classmethod
    def start(cls):
        cls.stopped = False

    @classmethod
    def create_connection(cls):
        cls.session = VMWareAPISession(cls.host_ip,
                                       cls.host_username,
                                       cls.host_password,
                                       cls.api_retry_count,
                                       cls.wsdl_url,
                                       cls.scheme,
                                       cls.https_port)
        return cls.session

    @classmethod
    def get_connection(cls, create=False):
        if not cls.session and create:
            return cls.create_connection()
        else:
            return cls.session

    @classmethod
    def try_connection(cls):
        while not cls.stopped:
            try:
                return cls.get_connection(create=True)
            except Exception as e:
                LOG.error(_("VMWare Connection failed - %s"), e)
                LOG.error(_("Will retry after 60 sec"))
                time.sleep(60)
                LOG.error(_("Retrying VMWare Connection after 60 sec"))
                continue


class VMWareAPISession(api.VMwareAPISession):

    """
    Sets up a session with the ESX host and handles all
    the calls made to the host.
    """

    def __init__(self, host_ip, host_username, host_password,
                 api_retry_count, wsdl_url, scheme="https", https_port=443,
                 ca_cert=None):
        super(VMWareAPISession, self).__init__(
                host=host_ip,
                port=https_port,
                server_username=host_username,
                server_password=host_password,
                api_retry_count=api_retry_count,
                scheme=scheme,
                task_poll_interval=1,
                wsdl_loc=wsdl_url,
                create_session=True,
                cacert=ca_cert)

    def __del__(self):
        """Logs-out the session."""
        # Logout to avoid un-necessary increase in session count at the
        # ESX host
        try:
            self.logout()
        except Exception:
            pass
            # It is just cautionary on our part to do a logout in del just
            # to ensure that the session is not left active.
            #LOG.exception(("exception in __del__ : %s") % excep)

    def _is_vim_object(self, module):
        """Check if the module is a VIM Object instance."""
        return isinstance(module, vim.Vim)

    def _call_method(self, module, method, *args, **kwargs):
        """
        Calls a method within the module specified with
        args provided.
        """
        if not self._is_vim_object(module):
            return self.invoke_api(module, method, self.vim, *args, **kwargs)
        else:
            return self.invoke_api(module, method, *args, **kwargs)

    def _get_vim(self):
        """Gets the VIM object reference."""
        return self.vim

    def _wait_for_task(self, task_ref):
        """
        The task is polled until it completes.
        """
        return self.wait_for_task(task_ref)
