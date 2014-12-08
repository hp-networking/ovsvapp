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
from neutron.plugins.ovsvapp.utils import error_util
from neutron.plugins.ovsvapp.utils import vim
from neutron.plugins.ovsvapp.utils import vim_util

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


class VMWareAPISession():

    """
    Sets up a session with the ESX host and handles all
    the calls made to the host.
    """

    def __init__(self, host_ip, host_username, host_password,
                 api_retry_count, wsdl_url, scheme="https", https_port=443):
        self._host_ip = host_ip
        self._host_username = host_username
        self._host_password = host_password
        self._https_port = https_port
        self.api_retry_count = api_retry_count
        self.wsdl_url = wsdl_url
        self._scheme = scheme
        self._session_id = None
        self.vim = None
        self._create_session()

    def _get_vim_object(self):
        """Create the VIM Object instance."""
        return vim.Vim(protocol=self._scheme,
                       host=self._host_ip,
                       https_port=self._https_port,
                       wsdl_url=self.wsdl_url)

    def _create_session(self):
        """Creates a session with the ESX host."""

        try:
            # Login and setup the session with the ESX host for making
            # API calls
            LOG.info(("Creating session with the ESX!"))
            self.vim = self._get_vim_object()
            session = self.vim.Login(
                self.vim.get_service_content().sessionManager,
                userName=self._host_username,
                password=self._host_password)
            # Terminate the earlier session, if possible ( For the sake of
            # preserving sessions as there is a limit to the number of
            # sessions we can have )
            if self._session_id:
                try:
                    self.vim.TerminateSession(
                        self.vim.get_service_content().sessionManager,
                        sessionId=[self._session_id])
                except Exception as excep:
                    # This exception is something we can live with. It is
                    # just an extra caution on our side. The session may
                    # have been cleared. We could have made a call to
                    # SessionIsActive, but that is an overhead because we
                    # anyway would have to call TerminateSession.
                    print(excep)
            self._session_id = session.key
            LOG.info(("Connection Established!"))
            return
        except Exception as excep:
            LOG.exception(("In vmwareapi:_create_session got"
                           " this exception: %s") % excep)
            raise

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

    def logout(self):
        if self.vim is not None:
            LOG.info(("Logging out from VI SDK session"))
            self.vim.Logout(self.vim.get_service_content().sessionManager)

    def _is_vim_object(self, module):
        """Check if the module is a VIM Object instance."""
        return isinstance(module, vim.Vim)

    def _call_method(self, module, method, *args, **kwargs):
        """
        Calls a method within the module specified with
        args provided.
        """
        args = list(args)
        retry_count = 0
        exc = None
        last_fault_list = []
        while True:
            try:
                if not self._is_vim_object(module):
                    # If it is not the first try, then get the latest
                    # vim object
                    if retry_count > 0:
                        args = args[1:]
                    args = [self.vim] + args
                retry_count += 1
                temp_module = module

                for method_elem in method.split("."):
                    temp_module = getattr(temp_module, method_elem)

                return temp_module(*args, **kwargs)
            except error_util.VimFaultException as excep:
                # If it is a Session Fault Exception, it may point
                # to a session gone bad. So we try re-creating a session
                # and then proceeding ahead with the call.
                exc = excep
                if error_util.FAULT_NOT_AUTHENTICATED in excep.fault_list:
                    # Because of the idle session returning an empty
                    # RetrievePropertiesResponse and also the same is returned
                    # when there is say empty answer to the query for
                    # VMs on the host ( as in no VMs on the host), we have no
                    # way to differentiate.
                    # So if the previous response was also am empty response
                    # and after creating a new session, we get the same empty
                    # response, then we are sure of the response being supposed
                    # to be empty.
                    if error_util.FAULT_NOT_AUTHENTICATED in last_fault_list:
                        return []
                    last_fault_list = excep.fault_list
                    self._create_session()
                else:
                    # No re-trying for errors for API call has gone through
                    # and is the caller's fault. Caller should handle these
                    # errors. e.g, InvalidArgument fault.
                    break
            except error_util.SessionOverLoadException as excep:
                # For exceptions which may come because of session overload,
                # we retry
                exc = excep
            except Exception as excep:
                # If it is a proper exception, say not having furnished
                # proper data in the SOAP call or the retry limit having
                # exceeded, we raise the exception
                exc = excep
                break
            # If retry count has been reached then break and
            # raise the exception
            if retry_count > self.api_retry_count:
                break
            time.sleep(TIME_BETWEEN_API_CALL_RETRIES)

        if not isinstance(exc, error_util.SocketTimeoutException):
            # Do not log socket timeout
            LOG.exception(("In vmwareapi:_call_method, "
                           "got this exception: %s") % exc)
        raise

    def _get_vim(self):
        """Gets the VIM object reference."""
        if self.vim is None:
            self._create_session()
        return self.vim

    def _wait_for_task(self, task_ref):
        """
        The task is polled until it completes.
        """
        while True:
            task_info = self._call_method(vim_util, "get_dynamic_property",
                                          task_ref, "Task", "info")
            if task_info.state in ['queued', 'running']:
                time.sleep(2)
            elif task_info.state == 'success':
                LOG.info(_("Task : %(name)s (%(key)s) status: success"),
                         {'name': task_info.name, 'key': task_info.key})
                return
            elif task_info.state == 'error':
                error_info = str(task_info.error.localizedMessage)
                LOG.error(_("Task : %(name)s (%(key)s) status: error, "
                          "cause: %(err)s"),
                          {'name': task_info.name, 'key': task_info.key,
                           'err': error_info})
                raise error_util.RunTimeError(error_info)
