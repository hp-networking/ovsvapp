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

import functools
import sys
import time
import traceback

from neutron.openstack.common import log as logging
from neutron.plugins.ovsvapp.common import error

LOG = logging.getLogger(__name__)


def retry(retries=0, delay=0):
    """Decorator for retry.
    retries: Number of retry times in case of exception
    delay: delay for the first retry
        Delay time will be added to the previous delay value
    on each retry
    """

    def retry_deco(func):
        @functools.wraps(func)
        def f_retry(*args, **kwargs):
            retry_count = retries
            retry_delay = delay
            while retry_count >= 0:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if retry_count:
                        LOG.error(_("Exception in %(func)s , Reason %(e)s"),
                                  {'func': func.__name__, 'e': e})
                        LOG.info(_("Sleeping for %s sec") % retry_delay)
                        time.sleep(retry_delay)
                        retry_delay = retry_delay + delay
                        LOG.info(_("Retrying..%s.") % retry_count)
                        retry_count = retry_count - 1
                        continue
                    else:
                        LOG.error(_("Exception in %(func)s , Reason %(e)s"),
                                  {'func': func.__name__, 'e': e})
                        raise
        return f_retry
    return retry_deco


def import_class(import_str):
    """Returns a class from a string including module and class."""
    mod_str, _sep, class_str = import_str.rpartition('.')
    try:
        __import__(mod_str)
        return getattr(sys.modules[mod_str], class_str)
    except (ValueError, AttributeError):
        raise ImportError('Class %s cannot be found (%s)' %
                          (class_str,
                           traceback.format_exception(*sys.exc_info())))


def load_object(driver, base_class, *args, **kwargs):
    """
        Load a class and instantiate it and
        Check if its of base type base_class
    """
    driver_obj = import_class(driver)(*args, **kwargs)
    if not isinstance(driver_obj, base_class):
        raise TypeError("Invalid type - %s not extending %s" %
                        (fullname(driver), base_class))
    return driver_obj


def fullname(cls):
    """
        Get full name of a class
    """
    module = cls.__module__
    if module is None or module == str.__class__.__module__:
        return cls.__name__
    return module + '.' + cls.__name__


class Singleton(type):

    def __init__(cls, name, bases, dict):
        super(Singleton, cls).__init__(name, bases, dict)
        cls.instance = None

    def __call__(cls, *args, **kw):
        if cls.instance is None:
            cls.instance = super(Singleton, cls).__call__(*args, **kw)
        return cls.instance


def require_state(state=None, excp=True):
    """
        Decorator to check state of an object.
        First argument of the decorated function should be
        the object whose state needs to be checked.
        Arg:
            state - valid set of states
            excp - If True then raise an exception if in invalid state
    """
    if state is not None and not isinstance(state, set):
        state = set(state)

    def outer(f):
        @functools.wraps(f)
        def inner(obj, *args, **kw):
            if state is not None and obj.state not in state:
                l_states = list(state)
                if excp:
                    raise error.\
                        NeutronAgentError("%s not allowed. "
                                          "%s is in %s state. "
                                          "Requires to be in %s state" %
                                          (f.__name__,
                                           obj.__class__.__name__,
                                           obj.state,
                                           l_states))
                else:
                    LOG.info(_("%(name)s not allowed. "
                             "%(obj)s is %(state)s state. "
                             "Requires to be in %(states)s state"),
                             {'name': f.__name__,
                              'obj': obj.__class__.__name__,
                              'state': obj.state, 'states': l_states})
                    return
            return f(obj, *args, **kw)
        return inner
    return outer
