# Contributors Listed Below - COPYRIGHT 2016
# [+] International Business Machines Corp.
#
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.

import os
import dbus
import dbus.exceptions
import json
from xml.etree import ElementTree
from bottle import Bottle, abort, request, response, JSONPlugin, HTTPError
from bottle import static_file
import obmc.utils.misc
from obmc.dbuslib.introspection import IntrospectionNodeParser
import obmc.mapper
import spwd
import grp
import crypt
import tempfile
import re

DBUS_UNKNOWN_INTERFACE = 'org.freedesktop.UnknownInterface'
DBUS_UNKNOWN_INTERFACE_ERROR = 'org.freedesktop.DBus.Error.UnknownInterface'
DBUS_UNKNOWN_METHOD = 'org.freedesktop.DBus.Error.UnknownMethod'
DBUS_INVALID_ARGS = 'org.freedesktop.DBus.Error.InvalidArgs'
DBUS_TYPE_ERROR = 'org.freedesktop.DBus.Python.TypeError'
DELETE_IFACE = 'xyz.openbmc_project.Object.Delete'

_4034_msg = "The specified %s cannot be %s: '%s'"


def valid_user(session, *a, **kw):
    ''' Authorization plugin callback that checks
    that the user is logged in. '''
    if session is None:
        abort(401, 'Login required')


def get_type_signature_by_introspection(bus, service, object_path,
                                        property_name):
    obj = bus.get_object(service, object_path)
    iface = dbus.Interface(obj, 'org.freedesktop.DBus.Introspectable')
    xml_string = iface.Introspect()
    for child in ElementTree.fromstring(xml_string):
        # Iterate over each interfaces's properties to find
        # matching property_name, and return its signature string
        if child.tag == 'interface':
            for i in child.iter():
                if ('name' in i.attrib) and \
                   (i.attrib['name'] == property_name):
                    type_signature = i.attrib['type']
                    return type_signature


def get_method_signature(bus, service, object_path, interface, method):
    obj = bus.get_object(service, object_path)
    iface = dbus.Interface(obj, 'org.freedesktop.DBus.Introspectable')
    xml_string = iface.Introspect()
    arglist = []

    root = ElementTree.fromstring(xml_string)
    for dbus_intf in root.findall('interface'):
        if (dbus_intf.get('name') == interface):
            for dbus_method in dbus_intf.findall('method'):
                if(dbus_method.get('name') == method):
                    for arg in dbus_method.findall('arg'):
                        arglist.append(arg.get('type'))
                    return arglist


def split_struct_signature(signature):
    struct_regex = r'(b|y|n|i|x|q|u|t|d|s|a\(.+?\)|\(.+?\))|a\{.+?\}+?'
    struct_matches = re.findall(struct_regex, signature)
    return struct_matches


def convert_type(signature, value):
    # Basic Types
    converted_value = None
    converted_container = None
    basic_types = {'b': bool, 'y': dbus.Byte, 'n': dbus.Int16, 'i': int,
                   'x': long, 'q': dbus.UInt16, 'u': dbus.UInt32,
                   't': dbus.UInt64, 'd': float, 's': str}
    array_matches = re.match(r'a\((\S+)\)', signature)
    struct_matches = re.match(r'\((\S+)\)', signature)
    dictionary_matches = re.match(r'a{(\S+)}', signature)
    if signature in basic_types:
        converted_value = basic_types[signature](value)
        return converted_value
    # Array
    if array_matches:
        element_type = array_matches.group(1)
        converted_container = list()
        # Test if value is a list
        # to avoid iterating over each character in a string.
        # Iterate over each item and convert type
        if isinstance(value, list):
            for i in value:
                converted_element = convert_type(element_type, i)
                converted_container.append(converted_element)
        # Convert non-sequence to expected type, and append to list
        else:
            converted_element = convert_type(element_type, value)
            converted_container.append(converted_element)
        return converted_container
    # Struct
    if struct_matches:
        element_types = struct_matches.group(1)
        split_element_types = split_struct_signature(element_types)
        converted_container = list()
        # Test if value is a list
        if isinstance(value, list):
            for index, val in enumerate(value):
                converted_element = convert_type(split_element_types[index],
                                                 value[index])
                converted_container.append(converted_element)
        else:
            converted_element = convert_type(element_types, value)
            converted_container.append(converted_element)
        return tuple(converted_container)
    # Dictionary
    if dictionary_matches:
        element_types = dictionary_matches.group(1)
        split_element_types = split_struct_signature(element_types)
        converted_container = dict()
        # Convert each element of dict
        for key, val in value.iteritems():
            converted_key = convert_type(split_element_types[0], key)
            converted_val = convert_type(split_element_types[1], val)
            converted_container[converted_key] = converted_val
        return converted_container


class UserInGroup:
    ''' Authorization plugin callback that checks that the user is logged in
    and a member of a group. '''
    def __init__(self, group):
        self.group = group

    def __call__(self, session, *a, **kw):
        valid_user(session, *a, **kw)
        res = False

        try:
            res = session['user'] in grp.getgrnam(self.group)[3]
        except KeyError:
            pass

        if not res:
            abort(403, 'Insufficient access')


class RouteHandler(object):
    _require_auth = obmc.utils.misc.makelist(valid_user)
    _enable_cors = True

    def __init__(self, app, bus, verbs, rules, content_type=''):
        self.app = app
        self.bus = bus
        self.mapper = obmc.mapper.Mapper(bus)
        self._verbs = obmc.utils.misc.makelist(verbs)
        self._rules = rules
        self._content_type = content_type

        if 'GET' in self._verbs:
            self._verbs = list(set(self._verbs + ['HEAD']))
        if 'OPTIONS' not in self._verbs:
            self._verbs.append('OPTIONS')

    def _setup(self, **kw):
        request.route_data = {}

        if request.method in self._verbs:
            if request.method != 'OPTIONS':
                return self.setup(**kw)

            # Javascript implementations will not send credentials
            # with an OPTIONS request.  Don't help malicious clients
            # by checking the path here and returning a 404 if the
            # path doesn't exist.
            return None

        # Return 405
        raise HTTPError(
            405, "Method not allowed.", Allow=','.join(self._verbs))

    def __call__(self, **kw):
        return getattr(self, 'do_' + request.method.lower())(**kw)

    def do_head(self, **kw):
        return self.do_get(**kw)

    def do_options(self, **kw):
        for v in self._verbs:
            response.set_header(
                'Allow',
                ','.join(self._verbs))
        return None

    def install(self):
        self.app.route(
            self._rules, callback=self,
            method=['OPTIONS', 'GET', 'PUT', 'PATCH', 'POST', 'DELETE'])

    @staticmethod
    def try_mapper_call(f, callback=None, **kw):
        try:
            return f(**kw)
        except dbus.exceptions.DBusException, e:
            if e.get_dbus_name() == \
                    'org.freedesktop.DBus.Error.ObjectPathInUse':
                abort(503, str(e))
            if e.get_dbus_name() != obmc.mapper.MAPPER_NOT_FOUND:
                raise
            if callback is None:
                def callback(e, **kw):
                    abort(404, str(e))

            callback(e, **kw)

    @staticmethod
    def try_properties_interface(f, *a):
        try:
            return f(*a)
        except dbus.exceptions.DBusException, e:
            if DBUS_UNKNOWN_INTERFACE in e.get_dbus_message():
                # interface doesn't have any properties
                return None
            if DBUS_UNKNOWN_INTERFACE_ERROR in e.get_dbus_name():
                # interface doesn't have any properties
                return None
            if DBUS_UNKNOWN_METHOD == e.get_dbus_name():
                # properties interface not implemented at all
                return None
            raise


class DirectoryHandler(RouteHandler):
    verbs = 'GET'
    rules = '<path:path>/'

    def __init__(self, app, bus):
        super(DirectoryHandler, self).__init__(
            app, bus, self.verbs, self.rules)

    def find(self, path='/'):
        return self.try_mapper_call(
            self.mapper.get_subtree_paths, path=path, depth=1)

    def setup(self, path='/'):
        request.route_data['map'] = self.find(path)

    def do_get(self, path='/'):
        return request.route_data['map']


class ListNamesHandler(RouteHandler):
    verbs = 'GET'
    rules = ['/list', '<path:path>/list']

    def __init__(self, app, bus):
        super(ListNamesHandler, self).__init__(
            app, bus, self.verbs, self.rules)

    def find(self, path='/'):
        return self.try_mapper_call(
            self.mapper.get_subtree, path=path).keys()

    def setup(self, path='/'):
        request.route_data['map'] = self.find(path)

    def do_get(self, path='/'):
        return request.route_data['map']


class ListHandler(RouteHandler):
    verbs = 'GET'
    rules = ['/enumerate', '<path:path>/enumerate']

    def __init__(self, app, bus):
        super(ListHandler, self).__init__(
            app, bus, self.verbs, self.rules)

    def find(self, path='/'):
        return self.try_mapper_call(
            self.mapper.get_subtree, path=path)

    def setup(self, path='/'):
        request.route_data['map'] = self.find(path)

    def do_get(self, path='/'):
        return {x: y for x, y in self.mapper.enumerate_subtree(
                path,
                mapper_data=request.route_data['map']).dataitems()}


class MethodHandler(RouteHandler):
    verbs = 'POST'
    rules = '<path:path>/action/<method>'
    request_type = list
    content_type = 'application/json'

    def __init__(self, app, bus):
        super(MethodHandler, self).__init__(
            app, bus, self.verbs, self.rules, self.content_type)
        self.service = ''
        self.interface = ''

    def find(self, path, method):
        busses = self.try_mapper_call(
            self.mapper.get_object, path=path)
        for items in busses.iteritems():
            m = self.find_method_on_bus(path, method, *items)
            if m:
                return m

        abort(404, _4034_msg % ('method', 'found', method))

    def setup(self, path, method):
        request.route_data['method'] = self.find(path, method)

    def do_post(self, path, method):
        try:
            if request.parameter_list:
                return request.route_data['method'](*request.parameter_list)
            else:
                return request.route_data['method']()

        except dbus.exceptions.DBusException, e:
            paramlist = []
            if e.get_dbus_name() == DBUS_INVALID_ARGS:

                signature_list = get_method_signature(self.bus, self.service,
                                                      path, self.interface,
                                                      method)
                if not signature_list:
                    abort(400, "Failed to get method signature: %s" % str(e))
                if len(signature_list) != len(request.parameter_list):
                    abort(400, "Invalid number of args")
                converted_value = None
                try:
                    for index, expected_type in enumerate(signature_list):
                        value = request.parameter_list[index]
                        converted_value = convert_type(expected_type, value)
                        paramlist.append(converted_value)
                    request.parameter_list = paramlist
                    self.do_post(path, method)
                    return
                except Exception as ex:
                    abort(400, "Failed to convert the types")
                abort(400, str(e))

            if e.get_dbus_name() == DBUS_TYPE_ERROR:
                abort(400, str(e))
            raise

    @staticmethod
    def find_method_in_interface(method, obj, interface, methods):
        if methods is None:
            return None

        method = obmc.utils.misc.find_case_insensitive(method, methods.keys())
        if method is not None:
            iface = dbus.Interface(obj, interface)
            return iface.get_dbus_method(method)

    def find_method_on_bus(self, path, method, bus, interfaces):
        obj = self.bus.get_object(bus, path, introspect=False)
        iface = dbus.Interface(obj, dbus.INTROSPECTABLE_IFACE)
        data = iface.Introspect()
        parser = IntrospectionNodeParser(
            ElementTree.fromstring(data),
            intf_match=obmc.utils.misc.ListMatch(interfaces))
        for x, y in parser.get_interfaces().iteritems():
            m = self.find_method_in_interface(
                method, obj, x, y.get('method'))
            if m:
                self.service = bus
                self.interface = x
                return m


class PropertyHandler(RouteHandler):
    verbs = ['PUT', 'GET']
    rules = '<path:path>/attr/<prop>'
    content_type = 'application/json'

    def __init__(self, app, bus):
        super(PropertyHandler, self).__init__(
            app, bus, self.verbs, self.rules, self.content_type)

    def find(self, path, prop):
        self.app.instance_handler.setup(path)
        obj = self.app.instance_handler.do_get(path)
        real_name = obmc.utils.misc.find_case_insensitive(
            prop, obj.keys())

        if not real_name:
            if request.method == 'PUT':
                abort(403, _4034_msg % ('property', 'created', prop))
            else:
                abort(404, _4034_msg % ('property', 'found', prop))
        return real_name, {path: obj}

    def setup(self, path, prop):
        name, obj = self.find(path, prop)
        request.route_data['obj'] = obj
        request.route_data['name'] = name

    def do_get(self, path, prop):
        name = request.route_data['name']
        return request.route_data['obj'][path][name]

    def do_put(self, path, prop, value=None):
        if value is None:
            value = request.parameter_list

        prop, iface, properties_iface = self.get_host_interface(
            path, prop, request.route_data['map'][path])
        try:
            properties_iface.Set(iface, prop, value)
        except ValueError, e:
            abort(400, str(e))
        except dbus.exceptions.DBusException, e:
            if e.get_dbus_name() == DBUS_INVALID_ARGS:
                bus_name = properties_iface.bus_name
                expected_type = get_type_signature_by_introspection(self.bus,
                                                                    bus_name,
                                                                    path,
                                                                    prop)
                if not expected_type:
                    abort(403, "Failed to get expected type: %s" % str(e))
                converted_value = None
                try:
                    converted_value = convert_type(expected_type, value)
                    self.do_put(path, prop, converted_value)
                    return
                except Exception as ex:
                    abort(403, "Failed to convert %s to type %s" %
                          (value, expected_type))
                abort(403, str(e))
            raise

    def get_host_interface(self, path, prop, bus_info):
        for bus, interfaces in bus_info.iteritems():
            obj = self.bus.get_object(bus, path, introspect=True)
            properties_iface = dbus.Interface(
                obj, dbus_interface=dbus.PROPERTIES_IFACE)

            info = self.get_host_interface_on_bus(
                path, prop, properties_iface, bus, interfaces)
            if info is not None:
                prop, iface = info
                return prop, iface, properties_iface

    def get_host_interface_on_bus(self, path, prop, iface, bus, interfaces):
        for i in interfaces:
            properties = self.try_properties_interface(iface.GetAll, i)
            if not properties:
                continue
            match = obmc.utils.misc.find_case_insensitive(
                prop, properties.keys())
            if match is None:
                continue
            prop = match
            return prop, i


class SchemaHandler(RouteHandler):
    verbs = ['GET']
    rules = '<path:path>/schema'

    def __init__(self, app, bus):
        super(SchemaHandler, self).__init__(
            app, bus, self.verbs, self.rules)

    def find(self, path):
        return self.try_mapper_call(
            self.mapper.get_object,
            path=path)

    def setup(self, path):
        request.route_data['map'] = self.find(path)

    def do_get(self, path):
        schema = {}
        for x in request.route_data['map'].iterkeys():
            obj = self.bus.get_object(x, path, introspect=False)
            iface = dbus.Interface(obj, dbus.INTROSPECTABLE_IFACE)
            data = iface.Introspect()
            parser = IntrospectionNodeParser(
                ElementTree.fromstring(data))
            for x, y in parser.get_interfaces().iteritems():
                schema[x] = y

        return schema


class InstanceHandler(RouteHandler):
    verbs = ['GET', 'PUT', 'DELETE']
    rules = '<path:path>'
    request_type = dict

    def __init__(self, app, bus):
        super(InstanceHandler, self).__init__(
            app, bus, self.verbs, self.rules)

    def find(self, path, callback=None):
        return {path: self.try_mapper_call(
            self.mapper.get_object,
            callback,
            path=path)}

    def setup(self, path):
        callback = None
        if request.method == 'PUT':
            def callback(e, **kw):
                abort(403, _4034_msg % ('resource', 'created', path))

        if request.route_data.get('map') is None:
            request.route_data['map'] = self.find(path, callback)

    def do_get(self, path):
        return self.mapper.enumerate_object(
            path,
            mapper_data=request.route_data['map'])

    def do_put(self, path):
        # make sure all properties exist in the request
        obj = set(self.do_get(path).keys())
        req = set(request.parameter_list.keys())

        diff = list(obj.difference(req))
        if diff:
            abort(403, _4034_msg % (
                'resource', 'removed', '%s/attr/%s' % (path, diff[0])))

        diff = list(req.difference(obj))
        if diff:
            abort(403, _4034_msg % (
                'resource', 'created', '%s/attr/%s' % (path, diff[0])))

        for p, v in request.parameter_list.iteritems():
            self.app.property_handler.do_put(
                path, p, v)

    def do_delete(self, path):
        for bus_info in request.route_data['map'][path].iteritems():
            if self.bus_missing_delete(path, *bus_info):
                abort(403, _4034_msg % ('resource', 'removed', path))

        for bus in request.route_data['map'][path].iterkeys():
            self.delete_on_bus(path, bus)

    def bus_missing_delete(self, path, bus, interfaces):
        return DELETE_IFACE not in interfaces

    def delete_on_bus(self, path, bus):
        obj = self.bus.get_object(bus, path, introspect=False)
        delete_iface = dbus.Interface(
            obj, dbus_interface=DELETE_IFACE)
        delete_iface.Delete()


class SessionHandler(MethodHandler):
    ''' Handles the /login and /logout routes, manages
    server side session store and session cookies.  '''

    rules = ['/login', '/logout']
    login_str = "User '%s' logged %s"
    bad_passwd_str = "Invalid username or password"
    no_user_str = "No user logged in"
    bad_json_str = "Expecting request format { 'data': " \
        "[<username>, <password>] }, got '%s'"
    _require_auth = None
    MAX_SESSIONS = 16

    def __init__(self, app, bus):
        super(SessionHandler, self).__init__(
            app, bus)
        self.hmac_key = os.urandom(128)
        self.session_store = []

    @staticmethod
    def authenticate(username, clear):
        try:
            encoded = spwd.getspnam(username)[1]
            return encoded == crypt.crypt(clear, encoded)
        except KeyError:
            return False

    def invalidate_session(self, session):
        try:
            self.session_store.remove(session)
        except ValueError:
            pass

    def new_session(self):
        sid = os.urandom(32)
        if self.MAX_SESSIONS <= len(self.session_store):
            self.session_store.pop()
        self.session_store.insert(0, {'sid': sid})

        return self.session_store[0]

    def get_session(self, sid):
        sids = [x['sid'] for x in self.session_store]
        try:
            return self.session_store[sids.index(sid)]
        except ValueError:
            return None

    def get_session_from_cookie(self):
        return self.get_session(
            request.get_cookie(
                'sid', secret=self.hmac_key))

    def do_post(self, **kw):
        if request.path == '/login':
            return self.do_login(**kw)
        else:
            return self.do_logout(**kw)

    def do_logout(self, **kw):
        session = self.get_session_from_cookie()
        if session is not None:
            user = session['user']
            self.invalidate_session(session)
            response.delete_cookie('sid')
            return self.login_str % (user, 'out')

        return self.no_user_str

    def do_login(self, **kw):
        session = self.get_session_from_cookie()
        if session is not None:
            return self.login_str % (session['user'], 'in')

        if len(request.parameter_list) != 2:
            abort(400, self.bad_json_str % (request.json))

        if not self.authenticate(*request.parameter_list):
            abort(401, self.bad_passwd_str)

        user = request.parameter_list[0]
        session = self.new_session()
        session['user'] = user
        response.set_cookie(
            'sid', session['sid'], secret=self.hmac_key,
            secure=True,
            httponly=True)
        return self.login_str % (user, 'in')

    def find(self, **kw):
        pass

    def setup(self, **kw):
        pass


class ImageUploadUtils:
    ''' Provides common utils for image upload. '''

    file_loc = '/tmp/images'
    file_prefix = 'img'
    file_suffix = ''

    @classmethod
    def do_upload(cls, filename=''):
        if not os.path.exists(cls.file_loc):
            os.makedirs(cls.file_loc)
        if not filename:
            handle, filename = tempfile.mkstemp(cls.file_suffix,
                                                cls.file_prefix, cls.file_loc)
        else:
            filename = os.path.join(cls.file_loc, filename)
            handle = os.open(filename, os.O_WRONLY | os.O_CREAT)
        try:
            file_contents = request.body.read()
            request.body.close()
            os.write(handle, file_contents)
        except (IOError, ValueError), e:
            abort(400, str(e))
        except:
            abort(400, "Unexpected Error")
        finally:
            os.close(handle)


class ImagePostHandler(RouteHandler):
    ''' Handles the /upload/image route. '''

    verbs = ['POST']
    rules = ['/upload/image']
    content_type = 'application/octet-stream'

    def __init__(self, app, bus):
        super(ImagePostHandler, self).__init__(
            app, bus, self.verbs, self.rules, self.content_type)

    def do_post(self, filename=''):
        ImageUploadUtils.do_upload()

    def find(self, **kw):
        pass

    def setup(self, **kw):
        pass


class ImagePutHandler(RouteHandler):
    ''' Handles the /upload/image/<filename> route. '''

    verbs = ['PUT']
    rules = ['/upload/image/<filename>']
    content_type = 'application/octet-stream'

    def __init__(self, app, bus):
        super(ImagePutHandler, self).__init__(
            app, bus, self.verbs, self.rules, self.content_type)

    def do_put(self, filename=''):
        ImageUploadUtils.do_upload(filename)

    def find(self, **kw):
        pass

    def setup(self, **kw):
        pass


class DownloadDumpHandler(RouteHandler):
    ''' Handles the /download/dump route. '''

    verbs = 'GET'
    rules = ['/download/dump/<dumpid>']
    content_type = 'application/octet-stream'
    dump_loc = '/var/lib/phosphor-debug-collector/dumps'
    suppress_json_resp = True

    def __init__(self, app, bus):
        super(DownloadDumpHandler, self).__init__(
            app, bus, self.verbs, self.rules, self.content_type)

    def do_get(self, dumpid):
        return self.do_download(dumpid)

    def find(self, **kw):
        pass

    def setup(self, **kw):
        pass

    def do_download(self, dumpid):
        dump_loc = os.path.join(self.dump_loc, dumpid)
        if not os.path.exists(dump_loc):
            abort(404, "Path not found")

        files = os.listdir(dump_loc)
        num_files = len(files)
        if num_files == 0:
            abort(404, "Dump not found")

        return static_file(os.path.basename(files[0]), root=dump_loc,
                           download=True, mimetype=self.content_type)


class AuthorizationPlugin(object):
    ''' Invokes an optional list of authorization callbacks. '''

    name = 'authorization'
    api = 2

    class Compose:
        def __init__(self, validators, callback, session_mgr):
            self.validators = validators
            self.callback = callback
            self.session_mgr = session_mgr

        def __call__(self, *a, **kw):
            sid = request.get_cookie('sid', secret=self.session_mgr.hmac_key)
            session = self.session_mgr.get_session(sid)
            if request.method != 'OPTIONS':
                for x in self.validators:
                    x(session, *a, **kw)

            return self.callback(*a, **kw)

    def apply(self, callback, route):
        undecorated = route.get_undecorated_callback()
        if not isinstance(undecorated, RouteHandler):
            return callback

        auth_types = getattr(
            undecorated, '_require_auth', None)
        if not auth_types:
            return callback

        return self.Compose(
            auth_types, callback, undecorated.app.session_handler)


class CorsPlugin(object):
    ''' Add CORS headers. '''

    name = 'cors'
    api = 2

    @staticmethod
    def process_origin():
        origin = request.headers.get('Origin')
        if origin:
            response.add_header('Access-Control-Allow-Origin', origin)
            response.add_header(
                'Access-Control-Allow-Credentials', 'true')

    @staticmethod
    def process_method_and_headers(verbs):
        method = request.headers.get('Access-Control-Request-Method')
        headers = request.headers.get('Access-Control-Request-Headers')
        if headers:
            headers = [x.lower() for x in headers.split(',')]

        if method in verbs \
                and headers == ['content-type']:
            response.add_header('Access-Control-Allow-Methods', method)
            response.add_header(
                'Access-Control-Allow-Headers', 'Content-Type')

    def __init__(self, app):
        app.install_error_callback(self.error_callback)

    def apply(self, callback, route):
        undecorated = route.get_undecorated_callback()
        if not isinstance(undecorated, RouteHandler):
            return callback

        if not getattr(undecorated, '_enable_cors', None):
            return callback

        def wrap(*a, **kw):
            self.process_origin()
            self.process_method_and_headers(undecorated._verbs)
            return callback(*a, **kw)

        return wrap

    def error_callback(self, **kw):
        self.process_origin()


class JsonApiRequestPlugin(object):
    ''' Ensures request content satisfies the OpenBMC json api format. '''
    name = 'json_api_request'
    api = 2

    error_str = "Expecting request format { 'data': <value> }, got '%s'"
    type_error_str = "Unsupported Content-Type: '%s'"
    json_type = "application/json"
    request_methods = ['PUT', 'POST', 'PATCH']

    @staticmethod
    def content_expected():
        return request.method in JsonApiRequestPlugin.request_methods

    def validate_request(self):
        if request.content_length > 0 and \
                request.content_type != self.json_type:
            abort(415, self.type_error_str % request.content_type)

        try:
            request.parameter_list = request.json.get('data')
        except ValueError, e:
            abort(400, str(e))
        except (AttributeError, KeyError, TypeError):
            abort(400, self.error_str % request.json)

    def apply(self, callback, route):
        content_type = getattr(
            route.get_undecorated_callback(), '_content_type', None)
        if self.json_type != content_type:
            return callback

        verbs = getattr(
            route.get_undecorated_callback(), '_verbs', None)
        if verbs is None:
            return callback

        if not set(self.request_methods).intersection(verbs):
            return callback

        def wrap(*a, **kw):
            if self.content_expected():
                self.validate_request()
            return callback(*a, **kw)

        return wrap


class JsonApiRequestTypePlugin(object):
    ''' Ensures request content type satisfies the OpenBMC json api format. '''
    name = 'json_api_method_request'
    api = 2

    error_str = "Expecting request format { 'data': %s }, got '%s'"
    json_type = "application/json"

    def apply(self, callback, route):
        content_type = getattr(
            route.get_undecorated_callback(), '_content_type', None)
        if self.json_type != content_type:
            return callback

        request_type = getattr(
            route.get_undecorated_callback(), 'request_type', None)
        if request_type is None:
            return callback

        def validate_request():
            if not isinstance(request.parameter_list, request_type):
                abort(400, self.error_str % (str(request_type), request.json))

        def wrap(*a, **kw):
            if JsonApiRequestPlugin.content_expected():
                validate_request()
            return callback(*a, **kw)

        return wrap


class JsonErrorsPlugin(JSONPlugin):
    ''' Extend the Bottle JSONPlugin such that it also encodes error
        responses. '''

    def __init__(self, app, **kw):
        super(JsonErrorsPlugin, self).__init__(**kw)
        self.json_opts = {
            x: y for x, y in kw.iteritems()
            if x in ['indent', 'sort_keys']}
        app.install_error_callback(self.error_callback)

    def error_callback(self, response_object, response_body, **kw):
        response_body['body'] = json.dumps(response_object, **self.json_opts)
        response.content_type = 'application/json'


class JsonApiResponsePlugin(object):
    ''' Emits responses in the OpenBMC json api format. '''
    name = 'json_api_response'
    api = 2

    @staticmethod
    def has_body():
        return request.method not in ['OPTIONS']

    def __init__(self, app):
        app.install_error_callback(self.error_callback)

    def apply(self, callback, route):
        skip = getattr(
            route.get_undecorated_callback(), 'suppress_json_resp', None)
        if skip:
            return callback

        def wrap(*a, **kw):
            data = callback(*a, **kw)
            if self.has_body():
                resp = {'data': data}
                resp['status'] = 'ok'
                resp['message'] = response.status_line
                return resp
        return wrap

    def error_callback(self, error, response_object, **kw):
        response_object['message'] = error.status_line
        response_object['status'] = 'error'
        response_object.setdefault('data', {})['description'] = str(error.body)
        if error.status_code == 500:
            response_object['data']['exception'] = repr(error.exception)
            response_object['data']['traceback'] = error.traceback.splitlines()


class JsonpPlugin(object):
    ''' Json javascript wrapper. '''
    name = 'jsonp'
    api = 2

    def __init__(self, app, **kw):
        app.install_error_callback(self.error_callback)

    @staticmethod
    def to_jsonp(json):
        jwrapper = request.query.callback or None
        if(jwrapper):
            response.set_header('Content-Type', 'application/javascript')
            json = jwrapper + '(' + json + ');'
        return json

    def apply(self, callback, route):
        def wrap(*a, **kw):
            return self.to_jsonp(callback(*a, **kw))
        return wrap

    def error_callback(self, response_body, **kw):
        response_body['body'] = self.to_jsonp(response_body['body'])


class ContentCheckerPlugin(object):
    ''' Ensures that a route is associated with the expected content-type
        header. '''
    name = 'content_checker'
    api = 2

    class Checker:
        def __init__(self, type, callback):
            self.expected_type = type
            self.callback = callback
            self.error_str = "Expecting content type '%s', got '%s'"

        def __call__(self, *a, **kw):
            if request.method in ['PUT', 'POST', 'PATCH'] and \
                    self.expected_type and \
                    self.expected_type != request.content_type:
                abort(415, self.error_str % (self.expected_type,
                      request.content_type))

            return self.callback(*a, **kw)

    def apply(self, callback, route):
        content_type = getattr(
            route.get_undecorated_callback(), '_content_type', None)

        return self.Checker(content_type, callback)

class CheckURLPlugin(object):
    ''' Ensures that anything read and write using the old org.openbmc would not
         be allowed in or out via REST. '''
    name = 'url_checker'
    api = 2

    class Checker:
        def __init__(self, callback):
            self.callback = callback
            self.error_str = "org.freedesktop.DBus.Error.FileNotFound: path or \
                              object not found: '%s'"

        def __call__(self, *a, **kw):
            if not request.urlparts.path.find("/org/openbmc"):
                abort(404, self.error_str % (request.urlparts.path))
            return self.callback(*a, **kw)

    def apply(self, callback, route):

        return self.Checker(callback)


class App(Bottle):
    def __init__(self):
        super(App, self).__init__(autojson=False)
        self.bus = dbus.SystemBus()
        self.mapper = obmc.mapper.Mapper(self.bus)
        self.error_callbacks = []

        self.install_hooks()
        self.install_plugins()
        self.create_handlers()
        self.install_handlers()

    def install_plugins(self):
        # install json api plugins
        json_kw = {'indent': 2, 'sort_keys': True}
        self.install(AuthorizationPlugin())
        self.install(CorsPlugin(self))
        self.install(ContentCheckerPlugin())
        self.install(JsonpPlugin(self, **json_kw))
        self.install(JsonErrorsPlugin(self, **json_kw))
        self.install(JsonApiResponsePlugin(self))
        self.install(JsonApiRequestPlugin())
        self.install(JsonApiRequestTypePlugin())
        self.install(CheckURLPlugin())

    def install_hooks(self):
        self.error_handler_type = type(self.default_error_handler)
        self.original_error_handler = self.default_error_handler
        self.default_error_handler = self.error_handler_type(
            self.custom_error_handler, self, Bottle)

        self.real_router_match = self.router.match
        self.router.match = self.custom_router_match
        self.add_hook('before_request', self.strip_extra_slashes)

    def create_handlers(self):
        # create route handlers
        self.session_handler = SessionHandler(self, self.bus)
        self.directory_handler = DirectoryHandler(self, self.bus)
        self.list_names_handler = ListNamesHandler(self, self.bus)
        self.list_handler = ListHandler(self, self.bus)
        self.method_handler = MethodHandler(self, self.bus)
        self.property_handler = PropertyHandler(self, self.bus)
        self.schema_handler = SchemaHandler(self, self.bus)
        self.image_upload_post_handler = ImagePostHandler(self, self.bus)
        self.image_upload_put_handler = ImagePutHandler(self, self.bus)
        self.download_dump_get_handler = DownloadDumpHandler(self, self.bus)
        self.instance_handler = InstanceHandler(self, self.bus)

    def install_handlers(self):
        self.session_handler.install()
        self.directory_handler.install()
        self.list_names_handler.install()
        self.list_handler.install()
        self.method_handler.install()
        self.property_handler.install()
        self.schema_handler.install()
        self.image_upload_post_handler.install()
        self.image_upload_put_handler.install()
        self.download_dump_get_handler.install()
        # this has to come last, since it matches everything
        self.instance_handler.install()

    def install_error_callback(self, callback):
        self.error_callbacks.insert(0, callback)

    def custom_router_match(self, environ):
        ''' The built-in Bottle algorithm for figuring out if a 404 or 405 is
            needed doesn't work for us since the instance rules match
            everything. This monkey-patch lets the route handler figure
            out which response is needed.  This could be accomplished
            with a hook but that would require calling the router match
            function twice.
        '''
        route, args = self.real_router_match(environ)
        if isinstance(route.callback, RouteHandler):
            route.callback._setup(**args)

        return route, args

    def custom_error_handler(self, res, error):
        ''' Allow plugins to modify error reponses too via this custom
            error handler. '''

        response_object = {}
        response_body = {}
        for x in self.error_callbacks:
            x(error=error,
                response_object=response_object,
                response_body=response_body)

        return response_body.get('body', "")

    @staticmethod
    def strip_extra_slashes():
        path = request.environ['PATH_INFO']
        trailing = ("", "/")[path[-1] == '/']
        parts = filter(bool, path.split('/'))
        request.environ['PATH_INFO'] = '/' + '/'.join(parts) + trailing
