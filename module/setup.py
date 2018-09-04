from distutils.core import setup

setup(
    name='phosphor-rest-dbus',
    version='1.0',
    py_modules=['obmc.wsgi.apps.rest_dbus'],
    data_files=[('/etc/pam.d/',['obmc/wsgi/apps/restserver_ldap','obmc/wsgi/apps/restserver'])],
    )
