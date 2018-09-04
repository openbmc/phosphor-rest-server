from distutils.core import setup

setup(
    name='phosphor-rest-dbus',
    version='1.0',
    py_modules=['obmc.wsgi.apps.rest_dbus'],
    data_files=[('/etc/pam.d/',['obmc/wsgi/apps/phosphor-rest-server-ldap','obmc/wsgi/apps/phosphor-rest-server-linux','obmc/wsgi/apps/phosphor-rest-server'])],
    )
