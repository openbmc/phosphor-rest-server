from distutils.core import setup

setup(name='phosphor-rest',
      version='1.0',
      scripts=['phosphor-rest'],
      data_files=[('phosphor-rest', ['cert.pem'])],
      )
