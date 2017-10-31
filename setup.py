'setuptools setup script'

from setuptools import setup

setup(name='nsdpy',
      version='0.1',
      description='Netgear Switch Discovery Protocol command line tool',
      keywords='NSDP Netgear switch',
      url='http://github.com/nmedb/nsdpy',
      author='nmeid',
      author_email='nmeid@users.noreply.github.com',
      license='MIT',
      packages=['nsdpy'],
      install_requires=['construct>=2.8'],
      package_dir={'': 'lib'},
      scripts=['bin/nsdp'],
      zip_safe=False)
