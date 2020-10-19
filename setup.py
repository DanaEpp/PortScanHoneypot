#!/usr/bin/env python
from setuptools import setup

setup(
      name='PortScanHoneypot',
      version='1.0',
      description='A python script to help blue teams detect bad actors who may be port scanning the network, and allow red teams to practice honeypot evasion. #blueteam #redteam',
      long_description=open('README.md').read(),
      author='Dana Epp',
      author_email='dana@vulscan.com',
      url='https://github.com/danaepp/portscanhoneypot',
      license='MIT',
      packages=['portscanhoneypot'],
      install_requires=[ 'requests', 'yaml', 'validators', 'pymsteams' ]
     )