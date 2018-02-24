from setuptools import setup

setup(
    name='dlms-cosem',
    version='0.0.1',
    description='A Python library for DLMS/COSEM',
    url='https://github.com/pwitab/dlms-cosem',
    author='Henrik Palmlund Wahlgren, '
           'Palmlund Wahlgren Innovative Technology AB',
    author_email='henrik@pwit.se',
    license='BSD 3-Clause License',
    packages=['dlms_cosem'],
    install_requires=['cryptography', ]

)
