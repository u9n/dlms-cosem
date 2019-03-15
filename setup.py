from setuptools import setup, find_packages, Command
import sys
import os
from shutil import rmtree

# Package meta-data.
NAME = 'dlms-cosem'
DESCRIPTION = 'A Python library for DLMS/COSEM'
URL = 'https://github.com/pwitab/dlms-cosem'
EMAIL = 'henrik@pwit.se'
AUTHOR = "Henrik Palmlund Wahlgren @ Palmlund Wahlgren Innovative Technology AB"
REQUIRES_PYTHON = '~=3.6'
# VERSION = None

# What packages are required for this module to be executed?
REQUIRED = [
    'amr-crypto',
    'attrs',
]

# What packages are optional?
EXTRAS = {
    # 'fancy feature': ['django'],
}

here = os.path.abspath(os.path.dirname(__file__))


class UploadCommand(Command):
    """Support setup.py upload."""

    description = 'Build and publish the package.'
    user_options = []

    @staticmethod
    def status(s):
        """Prints things in bold."""
        print('\033[1m{0}\033[0m'.format(s))

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        try:
            self.status('Removing previous builds…')
            rmtree(os.path.join(here, 'dist'))
        except OSError:
            pass

        self.status('Building Source and Wheel (universal) distribution…')
        os.system(
            '{0} setup.py sdist bdist_wheel'.format(sys.executable))

        self.status('Uploading the package to PyPI via Twine…')
        os.system('twine upload dist/*')

        self.status('Pushing git tags…')
        # os.system('git tag v{0}'.format(about['__version__']))
        os.system('git push --tags')

        sys.exit()


with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

setup(
    name=NAME,
    version='0.0.2',
    python_requires=REQUIRES_PYTHON,
    description=DESCRIPTION,
    long_description=readme + '\n\n' + history,
    author=AUTHOR,
    author_email=EMAIL,
    url=URL,
    packages=find_packages(exclude=('tests',)),
    entry_points={},
    install_requires=REQUIRED,
    extras_require=EXTRAS,
    include_package_data=True,
    license='BSD 3-Clause License',
    zip_safe=False,
    keywords='AMR, Metering, MDM, dlms, cosem',
    classifiers=[
    ],
    # $ setup.py publish support.
    cmdclass={
        'upload': UploadCommand,
    },

)
