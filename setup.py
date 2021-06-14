import os
import sys
from shutil import rmtree

from setuptools import Command, find_packages, setup

# Package meta-data.
NAME = "dlms-cosem"
DESCRIPTION = "A Python library for DLMS/COSEM"
URL = "https://github.com/pwitab/dlms-cosem"
PROJECT_URLS = {
    "Documentation": "https://www.dlms.dev/",
    "Bug Tracker": "https://github.com/pwitab/dlms-cosem/issues",
    "Source Code": "https://github.com/pwitab/dlms-cosem",
}
EMAIL = "henrik@pwit.se"
AUTHOR = "Henrik Palmlund Wahlgren @ Palmlund Wahlgren Innovative Technology AB"
REQUIRES_PYTHON = "~=3.6"
VERSION = "21.3.1"

# What packages are required for this module to be executed?
REQUIRED = [
    "attrs==20.3.0",
    "pyserial==3.5",
    "cryptography==3.3.2",
    "asn1crypto==0.24.0",
    "python-dateutil==2.8.1",
    "typing-extensions==3.7.4.3",
]

DOC_PACKAGES = ["mkdocs", "mkdocs-material"]
TEST_PACKAGES = ["pytest", "pytest-cov", "pytest-sugar"]
DEV_PACKAGES = ["pre-commit"] + DOC_PACKAGES + TEST_PACKAGES

EXTRAS = {
    "docs": DOC_PACKAGES,
    "test": TEST_PACKAGES,
    "dev": DEV_PACKAGES,
}

CLASSIFIERS = [
    "Intended Audience :: Developers",
    "Natural Language :: English",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.6",
    "Programming Language :: Python :: 3.7",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: Implementation :: CPython",
    "Topic :: Software Development :: Libraries :: Python Modules",
]

here = os.path.abspath(os.path.dirname(__file__))


class UploadCommand(Command):
    """Support setup.py upload."""

    description = "Build and publish the package."
    user_options = []

    @staticmethod
    def status(s):
        """Prints things in bold."""
        print("\033[1m{0}\033[0m".format(s))

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        try:
            self.status("Removing previous builds…")
            rmtree(os.path.join(here, "dist"))
        except OSError:
            pass

        self.status("Building Source and Wheel (universal) distribution…")
        os.system("{0} setup.py sdist bdist_wheel".format(sys.executable))

        self.status("Uploading the package to PyPI via Twine…")
        os.system("twine upload dist/*")

        self.status("Pushing git tags…")
        # os.system('git tag v{0}'.format(about['__version__']))
        os.system("git push --tags")

        sys.exit()


with open("README.md") as readme_file:
    readme = readme_file.read()

with open("HISTORY.md") as history_file:
    history = history_file.read()

setup(
    name=NAME,
    version=VERSION,
    python_requires=REQUIRES_PYTHON,
    description=DESCRIPTION,
    long_description=readme + "\n\n" + history,
    long_description_content_type="text/markdown",
    author=AUTHOR,
    author_email=EMAIL,
    maintainer=AUTHOR,
    maintainer_email=EMAIL,
    url=URL,
    project_urls=PROJECT_URLS,
    packages=find_packages(exclude=("tests",)),
    entry_points={},
    install_requires=REQUIRED,
    extras_require=EXTRAS,
    include_package_data=True,
    license="MIT",
    zip_safe=False,
    keywords="AMR, Metering, smart meters, MDM, dlms, cosem",
    classifiers=CLASSIFIERS,
    # $ setup.py publish support.
    cmdclass={"upload": UploadCommand},
)
