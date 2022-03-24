# Release process setup see:
# https://github.com/pypa/twine
#
# Upgrade twine
#     python3 -m pip install --user --upgrade twine
#
# Run this to build the `dist/PACKAGE_NAME-xxx.tar.gz` file
#     rm -rf ./dist && python3 setup.py sdist
#
# Check dist/*
#     python3 -m twine check dist/*
#
# Run this to build & upload it to `pypi`, type your account name when prompted.
#     python3 -m twine upload dist/*
#
# In one command line:
#     rm -rf ./dist && python3 setup.py sdist bdist_wheel && python3 -m twine check dist/*
#     rm -rf ./dist && python3 setup.py sdist bdist_wheel && python3 -m twine upload dist/*
#

from setuptools import setup, find_packages

# Usage: python setup.py sdist bdist_wheel

links = []  # for repo urls (dependency_links)

with open("requirements.txt") as fp:
    install_requires = fp.read()

DESCRIPTION = "Python library for Passbolt, an open-source manager for teams"
VERSION = "0.0.3"

with open("README.md", "r") as fh:
    LONG_DESCRIPTION = fh.read()

setup(
    name="py-passbolt",
    version=VERSION,
    author="Jean-Christophe Vassort",
    author_email="anatomicjc@open-web.fr",
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    url="https://gitlab.com/AnatomicJC/py-passbolt",
    license="WTFPL",
    packages=find_packages(),
    platforms=["any"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    install_requires=install_requires,
    dependency_links=links,
    include_package_data=True,
)
