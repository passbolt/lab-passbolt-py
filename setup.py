# Release process setup see:
# https://github.com/pypa/twine
#
# Upgrade twine
#     python -m pip install --upgrade twine
#
# Run this to build the `dist/PACKAGE_NAME-xxx.tar.gz` file
#     rm -rf ./dist && python -m build
#
# Check dist/*
#     python -m twine check dist/*
#
# Run this to build & upload it to `pypi`, type your account name when prompted.
#     python -m twine upload dist/*
#
# In one command line:
#     rm -rf ./dist && python3 setup.py sdist bdist_wheel && python3 -m twine check dist/*
#     rm -rf ./dist && python3 setup.py sdist bdist_wheel && python3 -m twine upload dist/*
#

from setuptools import setup

# Usage: python setup.py sdist bdist_wheel

if __name__ == "__main__":
    setup()
