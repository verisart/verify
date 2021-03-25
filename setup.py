import pathlib

from setuptools import find_packages, setup

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

setup(
    name='verisart-verify',
    packages=find_packages(include=['verisartverify']),
    version='0.1.0',
    description='Verisart Certificate Verification CLI',
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/verisart/verify",
    author_email="info@verisart.com",
    author='Verisart',
    install_requires=['requests', 'ecdsa>=0.16.1'],
    scripts=['verisart-verify'],
    include_package_data=True,
    license='LGPL',
)
