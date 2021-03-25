# Verisart Verify API

A CLI to allow independent verification of [Verisart](https://verisart.com) Certificate Archives.

Further reading: 

 * [Verifying a Verisart Certificate](https://www.notion.so/verisart/Verifying-a-Verisart-Certificate-8e1ba6292df04ca881b5662dd884e935)
 * [Verisart Archive File Format](https://www.notion.so/verisart/Verisart-Archive-File-Format-844e27eda4844915a4e47b6cb896244e)


## Requires

 - [Python 3](https://www.python.org/downloads/)
 - [Java 1.7+](https://www.java.com)

## Installation

    pip3 install verisart-verify

## Running

    verisart-verify verisart-archive-xxx.zip 

## Building

    rm -r build dist && python3 setup.py sdist bdist_wheel

## Deploying to Test PyPi 

    twine upload --repository-url https://test.pypi.org/legacy/ dist/*

## Deploying to Live PyPi

    twine upload dist/*

## OpenTimestamps Java Library

This package includes a compiled Java JAR file from the [OpenTimestamp Java client library](https://github.com/opentimestamps/java-opentimestamps).

TODO: We're using the JAR instead of the Python OTS library as the JAR can check the OTS timestamps using a public
      block explorer. We should figure out a way to do something similar with the Python library, or provide our
      own Bitcoin node for validation.
