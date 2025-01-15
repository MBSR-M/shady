#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from setuptools import setup, find_packages
import datetime


def version():
    try:
        with open('_version.py', 'r') as file_:
            for line in file_:
                if line.startswith('__version__'):
                    return line.split('=')[1].strip().strip("'")
            raise ValueError("Version string not found in file")
    except (FileNotFoundError, IndexError, ValueError) as e:
        print("Exception occurred:", e)
        return datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')


setup(
    name='wheel-name',
    version=version(),
    description='Description',
    author='Mubashir',
    author_email='mubashir.ai@outlook.com',
    include_package_data=True,
    package_dir={'': 'src'},
    package_data={'': ['*.json', '*.yml', '*.conf']},
    license='Other/Proprietary License',
    install_requires=[
        'kafka-python',
        'pymysql',
        'mysql-connector-python',
        'python-dateutil',
        'requests',
        'pytz',
        'openpyxl',
        'pandas',
        'cryptography',
    ],
    extras_require={
        'test': [
            'pytest',
            'pytest-cov',
        ]
    },
    entry_points={
        'console_scripts': [

        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: Other/Proprietary License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
