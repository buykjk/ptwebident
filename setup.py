import setuptools

setuptools.setup(
    name="ptwebident",
    description="",
    version="0.1.0",
    author="Penterep",
    author_email="xvasic34@vutbr.cz",
    url="https://www.penterep.com/",
    licence="GPLv3",
    packages=setuptools.find_packages(),
    classifiers=[
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3.10",
        "Environment :: Console"
    ],
    python_requires = '>=3.10',
    install_requires=[
        'certifi~=2022.5.18.1',
        'charset~normalizer==2.0.12',
        'idna~=3.3',
        'numpy~=1.22.4',
        'pandas~=1.4.2',
        'ptlibs~=0.0.6',
        'python~dateutil==2.8.2',
        'python3~nmap==1.5.1',
        'pytz~=2022.1',
        'requests~=2.27.1',
        'simplejson~=3.17.6',
        'six~=1.16.0',
        'urllib3~=1.26.9'
    ],
    entry_points = {
        'console_scripts': [
            'ptwebident = ptwebident.ptwebident:main'
        ]
    },
    include_package_data= True
)
