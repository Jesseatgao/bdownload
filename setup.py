from setuptools import setup, find_packages

with open('VERSION', mode='r') as fd:
    version = fd.read().strip()
    
with open('README.md', mode='r') as fd:
    long_description = fd.read()
    
# Extends the Setuptools `clean` command
with open('third_parties/setupext_janitor/janitor.py') as setupext_janitor:
    exec(setupext_janitor.read())

# try:
#     from setupext_janitor import janitor
#     CleanCommand = janitor.CleanCommand
# except ImportError:
#     CleanCommand = None

cmd_classes = {}
if CleanCommand is not None:
    cmd_classes['clean'] = CleanCommand

setup(
    name='bdownload',
    version=version,
    package_dir={'': 'src'},
    packages=find_packages('src'),
    include_package_data=True,
    zip_safe=False,
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*',
    install_requires=[
        'requests[socks]',
        'requests',
        'clint',
        'futures; python_version == "2.7"'
    ],
    setup_requires=[],
    cmdclass=cmd_classes,
    entry_points={
        'console_scripts': [
            'bdownload = bdownload.cli:main',
        ],
        'distutils.commands': [
            ' clean = CleanCommand'
        ]
    },
    url='https://github.com/Jesseatgao/bdownload',
    license='MIT License',
    author='Jesse',
    author_email='changxigao@gmail.com',
    description='A multi-threaded aria2-like batch file downloading library for Python',
    long_description=long_description,
    long_description_content_type='text/markdown',
    classifiers=[
        'Intended Audience :: Developers',
        'Environment :: Console',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent'
    ]
)
