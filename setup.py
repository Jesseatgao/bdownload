from setuptools import setup, find_packages

with open('VERSION') as fd:
    version = fd.read().strip()

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
    python_requires='>=3.7',
    install_requires=['requests', 'requests[socks]', 'clint'],
    setup_requires=[],
    cmdclass=cmd_classes,
    entry_points={
        'distutils.commands': [
            ' clean = CleanCommand'
        ]
    },
    url='https://github.com/Jesseatgao/bdownload',
    license='MIT License',
    author='Jesse',
    author_email='changxigao@gmail.com',
    description='A multi-threaded aria2-like batch file downloading library for Python',
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ]
)
