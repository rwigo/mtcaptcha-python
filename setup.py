from setuptools import setup, find_packages
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='mtcaptcha',
    version='1.0.0',
    description='MTCaptcha Direct Token Decryption for python 3',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/rwigo/mtcaptcha-python',
    author='Nicolas Cenerario',
    author_email='nicolas@rwigo.com',
    python_requires='>=3.5',
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
        "Operating System :: OS Independent",
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        "Programming Language :: Python :: 3",
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    keywords='mtcaptcha v1 decryption serverside',
    package_dir={'': 'src'},
    packages=find_packages(where='src'),
    install_requires=['pycryptodome'],
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],
    extras_require={
        'dev': ['check-manifest'],
    },
    project_urls={
        'Company': 'https://www.rwigo.com/',
        'Source': 'https://github.com/rwigo/mtcaptcha-python',
    },
)
