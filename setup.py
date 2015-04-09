import os
from setuptools import setup
from setuptools import find_packages

def get_docs():
    result = []
    in_docs = False
    f = open(os.path.join(os.path.dirname(__file__), 'facebook_utils/facebook_utils.py'))
    try:
        for line in f:
            if in_docs:
                if line.lstrip().startswith(':copyright:'):
                    break
                result.append(line[4:].rstrip())
            elif line.strip() == 'r"""':
                in_docs = True
    finally:
        f.close()
    return '\n'.join(result)

setup(
    name='facebook_utils',
    author='Jonathan Vanasco',
    author_email='jonathan@findmeon.com',
    version='0.30.2',
    url='http://github.com/jvanasco/facebook_utils',
    description='simple utilites for facebook integration.',
    long_description=get_docs(),
    license="BSD",
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'requests>=1.2'
    ],
    test_suite='tests',
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python',
        "Framework :: Pyramid",
        "Intended Audience :: Developers",
    ]
)
