import os
import re
from setuptools import setup
from setuptools import find_packages

# store version in the init.py
with open(
    os.path.join(os.path.dirname(__file__), "facebook_utils", "__init__.py")
) as v_file:
    VERSION = re.compile(r'.*__VERSION__ = "(.*?)"', re.S).match(v_file.read()).group(1)


long_description = (
    description
) = "Simple utilites for Facebook integration with your website."
try:
    here = os.path.abspath(os.path.dirname(__file__))
    long_description = open(os.path.join(here, "README.md")).read()
except:
    pass

install_requires = [
    "requests>=1.2",
    "six",
]
tests_require = [
    "pytest",
]
testing_extras = tests_require + []

setup(
    name="facebook_utils",
    author="Jonathan Vanasco",
    author_email="jonathan@findmeon.com",
    version=VERSION,
    url="http://github.com/jvanasco/facebook_utils",
    description=description,
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="BSD",
    keywords="facebook",
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=install_requires,
    tests_require=tests_require,
    extras_require={
        "testing": testing_extras,
    },
    test_suite="tests",
    classifiers=[
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Framework :: Pyramid",
        "Intended Audience :: Developers",
    ],
)
