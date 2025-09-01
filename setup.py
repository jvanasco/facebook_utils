import os
import re
from setuptools import setup
from setuptools import find_packages

HERE = os.path.abspath(os.path.dirname(__file__))

# store version in the init.py
with open(os.path.join(HERE, "src", "facebook_utils", "__init__.py")) as v_file:
    VERSION = re.compile(r'.*__VERSION__ = "(.*?)"', re.S).match(v_file.read()).group(1)


long_description = description = (
    "Simple utilites for Facebook integration with your website."
)
with open(os.path.join(HERE, "README.md")) as fp:
    long_description = fp.read()

install_requires = [
    "requests>=1.2",
    "typing_extensions",
]
tests_require = [
    "mypy",
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
    packages=find_packages(
        where="src",
    ),
    package_dir={"": "src"},
    package_data={"facebook_utils": ["py.typed"]},
    include_package_data=True,
    zip_safe=False,
    install_requires=install_requires,
    tests_require=tests_require,
    extras_require={
        "testing": testing_extras,
    },
    test_suite="tests",
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Framework :: Pyramid",
        "Intended Audience :: Developers",
    ],
)
