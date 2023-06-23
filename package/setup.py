from setuptools import setup, find_packages
import codecs
import os

here = os.path.abspath(os.path.dirname(__file__))

with codecs.open(os.path.join(here, "README.md"), encoding="utf-8") as fh:
    long_description = "\n" + fh.read()

VERSION = '0.1.1'
DESCRIPTION = 'Python Project for GPT-Vuln_analyzer'
LONG_DESCRIPTION = 'This is a Proof Of Concept application that demostrates how AI can be used to generate accurate results for vulnerability analysis and also allows further utilization of the already super useful ChatGPT made using openai-api, python-nmap, dnsresolver python modules and also use customtkinter and tkinter for the GUI version of the code. This project also has a CLI and a GUI interface, It is capable of doing network vulnerability analysis, DNS enumeration and also subdomain enumeration.'

# Setting up
setup(
    name="GVA",
    version=VERSION,
    author="Chiranjeevi G",
    author_email="morpheuslord@protonmail.com",
    description=DESCRIPTION,
    long_description_content_type="text/markdown",
    long_description=long_description,
    packages=find_packages(),
    install_requires=['aiohttp == 3.8.4',
                      'aiosignal == 1.3.1',
                      'async-timeout == 4.0.2',
                      'attrs == 22.2.0',
                      'certifi == 2022.12.7',
                      'charset-normalizer == 3.0.1', 'frozenlist == 1.3.3', 'idna == 3.4',
                      'multidict == 6.0.4', 'openai == 0.27.0', 'python-nmap == 0.7.1', 'requests == 2.28.2', 'tqdm == 4.65.0', 'urllib3 == 1.26.14', 'yarl == 1.8.2', 'dnspython', 'rich', 'cowsay', 'tk', 'customtkinter'],
    keywords=['python', 'GPT', 'vulnerability',
              'ai', 'vulnerability-assessment', 'network-scanning'],
    classifiers=[
        "Development Status :: 1 - Planning",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Operating System :: Unix",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
    ]
)
