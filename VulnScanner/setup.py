#!/usr/bin/env python3
"""
VulnScanner v1.8 - Setup Configuration
Comprehensive Vulnerability Assessment Tool with 7 Immunefi Case Studies
"""

from setuptools import setup, find_packages
import os

# Read the requirements from requirements.txt
def read_requirements():
    """Read requirements from requirements.txt file"""
    requirements_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    with open(requirements_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # Filter out comments, empty lines, and built-in modules
    requirements = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith('#') and not line.startswith('Note:') and '>=' in line:
            # Extract just the package name and version
            requirements.append(line)
    return requirements

# Read the README file for long description
def read_readme():
    """Read README.md for long description"""
    readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
    if os.path.exists(readme_path):
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    return "VulnScanner v1.8 - Comprehensive Vulnerability Assessment Tool with 7 Immunefi Case Studies"

setup(
    name="zerohack",
    version="1.8.0",
    author="ZeroHack Team",
    author_email="security@zerohack.dev",
    description="Comprehensive Vulnerability Assessment Tool with 7 Immunefi Case Studies ($10M+ Portfolio)",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/zerohack-team/zerohack",
    project_urls={
        "Bug Reports": "https://github.com/zerohack-team/zerohack/issues",
        "Source": "https://github.com/zerohack-team/zerohack",
        "Documentation": "https://github.com/zerohack-team/zerohack/wiki",
    },
    packages=find_packages(exclude=['tests*', 'docs*']),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators", 
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP :: Site Management",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: MacOS",
        "Environment :: Console",
        "Natural Language :: English",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        'dev': [
            'pytest>=7.4.0',
            'pytest-asyncio>=0.21.0',
            'black>=23.7.0',
            'flake8>=6.0.0',
            'mypy>=1.5.0',
        ],
        'advanced': [
            'scikit-learn>=1.3.0',
            'tensorflow>=2.13.0',
            'pyshark>=0.6.0',
            'impacket>=0.11.0',
        ],
        'all': [
            'pytest>=7.4.0',
            'pytest-asyncio>=0.21.0', 
            'black>=23.7.0',
            'flake8>=6.0.0',
            'mypy>=1.5.0',
            'scikit-learn>=1.3.0',
            'tensorflow>=2.13.0',
            'pyshark>=0.6.0',
            'impacket>=0.11.0',
        ]
    },
    entry_points={
        'console_scripts': [
            'zerohack=vulnscanner:main',
            'zero-hack=vulnscanner:main',
            'zhack=vulnscanner:main',
        ],
    },
    include_package_data=True,
    package_data={
        'zerohack': [
            'modules/*.py',
            'demos/*.py',
            'configs/*.yaml',
            'payloads/*.json',
            'wordlists/*.txt',
        ],
    },
    data_files=[
        ('share/zerohack/docs', ['README.md', 'LICENSE']),
        ('share/zerohack/examples', ['demos/wormhole_proxy_demo.py', 'demos/port_finance_demo.py', 'demos/perpetual_protocol_demo.py']),
        ('share/zerohack/configs', ['requirements.txt']),
    ],
    keywords=[
        "vulnerability", "scanner", "security", "testing", "pentest",
        "web", "api", "cloud", "mobile", "iot", "smart-contracts",
        "immunefi", "bug-bounty", "ethical-hacking", "cybersecurity",
        "kali-linux", "infosec", "defi", "blockchain", "web3", "zerohack"
    ],
    zip_safe=False,
    platforms=['any'],
    license="MIT",
    
    # Metadata for PyPI
    options={
        'bdist_wheel': {'universal': True}
    },
    
    # Security and compliance
    download_url="https://github.com/zerohack-team/zerohack/archive/v1.8.0.tar.gz",
)

# Post-installation message
print("""
╔══════════════════════════════════════════════════════════════╗
║                     ZEROHACK v1.8 INSTALLED                 ║
║              7 Immunefi Case Studies Integrated             ║
║                $10,660,000+ Bounty Portfolio                ║
╚══════════════════════════════════════════════════════════════╝

🚀 Installation Complete! 

Quick Start:
  zerohack -t example.com                       # Basic scan
  zerohack -t example.com -l extreme            # Advanced scan
  python -m zerohack.demos.wormhole_proxy_demo  # Educational demo

Documentation: https://github.com/zerohack-team/zerohack/wiki
Support: https://github.com/zerohack-team/zerohack/issues

⚠️  ETHICAL USE ONLY - Authorized testing only!
⚠️  Ensure you have permission before scanning any target!
""")