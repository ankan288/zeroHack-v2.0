"""
ZeroHack v2.0 - Package Setup
"""

from setuptools import setup, find_packages

with open("requirements.txt") as f:
    requirements = [
        line.strip()
        for line in f
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="zerohack",
    version="2.0.0",
    description="ZeroHack v2.0 — Advanced Vulnerability Assessment Tool",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="ZeroHack Team",
    license="MIT",
    python_requires=">=3.9",
    packages=find_packages(),
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "zerohack=vulnscanner:cli_main",
            "zerohack-bench=benchmark_eval:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    keywords=[
        "security", "vulnerability", "scanner", "penetration-testing",
        "owasp", "sql-injection", "xss", "ssrf", "ethical-hacking",
        "bug-bounty", "web-security", "api-security",
    ],
)
