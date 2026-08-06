from setuptools import setup, find_packages

setup(
    name="vulnforge",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "httpx>=0.24.1",
        "pyyaml>=6.0.2",
        "lxml>=4.9.3",
        "rich>=13.0.0"
    ],
    entry_points={
        "console_scripts": [
            "VulnForge=terminal.cli:main",
            "vulnforge=terminal.cli:main",
        ],
    },
)
