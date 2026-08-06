from setuptools import setup, find_packages

setup(
    name="vulnforge",
    version="0.1.0",
    description="VulnForge: Next-generation AI-assisted Security Research Platform",
    author="VulnForge Team",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
    "httpx>=0.24.1",
    "pyyaml>=6.0.2",
    "lxml>=4.9.3",
]
,
    entry_points={
        "console_scripts": [
            "vulnforge=terminal.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
)
