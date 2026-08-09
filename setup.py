from setuptools import setup, find_packages

setup(
    name="vulnforge",
    version="0.1.0",
    description="VulnForge - Template-driven security research CLI",
    author="Nisan Budhathoki",
    license="MIT",
    python_requires=">=3.10",

    packages=find_packages(),

    install_requires=[
        "httpx>=0.24.1",
        "PyYAML>=6.0.2",
        "lxml>=4.9.3",
        "rich>=13.0.0",
    ],

    entry_points={
        "console_scripts": [
            "VulnForge=terminal.cli:main",
            "vulnforge=terminal.cli:main",
        ],
    },

    include_package_data=True,
    zip_safe=False,
)
