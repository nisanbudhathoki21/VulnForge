from setuptools import setup, find_packages

setup(
    name="VulnForge",
    version="3.2.0",
    py_modules=["cli", "database", "seed"],
    packages=find_packages(),
    install_requires=[
        "fastapi>=0.110.0",
        "uvicorn>=0.29.0",
        "httpx>=0.27.0",
        "reportlab>=4.1.0",
        "pydantic>=2.0.0"
    ],
    entry_points={
        "console_scripts": [
            "VulnForge=cli:main",
            "vulnforge=cli:main"
        ]
    }
)
