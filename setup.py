"""Setup script for the File Carving Suite."""
from setuptools import setup, find_packages

setup(
    name="file-carver",
    version="2.0.0",
    description="Court-defensible file carving suite for DFIR",
    author="Forensic Tools",
    packages=find_packages(),
    py_modules=["carver", "carver_engine", "signatures", "integrity", "reporting", "threat_protection", "fs_aware", "recurse"],
    install_requires=[],
    extras_require={
        "full": [
            "pyewf>=0.6.0",
            "python-magic>=0.4.27",
            "yara-python>=4.5.0",
            "Pillow>=10.0.0",
            "pypdf>=3.0.0",
            "numpy>=1.24.0",
        ]
    },
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "file-carver=carver:main",
        ],
    },
)
