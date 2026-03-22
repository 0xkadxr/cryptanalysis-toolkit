"""Setup configuration for the cryptanalysis-toolkit package."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="cryptanalysis-toolkit",
    version="1.0.0",
    author="Abdelkader Benmeriem",
    author_email="",
    description="Classical cipher implementations and cryptanalysis toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/kadirou12333/cryptanalysis-toolkit",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "cryptanalysis": ["data/*.json", "data/*.txt"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
        "Topic :: Education",
        "Intended Audience :: Education",
        "Intended Audience :: Developers",
    ],
    python_requires=">=3.8",
    install_requires=[
        "numpy",
        "rich",
    ],
    extras_require={
        "dev": ["pytest", "matplotlib"],
    },
    entry_points={
        "console_scripts": [
            "cryptanalysis=cli:main",
        ],
    },
)
