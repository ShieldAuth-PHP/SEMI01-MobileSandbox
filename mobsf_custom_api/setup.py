from setuptools import find_packages, setup

setup(
    name="mobsf-custom-api",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "fastapi",
        "uvicorn",
    ],
    extras_require={
        'test': [
            'pytest',
            'pytest-cov',
            'pytest-mock',
            'requests-mock',
        ],
    },
)