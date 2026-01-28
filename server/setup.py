from pathlib import Path

from setuptools import Command, find_packages, setup


class GenerateCommand(Command):
    description = "generates manticore_server server protobuf + grpc code from protobuf specification file"
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        from grpc.tools import protoc

        protoc.main(
            [
                "grpc_tools.protoc",
                "-I.",
                "--python_out=.",
                "--grpc_python_out=.",
                "--mypy_out=.",
                "./manticore_server/ManticoreServer.proto",
            ]
        )


# Minimum protobuf version for types-protobuf compatibility
TYPES_PROTOBUF_MIN_VER = "3.20"

setup(
    name="manticore_server",
    version="0.0.1",
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.9",
    install_requires=[
        f"manticore[native] @ file://{Path(__file__).parent.resolve()}/..",
        "protobuf>=3.20,<6.0",
        "grpcio>=1.60,<2.0",
        "crytic-compile>=0.2.2",
    ],
    extras_require={
        "dev": [
            "grpcio-tools",
            "mypy-protobuf",
            f"types-protobuf>={TYPES_PROTOBUF_MIN_VER}",
            "shiv~=1.0.1",
            "types-setuptools",
            "black>=24.0",
            "isort>=5.12",
            "mypy>=1.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "manticore_server=manticore_server.manticore_server:main",
        ],
    },
    cmdclass={
        "generate": GenerateCommand,
    },
)
