import os

from attack_executor.post_exploit.Sliver import SliverExecutor
from attack_executor.config import load_config

config = load_config(config_file_path="/home/user/attack_executor/test/config.ini")

sliver_exe = SliverExecutor(config["sliver"].get("client_config_file"))



