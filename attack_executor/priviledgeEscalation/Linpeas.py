

def execute_linpeas_script(command, executor):
    executor.communicate_with_msf_session(command)

execute_linpeas_script(command = "xxx",
                       executor = metasploit_excutor)