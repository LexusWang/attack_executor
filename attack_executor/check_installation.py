'''
This script checks if you have installed the necessary tools used by attack-executor 
'''

import time
import subprocess
from rich.console import Console
console = Console()

def check_nmap_installation():
    with console.status("Check if nmap is installed..."):
        try:
            result = subprocess.run(["nmap", "--version"], capture_output=True, text=True, check=True)
            console.print("[bold green][SUCCESS] nmap is installed![/bold green]")
            console.print(result.stdout.splitlines()[0])  # print the version info in the first line
        except FileNotFoundError:
            console.print("[bold red][FAILED] nmap is uninstalled! [/bold red]")
        except subprocess.CalledProcessError:
            console.print("[bold red][FAILED] nmap is uninstalled! [/bold red]")

def check_nuclei_installation():
    with console.status("Check if nuclei is installed..."):
        try:
            result = subprocess.run(["nuclei", "--version"], capture_output=True, text=True, check=True)
            console.print("[bold green][SUCCESS] nuclei is installed![/bold green]")
            console.print(result.stdout.splitlines()[0])  # print the version info in the first line
        except FileNotFoundError:
            console.print("[bold red][FAILED] nuclei is uninstalled! [/bold red]")
        except subprocess.CalledProcessError:
            console.print("[bold red][FAILED] nuclei is uninstalled! [/bold red]")

def check_gobuster_installation():
    with console.status("Check if gobuster is installed..."):
        try:
            result = subprocess.run(["gobuster", "version"], capture_output=True, text=True, check=True)
            console.print("[bold green][SUCCESS] gobuster is installed![/bold green]")
            console.print(result.stdout.splitlines()[0])  # print the version info in the first line
        except FileNotFoundError:
            console.print("[bold red][FAILED] gobuster is uninstalled! [/bold red]")
        except subprocess.CalledProcessError:
            console.print("[bold red][FAILED] gobuster is uninstalled! [/bold red]")

def check_installation():
    check_nmap_installation()
    check_nuclei_installation()
    check_gobuster_installation()
