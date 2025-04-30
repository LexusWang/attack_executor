from attack_executor.scan.nmap import NmapExecutor
import subprocess
import json


class SearchsploitExecutor:
    def __init__(self, limit=None):
        self.limit = limit
        self.nmap = NmapExecutor()

    def search_exploits(self, query):
        """
        Run searchsploit for the given query and return a list of exploit entries.
        """
        cmd = ["searchsploit", "--json", query]
        res = subprocess.run(cmd,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL,
                             text=True)
        if res.returncode != 0 or not res.stdout:
            return []

        try:
            data = json.loads(res.stdout)
            exploits = data.get("RESULTS_EXPLOIT", [])
            if self.limit is not None:
                return exploits[: self.limit]
            return exploits

        except json.JSONDecodeError:
            return []

    def searchsploit(self, target):
        """
        Scan the target with Nmap, then for each open service,
        query searchsploit and collect results.
        """
        services = self.nmap.scan_xml(target=target)
        results = []

        for svc in services:
            # build a query string from service name, product, version
            query = " ".join(filter(None,
                                    [svc.get("name"),
                                     svc.get("product"),
                                     svc.get("version")]))
            print(query)
            exploits = self.search_exploits(query)
            results.append({
                **svc,
                "query": query,
                "exploits": exploits
            })

        return results

if __name__ == "__main__":
    ss = SearchsploitExecutor()
    print(ss.searchsploit(target="10.129.171.90"))
    # example output:
    # [{'port': '21', 'proto': 'tcp', 'name': 'ftp', 'product': 'vsftpd', 'version': '2.3.4',
    # 'query': 'ftp vsftpd 2.3.4', 'exploits': [{'Title': 'vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)',
    # 'EDB-ID': '17491', 'Date_Published': '2011-07-05', 'Date_Added': '2011-07-05', 'Date_Updated': '2021-04-12',
    # 'Author': 'Metasploit', 'Type': 'remote', 'Platform': 'unix', 'Port': '', 'Verified': '1', 'Codes':
    # 'OSVDB-73573;CVE-2011-2523', 'Tags': 'Metasploit Framework (MSF)', 'Aliases': '', 'Screenshot': '',
    # 'Application': 'http://www.exploit-db.comvsftpd-2.3.4.tar.gz', 'Source': '',
    # 'Path': '/snap/searchsploit/542/opt/exploitdb/exploits/unix/remote/17491.rb'},
    # {'Title': 'vsftpd 2.3.4 - Backdoor Command Execution', 'EDB-ID': '49757',
    # 'Date_Published': '2021-04-12', 'Date_Added': '2021-04-12', 'Date_Updated': '2021-07-16',
    # 'Author': 'HerculesRD', 'Type': 'remote', 'Platform': 'unix', 'Port': '', 'Verified': '1',
    # 'Codes': 'CVE-2011-2523', 'Tags': '', 'Aliases': '', 'Screenshot': '', 'Application': '', 'Source': '',
    # 'Path': '/snap/searchsploit/542/opt/exploitdb/exploits/unix/remote/49757.py'}]}, {'port': '22', 'proto':
    # 'tcp', 'name': 'ssh', 'product': 'OpenSSH', 'version': '4.7p1 Debian 8ubuntu1', 'query': 'ssh OpenSSH 4.7p1
    # Debian 8ubuntu1', 'exploits': []}, {'port': '139', 'proto': 'tcp', 'name': 'netbios-ssn', 'product': 'Samba
    # smbd', 'version': '3.X - 4.X', 'query': 'netbios-ssn Samba smbd 3.X - 4.X', 'exploits': []}, {'port': '445',
    # 'proto': 'tcp', 'name': 'netbios-ssn', 'product': 'Samba smbd', 'version': '3.0.20-Debian', 'query': 'netbios
    # -ssn Samba smbd 3.0.20-Debian', 'exploits': []}]




