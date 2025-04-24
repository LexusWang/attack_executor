import subprocess

class GobusterExecutor:
    def __init__(self):
        self.last_result = None
        self.target = None

    def start_session(self, target):
        self.target = target

    def fuzz_directory(self, wordlist="directory-list-2.3-small.txt", endchar="/"):
        if not self.target:
            print("Session not started.")
            return None
        self.target = self.target + "FUZZ" + endchar 
        command = ["gobuster", "fuzz", "-u", self.target, "-w", wordlist, "-b", "404"]

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True
            )
            output = process.stdout
            self.last_result = output
            print(output)
            return output
        except subprocess.CalledProcessError as e:
            print(f"Gobuster scan failed: {e}")
            if e.stdout:
                print("Output:", e.stdout)
            if e.stderr:
                print("Error:", e.stderr)
            return None

if __name__ == "__main__":
    gobuster_executor = GobusterExecutor()
    gobuster_executor.start_session("http://10.129.187.28/")
    gobuster_executor.fuzz_directory()
