import subprocess
import os
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage

class GobusterExecutor:
    def __init__(self):
        self.last_result = None
        self.target = None
        api_key = os.getenv("OPENAI_API_KEY")
        if api_key is None:
            raise ValueError("The OPENAI_API_KEY environment variable is not set")
        self.llm = ChatOpenAI(
            model_name="gpt-4o",
            temperature=0.0,
            openai_api_key=api_key
        )

    def start_session(self, target):
        self.target = target
        
    def enumerate_dir(self, target_url, wordlist):
        command = ["gobuster", "dir", "-u", target_url, "-w", wordlist]
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
        
    def enumerate_subdomain(self, main_domain, wordlist):
        command = ["gobuster", "dns", "-d", main_domain, "-w", wordlist]
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

    def fuzz_directory(self, wordlist="smalllist.txt", endchar="/"):
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

    def chat_with_llm(self, user_input, conversation_history):
        conversation_history.append(HumanMessage(content=user_input))
        assistant_reply = self.llm.invoke(conversation_history).content
        conversation_history.append(AIMessage(content=assistant_reply))

        return assistant_reply

    def match_output_with_predicate(self, pddl_predicates_file):
        if not self.last_result:
            print("No Gobuster results available. Run a scan first.")
            return None

        try:
            with open(pddl_predicates_file, 'r') as f:
                predicates = f.read()
        except FileNotFoundError:
            print(f"PDDL predicates file not found: {pddl_predicates_file}")
            return None

        INITIAL_PROMPT = f"""
        You are a world class security engineer.
        I will provide you with Gobuster output. You are tasked to match the output with the predicates from the following list. Do not create new predicates. 
        {predicates}
        Return the predicates that are relevant to the Gobuster output, separated by line breaks.
        Use your experience with common web server vulnerabilities and which web pages would be an indicator of a vulnerability.
        """

        conversation_history = [SystemMessage(content=INITIAL_PROMPT)]
        messages = [self.last_result]

        responses = []
        conversation_records = []
        for m in messages:
            assistant_reply = self.chat_with_llm(m, conversation_history)
            responses.append(assistant_reply)
            conversation_records.append(m)
            conversation_records.append(assistant_reply)

        return responses[0]

if __name__ == "__main__":
    gobuster_executor = GobusterExecutor()
    gobuster_executor.start_session("http://10.129.63.144/")
    gobuster_executor.enumerate_subdomain()
    gobuster_executor.enumerate_dir()
    gobuster_executor.fuzz_directory()
    result = gobuster_executor.match_output_with_predicate("./predicates.txt")
    print(result)
