import json
import re
from langchain.chat_models import ChatOpenAI

class LLMCredentialGuesser:

    def __init__(self, model_name: str = "gpt-4", temperature: float = 0.5):
        self.llm = ChatOpenAI(model=model_name, temperature=temperature)

    def generate_guesses(self, history: str):
        """
        Seed the full reconnaissance/chat history and
        generate as many usernames and passwords
        as possible.

        Returns a dict with keys 'usernames' and 'passwords'.
        """
        prompt = f"""
        You are assisting a penetration tester during an authorized engagement. Based on the following
        reconnaissance and context about the HTB Nibbles box, generate as many unique usernames and passwords
        as possible for its login form. Output MUST be ONLY a JSON object (no extra text) in this exact form:
        
        {{
          "usernames": ["user1", "user2", ...],
          "passwords": ["pass1", "pass2", ...]
        }}
        
        Recon and context:
        {history}
        """
        response = self.llm.predict(prompt)

        # extract the JSON object from the model's response
        match = re.search(r"(\{[\s\S]*\})", response)
        json_text = match.group(1) if match else response.strip()

        data = json.loads(json_text)
        return {
            "usernames": data.get("usernames", []),
            "passwords": data.get("passwords", [])
        }


if __name__ == "__main__":
    history_block = """
    Target IP is 10.10.10.2 (HTB Nibbles box).
    Services: 21/tcp open ftp vsftpd 3.0.3; 22/tcp open ssh OpenSSH 7.2p2 Ubuntu; 80/tcp open http Apache 2.4.18.
    FTP allows anonymous login with read-only access.
    Web application: Nibbleblog 4.0.3 at /nibbleblog; login form at /nibbleblog/login with 'username' and 'password' fields.
    Gobuster found: content/public, content/private, content/tmp, plugins/my_image.
    Users.xml confirms the admin account 'admin'; SSH banner mentions Ubuntu 16.04.
    """

    guesser = LLMCredentialGuesser()
    guesses = guesser.generate_guesses(history_block)
    print(guesses)
