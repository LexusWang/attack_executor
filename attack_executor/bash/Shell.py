import subprocess

class ShellExecutor:
    def __init__(self):
        """
        It sets up the initial state by assigning values to instance attributes.
        """
        pass

    def execute_command(self,
                        command):
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        # result.stdout 保存了标准输出
        print("Standard Output:")
        print(result.stdout)

        # result.stderr 保存了标准错误
        print("Standard Error:")
        print(result.stderr)

        # result.returncode 是返回码，通常 0 表示执行成功
        print("Return Code", result.returncode)

se = ShellExecutor()
se.execute_command(command = "ls -l")


