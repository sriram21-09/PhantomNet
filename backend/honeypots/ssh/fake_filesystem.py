import os

class FakeFilesystem:
    def __init__(self, username="root"):
        self.username = username
        self.fs = {
            "/": ["bin", "boot", "dev", "etc", "home", "lib", "media", "mnt", "opt", "proc", "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var"],
            "/etc": ["passwd", "shadow", "group", "hostname", "ssh", "network", "apt"],
            "/etc/ssh": ["sshd_config", "ssh_config"],
            "/var": ["log", "mail", "spool", "www", "lib", "cache"],
            "/var/www": ["html"],
            "/var/www/html": ["index.html", "admin.php", "config.php"],
            "/home": [username],
            f"/home/{username}": ["Desktop", "Documents", "Downloads", "project.txt", ".bashrc"],
            "/root": [".bashrc", ".ssh", "secrets.txt"],
            "/bin": ["ls", "cat", "cd", "pwd", "whoami", "exit", "echo", "mkdir", "rm"],
            "/usr": ["bin", "lib", "local", "sbin", "share"],
            "/usr/bin": ["python", "gcc", "make", "curl", "wget"]
        }
        self.file_contents = {
            "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n" + f"{username}:x:1000:1000:{username}:/home/{username}:/bin/bash",
            "/etc/hostname": "phantomnet-prod-server",
            "/var/www/html/index.html": "<html><body><h1>It Works!</h1></body></html>",
            "/var/www/html/config.php": "<?php\n$db_user = 'admin';\n$db_pass = 'phantom123';\n?>",
            f"/home/{username}/project.txt": "PhantomNet Phase 2: Deception Architecture v2.1",
            "/root/secrets.txt": "CRITICAL: Remember to rotate internal API keys by Month 3."
        }

    def list_dir(self, path):
        path = self._normalize_path(path)
        return self.fs.get(path, [])

    def read_file(self, path):
        path = self._normalize_path(path)
        return self.file_contents.get(path, f"cat: {path}: No such file or directory")

    def is_dir(self, path):
        path = self._normalize_path(path)
        return path in self.fs

    def _normalize_path(self, path):
        if not path:
            return "/"
        path = path.rstrip("/")
        if not path:
            return "/"
        return path

    def get_prompt(self, user, host, cwd):
        return f"{user}@{host}:{cwd}$ "
