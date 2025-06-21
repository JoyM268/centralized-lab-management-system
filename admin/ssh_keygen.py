import os
import subprocess
import pwd
from pathlib import Path

def ensure_ssh_key(sudo_user):
    key_path = Path(os.path.expanduser(f"~{sudo_user}")) / ".ssh" / "id_rsa"
    if not key_path.exists():
        key_path.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["ssh-keygen", "-t", "rsa", "-b", "4096", "-f", str(key_path), "-N", ""],
            check=True,
            capture_output=True
        )
        pw_record = pwd.getpwnam(sudo_user)
        uid, gid = pw_record.pw_uid, pw_record.pw_gid
        os.chown(key_path.parent, uid, gid)
        os.chown(key_path, uid, gid)
        os.chown(key_path.with_suffix(".pub"), uid, gid)
