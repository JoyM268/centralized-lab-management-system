import os
import subprocess
import shutil
from pathlib import Path

def generate_ssh_key_if_needed(key_path: Path):
    if key_path.exists():
        print(f"SSH key already exists at {key_path}")
    else:
        subprocess.run(
            ["ssh-keygen", "-t", "rsa", "-b", "4096", "-f", str(key_path), "-N", ""],
            check=True
        )
        print(f"SSH key generated at {key_path}")

def copy_public_key(src_pub_key: Path, dest_path: Path):
    if not src_pub_key.exists():
        raise FileNotFoundError(f"Public key not found at {src_pub_key}")

    dest_path = dest_path.expanduser().resolve()
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    shutil.copy2(src_pub_key, dest_path)
    print(f"Public key copied to {dest_path}")

if __name__ == "__main__":
    key_path = Path.home() / ".ssh" / "id_rsa"
    pub_key_path = key_path.with_suffix(".pub")

    # Generate key only if not exists
    generate_ssh_key_if_needed(key_path)

    # Ask for destination
    destination = input("Enter the destination path for the public key (e.g., /tmp/my_id_rsa.pub): ").strip()
    copy_public_key(pub_key_path, Path(destination))