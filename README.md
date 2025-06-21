# Centralized Lab Management System

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A GUI-based solution for admin to manage a network of student computers in a lab environment. This system provides tools for remote command execution, file distribution over SSH, all from a central admin dashboard.

## 📋 Table of Contents

-   [About The Project](#about-the-project)
-   [How It Works](#how-it-works)
-   [Features](#features)
-   [Screenshots](#screenshots)
    -   [Admin Dashboard](#admin-dashboard-1)
    -   [Student Client](#student-client-1)
-   [Getting Started](#getting-started)
    -   [Prerequisites](#prerequisites)
    -   [Installation & Setup](#installation--setup)
-   [Contributing](#contributing)
-   [License](#license)
-   [Acknowledgments](#acknowledgments)

## 🚀 About The Project

This project consists of two main applications:

1.  🖥️ **Admin**: A powerful dashboard for the admin. It discovers active student machines on the network, allows for the execution of commands, and facilitates the transfer of files to single or multiple clients simultaneously.
2.  💻 **Student**: A application that runs on each student's machine. It automates the setup of a secure SSH server and provides a simple interface for managing access keys.

The entire system is built with Python and uses Tkinter for a user-friendly graphical interface, Paramiko for SSH communications, and Scapy for network discovery.

## ⚙️ How It Works

The system operates on a secure client-server model using SSH:

1.  🔐 **Authentication**: The connection is secured using an SSH key pair. The Admin machine holds a private key, while the corresponding public key is distributed to all Student machines.
2.  📡 **Discovery**: The admin uses the GUI to add each student PC's username and MAC address, creating a user list that is saved for future sessions. When a network scan is performed, the application uses ARP to discover all active devices. It then compares the discovered MAC addresses against the saved user list to identify student PCs and their current IP addresses, which are used to establish the SSH connection.
3.  🔁 **Communication**: All actions, such as remote command execution and file transfers, are performed over the secure SSH protocol using the Paramiko library.
4.  ⚡ **Concurrency**: The Admin application leverages multithreading to perform tasks on multiple student machines simultaneously, making it efficient for managing an entire lab.

## ✨ Features

### 👨‍💻 Admin Dashboard

-   **Automated Setup**: Automatically generates the necessary SSH key pair on first launch.
-   **Network Configuration**: Prompts for a network subnet (e.g., `192.168.1.0/24`) and allows it to be changed at any time.
-   **Active User Discovery**: Scans the network to display a real-time list of recognized and active student users.
-   **Remote Command Execution**: Execute shell commands on a single student machine or on all active machines at once, with output streamed back to the dashboard.
-   **Concurrent File Transfer**: Securely send files to a specified path on multiple student machines simultaneously.
-   **User Management**: An intuitive interface to add or remove users by mapping a username to a unique MAC address.
-   **Public Key Exporter**: A simple button to export the admin's public key (`id_rsa.pub`) for distribution to student machines.

### 🎓 Student Client

-   **One-Click SSH Setup**: Automatically installs and configures `openssh-server`.
-   **Secure Configuration**: Enables the SSH service, configures the firewall (`ufw`), and hardens the server by disabling password authentication in favor of public key authentication.
-   **Key Management UI**: A simple interface to add the admin's public key to the `authorized_keys` file or to view and delete existing keys.
-   **Root Privileges Check**: Ensures the script is run with `sudo` to perform necessary system-level tasks.

## 📸 Screenshots

### Admin Dashboard

<table>
 <tr>
    <td align="center"><strong>Main Menu</strong></td>
    <td align="center"><strong>Active Users</strong></td>
 </tr>
 <tr>
    <td align="center"><img src="https://github.com/JoyM268/centralized-lab-management-system/blob/main/images/admin/main_menu.png" width="400"></td>
    <td align="center"><img src="https://github.com/JoyM268/centralized-lab-management-system/blob/main/images/admin/active_users.png" width="400"></td>
 </tr>
 <tr>
    <td align="center"><strong>Remote Command Execution</strong></td>
    <td align="center"><strong>File Transfer</strong></td>
 </tr>
 <tr>
    <td align="center"><img src="https://github.com/JoyM268/centralized-lab-management-system/blob/main/images/admin/execute_command.png" width="400"></td>
    <td align="center"><img src="https://github.com/JoyM268/centralized-lab-management-system/blob/main/images/admin/file_sharing.png" width="400"></td>
 </tr>
  <tr>
    <td align="center"><strong>Manage Users</strong></td>
    <td align="center"><strong>Add User</strong></td>
 </tr>
   <tr>
    <td align="center"><img src="https://github.com/JoyM268/centralized-lab-management-system/blob/main/images/admin/manage_users.png" width="400"></td>
    <td align="center"><img src="https://github.com/JoyM268/centralized-lab-management-system/blob/main/images/admin/add_user.png" width="320"></td>
 </tr>
</table>

### Student Client

<table>
 <tr>
    <td align="center"><strong>Main Menu</strong></td>
    <td align="center"><strong>Add Public Key</strong></td>
    <td align="center"><strong>Delete Public Key</strong></td>
 </tr>
 <tr>
    <td align="center"><img src="https://github.com/JoyM268/centralized-lab-management-system/blob/main/images/student/main_menu.png" width="260"></td>
    <td align="center"><img src="https://github.com/JoyM268/centralized-lab-management-system/blob/main/images/student/add_key.png" width="260"></td>
    <td align="center"><img src="https://github.com/JoyM268/centralized-lab-management-system/blob/main/images/student/delete_key.png" width="260"></td>
 </tr>
</table>

## 🏁 Getting Started

Follow these instructions to get the system up and running in your lab.

### ✅ Prerequisites

-   Both Admin and Student machines must be running a Debian-based Linux distribution (like Ubuntu).
-   **Python 3**: If not already installed, download it from [python.org](https://www.python.org/downloads/) or use your distribution's package manager.
-   **Tkinter**: To install, run the following command:

    ```
    sudo apt-get update && sudo apt-get install python3-tk
    ```

-   **Python Packages**: Install the required packages using the `requirements.txt` file.

    ```
    pip install -r requirements.txt
    ```

### 🛠️ Installation & Setup

1.  **Clone the Repository**

    ```
    git clone [https://github.com/JoyM268/centralized-lab-management-system.git](https://github.com/JoyM268/centralized-lab-management-system.git)
    cd centralized-lab-management-system
    ```

2.  **Admin PC Setup**

    a. Run the admin application with root privileges:

    ```
    cd admin
    sudo python3 main.py
    ```

    b. **First Run**: The app will generate an SSH key pair and prompt you to enter the network subnet to manage (e.g., `192.168.1.0/24`).

    c. **Export and Transfer Key**: Click **"Export Public Key"** and manually copy the resulting `id_rsa.pub` file to each student PC (e.g., via a USB drive).

    d. **Add Users**: Click **"Manage Users"** to add the `username` and `MAC address` for each student computer. This is crucial for device identification.

3.  **Student PC Setup**

    a. On each student machine, run the student application with root privileges:

    ```
    cd student
    sudo python3 main.py
    ```

    b. The script will automatically install and configure the SSH server and firewall.

    c. Click **"Add Public Key"** and select the `id_rsa.pub` file that you copied from the admin PC.

    **Note**: The student PC setup is a **one-time operation**. Once the admin's key is added, you do not need to run `student/main.py` on that machine again for normal operation.

The setup is now complete! The administrator can manage all configured student PCs directly from the Admin Dashboard.

## 🤝 Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request.

## 📜 License

This project is licensed under the MIT License. The license can be viewed [here](https://github.com/JoyM268/centralized-lab-management-system/blob/main/LICENSE).

## Acknowledgments

-   [Paramiko](http://www.paramiko.org/) for SSHv2 protocol implementation.
-   [Scapy](https://scapy.net/) for powerful packet manipulation.
-   [Tkinter](https://docs.python.org/3/library/tkinter.html) for the standard GUI toolkit.
-   DigitalOcean for their tutorial on [SSH Key-Based Authentication](https://www.digitalocean.com/community/tutorials/how-to-configure-ssh-key-based-authentication-on-a-linux-server).
-   Medium article on [Network Monitoring with Python and Scapy](https://medium.com/@aneess437/network-monitoring-with-python-and-scapy-arp-scanning-and-dns-sniffing-explained-8b4eb1c3ff58).
