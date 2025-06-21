# Centralized Lab Management System

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A GUI-based solution for system administrators to manage a network of student computers in a lab environment. This system provides tools for remote command execution, file distribution, and user management, all from a central admin dashboard.

## Table of Contents

- [About The Project](#about-the-project)
- [How It Works](#how-it-works)
- [Features](#features)
- [Screenshots](#screenshots)
  - [Admin Dashboard](#admin-dashboard-1)
  - [Student Client](#student-client-1)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation & Setup](#installation--setup)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## About The Project

This project consists of two main applications:

1.  **Admin.py**: A powerful dashboard for the administrator. It discovers active student machines on the network, allows for the execution of commands, and facilitates the transfer of files to single or multiple clients simultaneously.
2.  **Student.py**: A client-side application that runs on each student's machine. It automates the setup of a secure SSH server and provides a simple interface for managing access keys.

The entire system is built with Python and uses Tkinter for a user-friendly graphical interface, Paramiko for SSH communications, and Scapy for network discovery.

## How It Works

The system operates on a secure client-server model built on top of SSH.

1.  **Authentication**: The connection is secured using an SSH key pair. The Admin machine generates a key pair and holds the private key. The public key is distributed to all Student machines.
2.  **Discovery**: The Admin application performs an ARP scan on a specified network subnet to discover active devices. It then uses a local `user.json` file, which maps MAC addresses to usernames, to identify and list the online student PCs. This `user.json` file can be easily managed (adding or deleting users) directly through the admin dashboard's "Manage Users" interface.
3.  **Communication**: All actions, such as remote command execution and file transfers, are performed over the SSH protocol using the Paramiko library. The Student application configures the client machine to only accept these key-based connections, enhancing security by disabling password authentication.
4.  **Concurrency**: The Admin application leverages multithreading to perform tasks like file transfers and remote command execution on multiple student machines simultaneously, making it efficient for managing an entire lab.

## Features

### Admin Dashboard

-   **Automated Setup**: On first launch, automatically generates the necessary SSH key pair.
-   **Network Configuration**: Prompts for a network subnet (e.g., `192.168.1.0/24`) to scan and allows it to be changed at any time.
-   **Active User Discovery**: Scans the network and displays a real-time list of all recognized and active student users.
-   **Remote Command Execution**: A UI to execute shell commands on a single selected student machine or on all active machines at once. Output is streamed back to the admin dashboard.
-   **Concurrent File Transfer**: Securely send files from the admin PC to a specified path on multiple student machines simultaneously.
-   **User Management**: An intuitive interface to add or remove users by mapping a username to a unique MAC address.
-   **Public Key Exporter**: A simple button to export the admin's public key (`id_rsa.pub`), which is needed for the student machines.

### Student Client

-   **One-Click SSH Setup**: Automatically installs `openssh-server`.
-   **Secure Configuration**:
    -   Enables and starts the SSH service (`systemctl`).
    -   Configures the firewall (`ufw`) to allow SSH connections.
    -   Hardens the SSH server by disabling password authentication in favor of public key authentication.
-   **Key Management UI**:
    -   Allows the user to easily add an admin's public key to the `authorized_keys` file.
    -   Provides a dialog to view and delete existing authorized keys.
-   **Root Privileges Check**: Ensures the script is run with `sudo` to perform system-level tasks.

## Screenshots

### Admin Dashboard
<table align="center">
  <tr>
    <td align="center"><strong>Main Menu</strong></td>
    <td align="center"><strong>Active Users</strong></td>
  </tr>
  <tr>
    <td><img src="https://github.com/JoyM268/centralized-lab-management-system/blob/main/images/Admin/main_menu.png" width="400"></td>
    <td><img src="https://github.com/JoyM268/centralized-lab-management-system/blob/main/images/Admin/active_users.png" width="400"></td>
  </tr>
  <tr>
    <td align="center"><strong>Remote Command Execution</strong></td>
    <td align="center"><strong>File Transfer</strong></td>
  </tr>
  <tr>
    <td><img src="https://github.com/JoyM268/centralized-lab-management-system/blob/main/images/Admin/execute_command.png" width="400"></td>
    <td><img src="https://github.com/JoyM268/centralized-lab-management-system/blob/main/images/Admin/file_sharing.png" width="400"></td>
  </tr>
   <tr>
    <td align="center"><strong>Manage Users</strong></td>
    <td align="center"><strong>Add User</strong></td>
  </tr>
    <tr>
    <td><img src="https://github.com/JoyM268/centralized-lab-management-system/blob/main/images/Admin/manage_users.png" width="400"></td>
    <td><img src="https://github.com/JoyM268/centralized-lab-management-system/blob/main/images/Admin/add_user.png" width="398"></td>
  </tr>
</table>

### Student Client
<table align="center">
  <tr>
    <td align="center"><strong>Main Menu</strong></td>
    <td align="center"><strong>Add Public Key</strong></td>
    <td align="center"><strong>Delete Public Key</strong></td>
  </tr>
  <tr>
    <td><img src="https://github.com/JoyM268/centralized-lab-management-system/blob/main/images/Student/main_menu.png" width="260"></td>
    <td><img src="https://github.com/JoyM268/centralized-lab-management-system/blob/main/images/Student/add_key.png" width="260"></td>
    <td><img src="https://github.com/JoyM268/centralized-lab-management-system/blob/main/images/Student/delete_key.png" width="260"></td>
  </tr>
</table>

## Getting Started

Follow these instructions to get the system up and running in your lab.

### Prerequisites

-   Both Admin and Student machines must be running a Debian-based Linux distribution (like Ubuntu).
-   **Python 3**: The scripts require Python 3. You can download it from [python.org](https://www.python.org/downloads/) or install it using your distribution's package manager.
-   **Tkinter**: This GUI toolkit is required. If it's not installed with Python by default, you can install it on Debian-based systems with the following command:
  
    ```
    sudo apt-get update && sudo apt-get install python3-tk
    ```
-   **Python Packages**: Install the required packages using the `requirements.txt` file.
  
    ```
    pip install -r requirements.txt
    ```

### Installation & Setup

1.  **Clone the Repository**
    ```
    git clone https://github.com/JoyM268/centralized-lab-management-system.git
    cd centralized-lab-management-system
    ```

2.  **Admin PC Setup**

    a. Run the admin application with root privileges:
    ```
    sudo python3 Admin.py
    ```

    b. **First Run**: The app will generate an SSH key pair. It will then ask you to enter the network subnet you want to manage (e.g., `192.168.1.0/24`).

    c. **Export Public Key**: Click the **"Export Public Key"** button. Save the `id_rsa.pub` file to a known location.

    d. **Transfer the Key**: You must **manually copy this `id_rsa.pub` file to each student PC** (e.g., using a USB flash drive).

    e. **Add Users**: Click **"Manage Users"** to add the `username` and `MAC address` for each student computer in the lab. This is crucial for device identification.

3.  **Student PC Setup**

    a. On each student machine, copy the `id_rsa.pub` file you exported from the admin PC.

    b. Run the student application with root privileges:
    ```
    sudo python3 Student.py
    ```

    c. The script will automatically install and configure the SSH server and firewall.

    d. Once the initial setup is complete, the application will show key management options. Click **"Add Public Key"** and select the `id_rsa.pub` file that you copied over.

    **Note**: This setup process for each student PC is a **one-time operation**. Once the admin's key is added, the system is permanently configured for remote access, and you do not need to run `Student.py` again on that machine for normal operation.

The setup is now complete! The admin can now manage all configured student PCs from the Admin Dashboard.

## Usage

-   **Running the Applications**: Always run both `Admin.py` and `Student.py` with `sudo` as they need root permissions for network scanning and system configuration.
-   **Viewing Active Users**: On the Admin Dashboard, click "View Active Users" to see a list of student machines that are currently online. You can refresh this list at any time.
-   **Sending Files**: Use the "Transfer File" option. Select a source file, specify a destination path (e.g., `~/Desktop/`), and the file will be sent to all active users.
-   **Executing Commands**: Use the "Execute Command" option. You can choose to run a command on a single user or all users. The output will be displayed in real-time.

## Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request.
1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License. The license can be viewed [here](https://github.com/JoyM268/centralized-lab-management-system/blob/main/LICENSE).

## Acknowledgments

-   [Paramiko](http://www.paramiko.org/) for SSHv2 protocol implementation.
-   [Scapy](https://scapy.net/) for powerful packet manipulation.
-   [Tkinter](https://docs.python.org/3/library/tkinter.html) for the standard GUI toolkit.
