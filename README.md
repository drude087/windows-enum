# PowerShell System Information Enumeration Script

## Overview

This PowerShell script is designed to access all the information that the current user has access to on a Windows system. It collects various details related to the system, users, processes, network configuration, and more.

The script was created using online resources and assistance from ChatGPT, and it is intended to gather information that the current user can access. In future versions, the script will be updated to identify privilege escalation methods and gather additional data when executed with administrative privileges.

## Key Features

- Accesses system information available to the current user
- Gathers user-related data (logged-in users, local users, user groups)
- Retrieves network configuration, active connections, and other system details
- Lists running processes, services, and other system attributes

## Future Updates

The script will be enhanced in future versions to:

- Identify privilege escalation methods
- Gather additional information when executed with administrative privileges

## Requirements

- PowerShell 5.1 or later (Windows PowerShell or PowerShell Core)
- Administrative privileges (in future versions for expanded functionality)
- Windows operating system

## Instructions

1. **Download the Script**  
   Save the script as a `.ps1` file, e.g., `SystemInfoEnumeration.ps1`.

2. **Run the Script**  
   To run the script, open PowerShell and execute it by running:
   ```powershell
   .\SystemInfoEnumeration.ps1
   ```

3. **Access the Output**  
   The script will output the collected information based on the current user's access rights.

## Customization

You can modify the script to fit your needs, including adjusting file paths or adding additional data collection steps.

## Troubleshooting

- Ensure that you are executing the script with the appropriate permissions based on your needs.
