<img width="400" src="https://github.com/user-attachments/assets/2b3b0257-dedc-4186-ad29-3c0994f45ca2"/>

# Threat Hunt Report: Data Theft

## Platforms and Languages Leveraged
- Linux (Ubuntu 22.04) Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Bash

## Scenario

Management has raised concerns about a potential data exfiltration attempt by an employee on the verge of being fired. The employee is suspected of copying sensitive company information—such as fake credit card information and fake user account details—into a folder and encrypting it to prepare for extraction. This data could potentially be moved off the system for malicious purposes. Security teams have detected unusual file activities on the machine, such as file copying, encryption, and file movement, suggesting that the employee may be attempting to hide or secure the data before leaving the organization.

## High-Level IoC Discovery Plan

- **Check `DeviceProcessEvents`** for suspicious executions of outdated software or any software associated with known vulnerabilities.
- **Check `DeviceNetworkEvents`** for unusual network activity made by the outdated software or suspicious outbound connections.
- **Check `DeviceFileEvents`** for modifications to software installation files, directories, and configuration files related to outdated software.

---

## Steps Taken

### 1. Searched the `DeviceProcessEvents` Table

Searched for processes running on the system, specifically looking for signs of suspicious file movement and encryption activities. Initial investigations led to the discovery of potentially suspicious processes on the device **"thlinux"** run by the user **"baddog"**.

At Feb 6, 2025 9:48:01 AM, the user "baddog" executed the following command on the device "thlinux":

`
mv /usr/bin/mv
`

This command is a system operation for moving files. The mv command typically indicates the movement of files, and this event could point to suspicious file handling activities. However, further investigation is required to identify the specific files being moved.

At Feb 6, 2025 9:24:31 AM, the user "baddog" executed the following command on the device "thlinux":

`
openssl
`

This command is associated with the execution of the openssl encryption tool. The frequent execution of openssl could indicate that the user was involved in encrypting files, which may be part of an attempt to obscure or protect sensitive data.

These findings suggest that "baddog" was involved in file manipulation, including movement and potential encryption of sensitive data on the device "thlinux". Further investigation is required to determine the exact files involved in these actions.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == 'thlinux'
| order by Timestamp desc

DeviceProcessEvents
| where DeviceName == 'thlinux'
| where ProcessCommandLine contains "mv" or ProcessCommandLine contains "openssl"
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/5fd48424-aaa7-4228-a241-b2d721d4ddc5">
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/507a42b8-950d-4b7e-8466-76c56cbe9b72">

---

### **Chronological Event Timeline**

### 1. Process Execution - Encrypting Data (Command: `openssl`)

- **Time:** `Feb 6, 2025 9:24:31 AM`
- **Event:** The employee **"baddog"** executed the **`openssl`** command to encrypt data on the system.
- **Action:** Process execution detected.
- **Command:** `openssl`
- **File Path:** `/usr/bin/openssl`

### 2. Process Execution - File Movement (Command: `mv`)

- **Time:** `Feb 6, 2025 9:24:37 AM`
- **Event:** The employee **"baddog"** executed the **`mv`** command to move files on the system.
- **Action:** Process execution detected.
- **Command:** `mv /usr/bin/mv`
- **File Path:** `/usr/bin/mv`

### 3. Process Execution - Encrypting Data (Command: `openssl`)

- **Time:** `Feb 6, 2025 9:47:42 AM`
- **Event:** The employee **"baddog"** executed the **`openssl`** command again to encrypt data on the system.
- **Action:** Process execution detected.
- **Command:** `openssl`
- **File Path:** `/usr/bin/openssl`

### 4. Process Execution - File Movement (Command: `mv`)

- **Time:** `Feb 6, 2025 9:48:01 AM`
- **Event:** The employee **"baddog"** executed the **`mv`** command again, likely for moving files to a new location after encryption.
- **Action:** Process execution detected.
- **Command:** `mv /usr/bin/mv`
- **File Path:** `/usr/bin/mv`

---

## Summary

The user "baddog" on the device "thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net" unknowingly downloaded and installed an outdated version of the Apache HTTP Server (`httpd-2.4.39`), which contains several known vulnerabilities. The employee executed commands to extract and install the software, activating it on the system. Once the outdated version was installed, the Apache service was started.

While the software was (probably) installed without malicious intent, its outdated nature and the associated vulnerabilities pose significant security risks. The use of this outdated version of Apache exposes the system to potential exploits by malicious actors targeting known vulnerabilities in this version.

These actions suggest that the employee inadvertently introduced a security risk by using outdated software, which could be exploited. Immediate action is required to update the software and mitigate any associated risks to the system.

---

## Response Taken

The use of outdated software and the potential vulnerabilities introduced by the employee "baddog" on the endpoint **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"** were confirmed. The device was immediately isolated from the network to prevent further risks. 

I suggest the outdated version of Apache HTTP Server be removed or updated to the latest, secure version. The employee's direct manager was notified, and a recommendation was made to educate the employee on the importance of using up-to-date software and the risks associated with using outdated versions that may have known vulnerabilities.

Further monitoring is being conducted to ensure that no unauthorized access or data exfiltration occurred during the period of exposure.

---
