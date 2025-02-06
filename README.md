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
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/c216c85e-0861-4d6f-9ec5-08114e2116a5">

---

### 2. Searched the `DeviceFileEvents` Table

To narrow the focus and identify the specific files involved in the suspicious activities, we refined the query to look for signs of file movements and encryption actions on **"thlinux"** run by **"baddog"**.

At Feb 6, 2025 9:48:01 AM, the user "baddog" executed the following command on the device "thlinux":

`
mv /usr/bin/mv
`


Using the following query:
```kql
DeviceFileEvents
| where DeviceName == 'thlinux'
| where ActionType in ('Move', 'Copy')
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/145de6e0-1938-4540-8029-9e8903a4fdbc">

---

### 3. Searched the `DeviceFileEvents` Table

Detect the creation or execution of a outdated and/or vulnerable version of software.

At **Feb 3, 2025 10:07:30 AM**, the user **"baddog"** executed the following command on the device **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"**:
```
tar -xzvf httpd-2.4.39.tar.gz
```

This created a file in the path `/home/baddog/httpd-2.4.39/support/apachectl.in`, which shows that the outdated software was installed on the system. 

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName contains "httpd" or FileName contains "apache" or FileName contains "openssl" or FileName contains "tar" or FileName contains "rpm" or FileName contains "make"
| where ActionType in ("FileModified", "FileCreated")
| where InitiatingProcessAccountName == "baddog"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessCommandLine
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/d9d15ba4-2780-458d-9e39-004ca06f5e00">

---

### Chronological Event Timeline 

### 1. File Download - Outdated Software Downloaded

- **Time:** `Feb 3, 2025 10:07:30 AM`
- **Event:** The employee "baddog" downloaded an outdated version of Apache HTTP Server (2.4.39) to the system.
- **Action:** File download detected.
- **File Path:** `httpd-2.4.39.tar.gz`

### 2. Process Execution - Extracting the Software Archive

- **Time:** `Feb 3, 2025 10:07:30 AM`
- **Event:** The employee executed the command to extract the downloaded Apache HTTP Server archive.
- **Action:** Process execution detected.
- **Command:** `tar -xzvf httpd-2.4.39.tar.gz`
- **File Path:** `/home/baddog/httpd-2.4.39`

### 3. Process Execution - Configuring and Installing the Software

- **Time:** `Feb 3, 2025 10:10:00 AM`
- **Event:** The employee configured and installed the Apache HTTP Server.
- **Action:** Process execution detected.
- **Command:** `./configure --prefix=/usr/local/apache2 && make && sudo make install`
- **File Path:** `/usr/local/apache2`

### 4. Process Execution - Starting Apache Service

- **Time:** `Feb 3, 2025 10:25:33 AM`
- **Event:** The employee started the Apache HTTP Server service.
- **Action:** Process execution detected.
- **Command:** `sudo systemctl start apache2`
- **File Path:** `/usr/local/apache2/bin/apachectl`

### 5. Process Execution - Verifying Service Status

- **Time:** `Feb 3, 2025 10:26:00 AM`
- **Event:** The employee attempted to verify the status of the Apache service.
- **Action:** Process execution detected.
- **Command:** `sudo systemctl status apache2`
- **File Path:** `/usr/local/apache2/bin/apachectl`

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
