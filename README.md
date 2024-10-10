# YARA Rules Creation & Testing
This is a collection of YARA rules I have written alongside a Python Script to be able to direct a scan using the rule to a specific Directory or File. I had a lot of help in understanding and writing these rules from Pack Of Coders on Udemy. 

## Objective

The objective of the first half of this Lab was to understand how to write YARA rules and learn what to look for to Identify Malware or other malicious processes that may warrant further investigation. The Second half of this lab revolved around building a python script to be able to run a specific YARA rule against a file or directory. This is one of the most interesting labs I have done, and I look forward to continuing to update my rules, so check back often for updates.   

### Skills Learned

- Developed proficiency in writing YARA rules for malware detection
- Hands on Experience looking for Indicators of Compromise (IOC)
- Improved Troubleshooting Skills in Both YARA and Python
- Gained Knowledge in Threat Detection and Analysis Using YARA

### Tools Used

- YARA : For Creation Of Rules
- Python : To Automate Scanning using YARA Rules
- Visual Studio Code : Writing and Debugging YARA Rules and Python Script
- Windows Command Prompt : For Executing Scans

## YARA Rule For Example

![Screenshot (860)](https://github.com/user-attachments/assets/5871e716-2ae5-45f6-b99f-4210356c41d1)



This YARA rule is designed to detects common phrases typically associated with Ransomware, it also detects the presence of Crypto Wallet Addresses like Bitcoin, Ethereum, Monero, and Litecoin. All of those being key indicators fo ransomware. Any triggers would warrant further investigation. [RULE](https://github.com/karamkamal1/YARA_Rules/blob/58cb7226e1513282fb836efc0c66150fe53840f5/malware_ransomware.yara)

----------------------------------------------------------------------------------------------------
## Script Running With Example Rule

![Screenshot (856)](https://github.com/user-attachments/assets/a6f0a0e0-2da1-42ca-8bc4-6ee6f00f12e0)

This Python Script will allow a user to define a YARA rule they wish to test against a particular file or directory on the system. It will then label the file as PASSED or FAILED based on the YARA rules string matches. [SCRIPT](https://github.com/karamkamal1/YARA_Rules/blob/58cb7226e1513282fb836efc0c66150fe53840f5/YARA_Scan_Script.py)

------------------------------------------------------------------------------------------------

![Screenshot (840)](https://github.com/user-attachments/assets/7c1ef368-7e54-492d-90ef-deb27775acdd)

I open an Administrator Command Prompt and navigate to the directory where my script is located. 

------------------------------------------------------------------------------------------------

![Screenshot (841)](https://github.com/user-attachments/assets/51d5b6c3-e774-4460-803c-de9b82c71bbd)

I run my script.

------------------------------------------------------------------------------------------------

![Screenshot (842)](https://github.com/user-attachments/assets/53f7f65d-ad26-45cc-87a2-2b0b155c7ce7)

It gives me a prompt to enter the YARA Rule I want to use in my scan.

------------------------------------------------------------------------------------------------

![Screenshot (845)](https://github.com/user-attachments/assets/ed662fbd-001a-4233-9d10-943c3bc8c347)

I select the Example YARA Rule, malware_ransomware.yara

------------------------------------------------------------------------------------------------

![Screenshot (846)](https://github.com/user-attachments/assets/0c497eb8-ee9f-44f6-98a2-1dc5b0429fa1)

It now prompts for the path of the file or directory to scan. I will point it towards a directory I have prepared named ytestdynamic.

------------------------------------------------------------------------------------------------

![Screenshot (847)](https://github.com/user-attachments/assets/92803295-0760-4c25-a83e-327664065233)

Once the scan concludes we can see which file/files in the directory matched the criteria of our YARA rule by looking for a FAILED label. In this case the Ytest.txt file failed our scan, the failed scan also includes our Rule name, description of our rule, as well as what version of the rule that was used.

------------------------------------------------------------------------------------------------

![Screenshot (857)](https://github.com/user-attachments/assets/1a9a972b-daad-4d2f-9c7d-4366f138efcd)

Now if I navigate to the Directory of the Ytest.txt file and open it.

------------------------------------------------------------------------------------------------

![Screenshot (858)](https://github.com/user-attachments/assets/420d03bc-781f-43e1-ad7c-10b203a0cf20)

There are two strings in the file that triggered the rule, a wallet address as well as a common phrase used in ransomware. In a real life environment another Yara rule would be run against the file directly with flags to indicate lines and what specifically in the file is triggering the FAILED scan.
