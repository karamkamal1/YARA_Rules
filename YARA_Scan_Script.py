import os
import yara
import colorama
from colorama import Fore, Style

colorama.init()

def scan_file_with_YARA(rule, path): #scan a file with YARA rule
    print(Fore.GREEN + "Scanning file: ", path)
    matches = rule.match(path)

    if matches:
        print(Fore.RED + "FAILED : " ,path + Style.RESET_ALL)
        for match in matches:
            print(Fore.RED + "Rule: ", match.rule , " - " , match.meta) 
    else:
        print(Fore.GREEN + "PASSED : ", path)

def scan_directory_with_YARA(rule, path): #Scan each file in a directory with YARA rule
    print(Fore.GREEN + "Scanning directory: ", path + Style.RESET_ALL)
    for root, _, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            scan_file_with_YARA(rule, file_path)

def main():
    #Main function runs the YARA scanner
    static_rule_path = "C:\\Users\\kkamal\\Desktop\\Rules\\YARA_RULES" #Static Path to folder containing YARA rule
    
    rule_name = input("Enter YARA Rule name : ") # Name for YARA rule file
    rule_file = os.path.join(static_rule_path, rule_name) #Path to YARA rule file
    rule = yara.compile(filepath=rule_file) #Compile YARA rule

    target_path = input("Enter the directory or file to scan: ")#Path to directory or file to scan

    if os.path.isfile(target_path): #checks if target path is a file
        scan_file_with_YARA(rule, target_path)
    elif os.path.isdir(target_path): #checks if target path is a directory
        scan_directory_with_YARA(rule, target_path)
    else:
        print ("Invalid path provided, Please enter a valid path")

if __name__ == "__main__":
    main()