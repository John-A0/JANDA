# JANDA - Malware Static Analysis Tool

# Overview
JANDA is a powerful malware static analysis tool designed to provide detailed insights into malicious files. This tool is particularly focused on extracting essential information such as hexadecimal representation, strings, hash values, file extensions, and the ability to check the file on the VirusTotal website for additional analysis.

# Features
1. Hexadecimal Analysis
JANDA allows users to perform a detailed hexadecimal analysis of a given file. This feature is essential for understanding the raw binary content of a file, which can reveal hidden patterns and structures indicative of malicious behavior.
2. Strings Extraction
The tool extracts human-readable strings from the binary file, aiding in the identification of plain text content within the malware. This can be crucial for understanding the purpose and functionality of the malicious file.
3. Hash Calculation
JANDA calculates various hash values (MD5, SHA-1, SHA-256) for the given file. These hash values can be used to uniquely identify the file and compare it with known malware signatures.
4. File Extension Identification
JANDA provides information about the file extension, helping users identify the type of file they are dealing with. Malicious files often attempt to disguise themselves using misleading extensions.
5. VirusTotal Integration
JANDA allows users to check the given file on the VirusTotal website, leveraging their extensive malware database for additional analysis. This feature provides a broader context and helps determine if the file is flagged as malicious by various antivirus engines.

# Installation
To install JANDA, follow these steps:
1. Clone the repository: git clone https://github.com/your-username/janda.git
2. Navigate to the project directory: cd janda
3. Install dependencies: pip install -r requirements.txt
4. Run the tool: python janda.py

# Contributing
Contributions are welcome! If you have ideas for improvements or new features, feel free to open an issue or submit a pull request.

Acknowledgments
JANDA is inspired by the need for a comprehensive static analysis tool for malware researchers.
Special thanks to the open-source community for providing valuable libraries and tools.
Made By: John Ayman and Amr Mousa.
Happy analyzing!
