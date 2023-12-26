import os
import hashlib
import requests


print ( """

         ▄█    ▄████████ ███▄▄▄▄   ████████▄     ▄████████ 
        ███   ███    ███ ███▀▀▀██▄ ███   ▀███   ███    ███ 
        ███   ███    ███ ███   ███ ███    ███   ███    ███ 
        ███   ███    ███ ███   ███ ███    ███   ███    ███ 
        ███ ▀███████████ ███   ███ ███    ███ ▀███████████ 
        ███   ███    ███ ███   ███ ███    ███   ███    ███ 
        ███   ███    ███ ███   ███ ███   ▄███   ███    ███ 
    █▄ ▄███   ███    █▀   ▀█   █▀  ████████▀    ███    █▀  
    ▀▀▀▀▀▀                                                 
>>> LET'S MAKE IT SECURE ...

"""
)

VIRUSTOTAL_API_KEY = 'PUT UR VIRUS TOTAL API KEY HEREEEEEEEEE'    #<----------------

def calculate_hash(file_path):
        with open(file_path, 'rb') as f:
            content = f.read()
            sha256_hash = hashlib.sha256(content).hexdigest()
            return sha256_hash
   


def query_virustotal(file_path):
    print("\nQuerying VirusTotal for additional information:")
    try:
        sha256_hash = calculate_hash(file_path)
        url = f'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': sha256_hash}
        response = requests.get(url, params=params)
        result = response.json()

        if result.get('response_code') == 1:
            print(f"VirusTotal Scan Results for {file_path}:")
            a=0
            m=0
            for scan, result in result['scans'].items():
                x=int(len(scan))
                i=0
                s="-"
                for i in range (30-x):
                    s+="-"
                print(f"{scan}:{s}> {result['result']}")
                a+=1
                if result['result'] != None:
                    m+=1
            prob = (m/a)*100
            print(f"\n\n{m} OUT OF {a} SECURITY VENDORS SAY IT'S MALICIOUS SOFTWARE\nMALICIOUS SOFTWARE --------------------> {prob}%")
        else:
            print("No information available on VirusTotal.")
    except Exception as e:
        print(f"Error querying VirusTotal: {str(e)}")
            

def jmal( file_path):

    if os.path.isfile(file_path):
        hash_value = calculate_hash(file_path)
        print(f"\nFile Hash:---------> {hash_value}\n")
        print("\n*********************************************************************")
        print("**************************** VIRUS TOTAL ****************************")
        print("*********************************************************************\n")
        query_virustotal(file_path)
        
    else:
        print("Invalid file path. Please provide a valid file.")
     
def write_hex(content, file_path):
            
                file_name = os.path.basename(file_path).strip()
                
                with open('hex_'+file_name+'.txt', 'w') as file:
                    file.write(content)
                
                print(f'Hex_File "{file_name}" has created in --> '+file_path)
            

def write_strings(content, file_path):
            
                file_name = os.path.basename(file_path).strip()
                
                with open('str_'+file_name+'.txt', 'w') as file:
                    file.write(content)
                
                print(f'Str_File "{file_name}" has created in --> '+file_path)

def format_text(input_text, max_line_length=30):
    return '\n'.join([input_text[i:i+max_line_length] for i in range(0, len(input_text), max_line_length)])

def file_hex(file_path):
    
        with open(file_path, 'rb') as file:
            content = file.read()
            
            hex_content = content.hex()
            
            write_hex(hex_content, file_path)
            #---------------------------------------------#
            decoded_text = content.decode(errors='replace')
            #print("\nDecoded ASCII Representation:")
            str=format_text(decoded_text)
            write_strings(str,file_path)
            #print(decoded_text)

            #---------------------------------------------#
            _, file_extension = os.path.splitext(file_path)
            print("\nFile Extension:")
            print(file_extension)

    
if __name__ == "__main__":
    
    while True:
        try:
                file_path = input(r'enter file path --> ')
                if file_path=='exit':
                    print('\n----------------- GOOD BYE ----------------\n')
                    break
                file_hex(file_path)
                jmal(file_path)
                print('if you want to terminat enter "exit"')
        except FileNotFoundError:
            print(f"Error: File not found - {file_path}")
        
        except Exception as e:
            print(f"An error occurred: {e}")

