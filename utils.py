import csv, json
from os import system, name 

def clear(): 
    ''' Clear the CLI
    '''
  
    # Windows clear
    if name == 'nt': 
        _ = system('cls') 
  
    # *nix clear
    else: 
        _ = system('clear')

def standardPorts(full_version = False):
    '''Return an array with standard TCP and UPD ports

    Params
        full_version (boolean) - Full list flag

    Return:
        ports (Array of int)
    '''
    
    # CSV LIST PATH
    if full_version:
        WELL_KNOW_PORTS_LIST = "WellKnownPortsFULL.csv"
    else:
        WELL_KNOW_PORTS_LIST = "WellKnownPortsLIGHT.csv"
        
    common_ports = []

    with open(WELL_KNOW_PORTS_LIST, mode='r') as csv_file:
        csv_reader = csv.DictReader(csv_file, delimiter=';')
        line_count = 0
        

        for row in csv_reader:
            if row["Port"] and len(row["Port"]) > 0:
                common_ports.append(int(row["Port"]))
                
    return common_ports


def saveToFile(data):
    filename = input("File name: ")
    with open(filename, 'w') as f:
        json.dump(data, f)
        print("Result saved on {}\n".format(filename))
