import csv
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

def standardPorts():
    '''Return an array with standard TCP and UPD ports

    Return:
        ports (Array of int)
    '''
    
    # CSV LIST PATH
    WELL_KNOW_PORTS_LIST = "WellKnownPorts.csv"
    common_ports = []

    with open(WELL_KNOW_PORTS_LIST, mode='r') as csv_file:
        csv_reader = csv.DictReader(csv_file, delimiter=';')
        line_count = 0
        

        for row in csv_reader:
            if row["Port"] and len(row["Port"]) > 0:
                common_ports.append(int(row["Port"]))
                
    return common_ports