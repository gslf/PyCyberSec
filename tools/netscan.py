import time
import scapy.all as scapy

from utils import clear, standardPorts, saveToFile


def netscan():
    ''' This function is the main netscan loop
    '''

    while True:
        clear()

        # Print Menu
        print("######################")
        print("")
        print("PCS NetScan Menu")
        print("")
        print("1 > SoftScan - Scan net address")
        print("2 > AdavancedScan - address and common ports")
        print("3 > CustomScan - address and common ports")
        print("0 > Back to MainMenu")
        print("")
        print("######################")
        print("")

        choice = input("Your choice: ")

        # Launch PCS SoftSCan
        if choice == "1":
            target = input("Target ip or subnet (xx.xx.xx.xx/yy): ")
            result = softScan(target)
            print(result)

            save_continue = input("\nPress s to save result or any other key to continue ")

            if save_continue == "s" or save_continue == "S":
                saveToFile(result)
        
        # Launch PCS AdvancedScan
        elif choice == "2":
            target = input("Target ip or subnet (xx.xx.xx.xx/yy): ")
            list_flag_string = input("1. for light port list (default - faster) or 2. for full port list (slower): ")
            if list_flag_string == "2":
                list_flag = True
            else:
                list_flag = False

            result = advancedScan(target, list_flag)
            print(result)

            save_continue = input("\nPress s to save result or any other key to continue ")

            if save_continue == "s" or save_continue == "S":
                saveToFile(result)

        # Launch PCS CustomScan
        elif choice == "3":
            try:
                target = input("Target ip or subnet (\"xx.xx.xx.xx/yy\"): ")
                ports_string = input("Target ports (\"22 80 443 ...\") : ")
                ports = list(map(int,ports_string.split()))
                method = input("Method (\"syn\" or \"udp\" or \"xmas\"): ")
                timeout = input("Timeout of port scan (seconds): ")
                result = customScan(target, ports, method, float(timeout))

                print(result)

                save_continue = input("\nPress s to save result or any other key to continue ")

                if save_continue == "s" or save_continue == "S":
                    saveToFile(result)

            except Exception as e:
                print("SCAN ERROR: {}".format(e))
            
            input("Press any key to continue . . .")

        # Exit
        elif choice == "0":
            break

        # Wrong choice
        else:
            clear()
            print("WRONG CHOICE!")
            time.sleep(2)

def _targetIPScan(target_subnet):
    '''A function to scan a target subnet 

    Params:
        target_subnet (String) - XX.XX.XX.XX/YY
    '''
    arp_req_frame = scapy.ARP(pdst = target_subnet)
    broadcast_ether_frame = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame


    ans = scapy.srp(broadcast_ether_arp_req_frame, timeout = 1, verbose = False)[0]
    result = []

    for sent, received in ans:
        result.append({'IP': received.psrc, 'MAC': received.hwsrc})

    return result


def _targetPortScan(target_ip, target_ports, method, timeout=1):
    '''A function to scan ports of a target ip.
    Supported scan methods: "syn" - "udp" - "xmas".
    Supported TCP port status: "unknow", "mute", "open", "closed", "filtered TCP" , "filtered ICMP"
    Supported UDP port status: "unknow", "open", "closed"

    Params
        target_ip (string) - The target IP
        target_ports ([int]) - A list with target ports
        method (string) - Port scsan method. 
    
    Return
        open_ports ([(int,string)]) - A list of tuples with scaned ports with status
    '''

    scanned_ports = []

    ########################################
    # SYN PORT SCAN
    if method == "syn":
        for target_port in target_ports:
            src_port = scapy.RandShort()
            port_status = "mute"

            response = scapy.sr1(scapy.IP(dst=target_ip)/scapy.TCP(sport= src_port, dport=target_port, flags="S"), verbose=False, timeout=timeout)

            if response != None:
                if response.haslayer(scapy.TCP):
                    if response[scapy.TCP].flags == 18:
                        port_status = "open"     
                    elif response[scapy.TCP].flags == 20:
                        port_status = "closed"
                    else:
                        port_status = "filtered TCP"

                elif response.haslayer(scapy.ICMP):
                    port_status = "filtered ICMP"

                else:
                    port_status = "unknow"
            
            else:
                port_status = "mute"

            scanned_ports.append((target_port, port_status))
            port_status = "mute"

        return scanned_ports

    ########################################
    # UPD PORT SCAN
    elif method == "udp":
        for target_port in target_ports:
            port_status = "unknow"

            response = scapy.sr1(scapy.IP(dst=target_ip)/scapy.UDP(dport=target_port), verbose=False, timeout=timeout)

            if response == None:
                port_status = "unknow"
		
            else:
                if response.haslayer(scapy.UDP):
                    port_status = "open"
                else:
                    port_status = "unknown"

            scanned_ports.append((target_port, port_status))
            port_status = "unknown"

        return scanned_ports

    ########################################
    # XMAS PORT SCAN
    elif method == "xmas":
        for target_port in target_ports:
            src_port = scapy.RandShort()
            port_status = "mute"

            response = scapy.sr1(scapy.IP(dst=target_ip)/scapy.TCP(sport= src_port, dport=target_port, flags="FPU"), verbose=False, timeout=timeout)
            
            if response != None:
                if response.haslayer(scapy.TCP):
                    if response[scapy.TCP].flags == 20:
                        port_status = "closed"
                    else:
                        port_status = "muted"
                elif response.haslayer(scapy.ICMP):
                    port_status = "filtered ICMP"
                else:
                    port_status = "unknow"
            else:
                port_status = "filtered"

            scanned_ports.append((target_port, port_status))
            port_status = "unknown"

        return scanned_ports
        

    ########################################
    # WRONG METHOD
    else:
        return None



def softScan(target_subnet):
    '''A function to scan IP of a subnet via ARP.
    This scan only detects IP and MAC addresses within a subnet.

    Params:
        target_subnet (string) - Subnet string "xx.xx.xx.xx./yy"
    '''

    print(">> PCS SoftScan in progress . . .\n")
    scan_result = _targetIPScan(target_subnet)
    result_string = ""
    for item in scan_result:
        result_string += "Client retrieved: \nIP: {} MAC: {}\n".format(item["IP"], item["MAC"])

    return result_string

def advancedScan(target_subnet, full_port_list = False):
    '''A function to scan IP of a subnet via ARP.
    This scan detects IP, MAC addresses and common TCP port status within a subnet.

    Params:
        target_subnet (string) - Subnet string "xx.xx.xx.xx./yy"
        full_port_list (boolean) - Flag to choice full/light port list
    '''

    print(">> PCS AdvancedScan in progress . . .\n")
    scan_result = _targetIPScan(target_subnet)
    standard_ports_list = standardPorts(full_port_list)
    result_string = ""
    for item in scan_result:
        result_string += "Client retrieved: \nIP: {} MAC: {}\n".format(item["IP"], item["MAC"])

        scanned_ports = _targetPortScan(item["IP"], standard_ports_list, "syn")

        for port in scanned_ports:
            if port[1] != "closed":
                result_string += "Port {} is {}\n".format(port[0], port[1])

        result_string += "----\n"

    return result_string
        


def customScan(target_subnet, target_ports=[], method="syn", timeout=1):
    '''A function to scan IP of a subnet via ARP.
    This scan detects IP, MAC addresses and common TCP port status within a subnet.

    Params:
        target_subnet (string) - Subnet string "xx.xx.xx.xx./yy"
    '''

    print(">> PCS CustomScan in progress . . .\n")
    scan_result = _targetIPScan(target_subnet)
    result_string = ""
    
    for item in scan_result:
        result_string += "Client retrieved: \nIP: {} MAC: {}\n".format(item["IP"], item["MAC"])

        scanned_ports = _targetPortScan(item["IP"], target_ports, method)

        for port in scanned_ports:
            if port[1] != "closed":
                result_string += "Port {} is {}\n".format(port[0], port[1])

        result_string += "----"

    return result_string



