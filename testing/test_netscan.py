from tools.netscan import _targetIPScan
from tools.netscan import _targetPortScan
from tools.netscan import softScan

def test_netscan():

    target_ip = "192.168.1.1"
    target_subnet = "192.168.1.0/24"
    target_ports = [80,22]


    print(">>>>>>>")
    print ("Test internal function _targetIPScan")
    result = _targetIPScan(target_subnet)
    print(result)
    input("Press any key to continue . . .")

    print(">>>>>>>")
    print ("Test internal function _targetPortScan - SYN")
    result = _targetPortScan(target_ip, target_ports, "syn")
    print(result)
    input("Press any key to continue . . .")

    print(">>>>>>>")
    print ("Test internal function _targetPortScan - UDP")
    result = _targetPortScan(target_ip, target_ports, "udp")
    print(result)
    input("Press any key to continue . . .")
    
    print(">>>>>>>")
    print ("Test internal function _targetPortScan - XMAS")
    result = _targetPortScan(target_ip, target_ports, "xmas")
    print(result)
    input("Press any key to continue . . .")
    
    print(">>>>>>>")
    print("Test SoftScan")
    softScan(target_subnet)
    input("Press any key to continue . . .")

    print(">>>>>>>")
    print("Test AdvancedScan")
    softScan(target_subnet)
    input("Press any key to continue . . .")
