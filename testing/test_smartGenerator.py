from tools.smartGenerator import *

def test_SmartGenerator():
    
    print(">>>>>>>>>>>>>>>>>>>>")
    print("Test Smart Generator")

    print("\n>>>>>>>")
    print ("Test fake person gen \n")
    result = genFakePerson('exxxxS', 'M')
    print(result)
    input("Press any key to continue . . .")

    print("\n>>>>>>>")
    print ("Test fake Bank Account \n")
    result = genBankInfo('en_US')
    print(result)
    input("Press any key to continue . . .")

    print("\n>>>>>>>")
    print ("Test fake WebIdentity \n")
    result = genWebIdentity('en_US')
    print(result)
    input("Press any key to continue . . .")