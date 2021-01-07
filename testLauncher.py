import time

from utils import clear
from testing.test_netscan import test_netscan

def launcher():
    '''Test launcher Menu loop
    '''

    while True:
        # Clear
        clear()
        
        # Print Menu
        print("######################")
        print("")
        print("PCS test launcher")
        print("")
        print("1 > Test PCS NetScan")
        print("0 > EXIT")
        print("")
        print("######################")
        print("")

        choice = input("Your choice: ")

        # Launch PCS netscan
        if choice == "1":
            test_netscan()

        # Exit
        elif choice == "0":
            break

        # Wrong choice
        else:
            clear()
            print("WRONG CHOICE!")
            time.sleep(2)
            
        

if __name__ == "__main__":
    launcher()
