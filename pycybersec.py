import time

from utils import clear
from tools.netscan import netscan


def launcher():
    '''Launcher Menu loop
    '''

    while True:
        # Clear
        clear()

        # Print Menu
        print("######################")
        print("")
        print("PCS Suite - PyCyberSec")
        print("")
        print("1 > PCS NetScan")
        print("0 > EXIT")
        print("")
        print("######################")
        print("")

        choice = input("Your choice: ")

        # Launch PCS netscan
        if choice == "1":
            netscan()

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
