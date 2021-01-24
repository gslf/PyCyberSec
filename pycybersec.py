import time

from utils import clear
from tools.netscan import netscan
from tools.smartGenerator import smartGenerator


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
        print("1 > NetScan")
        print("2 > SmartGenerator")
        print("0 > EXIT")
        print("")
        print("######################")
        print("")

        choice = input("Your choice: ")

        # Launch PCS NetScan
        if choice == "1":
            netscan()

        # Launch PCS SmartGenerator
        if choice == "2":
            smartGenerator()

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
