import time

from utils import clear

def smartGenerator():
    '''This function is the main SmartGenerator loop
    '''
    
    
    while True:
        clear()

        # Print Menu
        print("######################")
        print("")
        print("PCS SmartGenerator Menu")
        print("")
        print("1 > ")
        print("2 > ")
        print("3 > ")
        print("0 > Back to MainMenu")
        print("")
        print("######################")
        print("")

        choice = input("Your choice: ")

        # Launch 
        if choice == "1":
            #TODO
            input("Press any key to continue . . .")
        
        # Launch 
        elif choice == "2":
            #TODO
            input("Press any key to continue . . .")

        # Launch 
        elif choice == "3":
            #TODO
            input("Press any key to continue . . .")

        # Exit
        elif choice == "0":
            break

        # Wrong choice
        else:
            clear()
            print("WRONG CHOICE!")
            time.sleep(2)