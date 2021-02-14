import time
from faker import Faker
from faker_vehicle import VehicleProvider
from faker_web import WebProvider
from faker_wifi_essid import WifiESSID

from utils import clear, saveToFile


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
        print("1 > Fake Person")
        print("2 > Fake Bank Information")
        print("3 > Fake Web Identity")
        print("0 > Back to MainMenu")
        print("")
        print("######################")
        print("")

        choice = input("Your choice: ")

        # Launch Fake Person Generator
        try:
            if choice == "1":
                print("\n> Fake identity generator")
                
                locale = input("Locale in RFC5646 standard (e.g. en-US):")
                sex = input("Sex ('M', 'F' or ''): ")
                print("")

                result = genFakePerson(locale, sex)
                formatted_result = "{}\n{}\nCurrent location: {} {}\nJob: {} for '{}'\nBirthdate: {} - SSN: {} - Blood group: {}\nEmail: {}\nDrive a {}".format(result['name'], 
                    result['address'],
                    result['current_location'][0], result['current_location'][1],
                    result['job'], result['company'],
                    result['birthdate'], result['ssn'], result['blood_group'],
                    result['mail'],
                    result['veichle'])

                print(formatted_result)
                save_continue = input("\nPress s to save result or any other key to continue . . .")

                if save_continue == "s" or save_continue == "S":
                    saveToFile(result)
                
            
            # Launch Fake Credit Card Number Generator
            elif choice == "2":
                print("\n> Fake Bank Information")
                
                locale = input("Locale in RFC5646 standard (e.g. en-US):")
                print()

                result = genBankInfo(locale)
                formatted_result = "IBAN: {}\nSWIFT: {}\nCC: {} {} CVC: {}".format(
                    result['iban'],
                    result['swift'],
                    result['cc'], result['cc_expire'], result['cc_sec_code']
                )

                print(formatted_result)
                save_continue = input("\nPress s to save result or any other key to continue . . .")

                if save_continue == "s" or save_continue == "S":
                    saveToFile(result)

            # Launch Fake Web Identity Generator
            elif choice == "3":
                print("\n> Fake Web Identity")
                
                result = genWebIdentity()
                formatted_result = "SSID: {}\nServer Token: {}\nContent-type: {}".format(
                    result['ssid'],
                    result['server_token'],
                    result['content_type'])

                print(formatted_result)
                save_continue = input("\nPress s to save result or any other key to continue . . .")

                if save_continue == "s" or save_continue == "S":
                    saveToFile(result)

            # Exit
            elif choice == "0":
                break

            # Wrong choice
            else:
                clear()
                print("WRONG CHOICE!")
                time.sleep(2)

        except Exception as excptn:
                print("Error {}".format(excptn))
                input("\nPress any key to continue . . .")



def genFakePerson(locale = 'en-US', sex = None):
    '''Generate a fake profile

    Params: 
        locale (string) -  e.g. en-US (optional)
        sex (string) - "M" or "F" (optional)

    Return:
        datas {dict} 
    '''


    fake = Faker(locale)
    fake.add_provider(VehicleProvider)
    result = fake.profile()
    result['veichle'] = fake.vehicle_year_make_model_cat()
    
    return result
    



def genBankInfo(locale = 'en-US'):
    '''Generate bank information

    Params: 
        locale (string) -  e.g. en-US (optional)

    Return:
        datas {dict} - iban, swift, cc, cc_expire, cc_sec_code
    '''

    fake = Faker(locale)

    datas = {
        'iban': fake.iban(),
        'swift': fake.swift(),
        'cc': fake.credit_card_number('visa16'),
        'cc_expire': fake.credit_card_expire(),
        'cc_sec_code': fake.credit_card_security_code()
    }

    return datas


def genWebIdentity():
    '''Generate a fake web identity

    Return:
        datas {dict} - ssid, content_type, server_token
    '''

    fake = Faker()
    fake.add_provider(WebProvider)
    fake.add_provider(WifiESSID)

    datas = {
        'ssid': fake.wifi_essid(),
        'content_type': fake.content_type_popular(),
        'server_token': fake.server_token()
    }

    return datas


