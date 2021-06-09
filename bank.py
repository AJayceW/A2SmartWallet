#!/usr/bin/python3 
 
# This is version 2.0
 
import sys
from binascii import unhexlify
 
try:
    from Assignment2_AES import AESCrypt
 
except:
    print("[*] Error importing AESCrypt")
    sys.exit(1)
 
def main():
    USERS = {}
    while True:
        while True:
                studentID = input("Please a wallet secret key: ")
 
                try:
                    if len(studentID) == 64:
                        break
 
                    else:
                        raise ValueError
 
                except ValueError:
                    print("\nInvalid student ID. Please try again.\n")
 
        while True:
            try:
                amount = int(input("Please enter the amount of funds to receive: ").replace(",", ""))
 
                if (len(str(amount)) > 7) or (amount < 0):
                    raise Exception
 
            except ValueError:
                print("\nIncorrect amount. Please try again.\n")
 
            except Exception:
                print("\nPlease enter an amount under $9,999,999.\n")
 
            else:
                amountToSend = AESCrypt(unhexlify(studentID), "yes")
                print("The EMD is: %s" % amountToSend.encrypt(hex(amount)).hex())
 
                if studentID in USERS:
                    USERS[studentID] += amount
                    break
                
                else:
                    USERS[studentID] = amount
                    break
 
        e = input("\nWould you like to quit (Y/N)? ")
        
        if e in ('y', 'Y'):
            break
 
if __name__ == "__main__":
    main()