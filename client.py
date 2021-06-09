#!/usr/bin/python3 
 
# This is version 2.0
 
import hashlib, sys, re
from binascii import unhexlify
from typing import Final
from base64 import b64decode
from Crypto.Cipher import AES
 
try:
    from Assignment2_AES import AESCrypt
except:
    print("[*] Error importing AESCrypt or Assignment2_Login")
    sys.exit(1)
 
CHAR: Final = 'UTF-8'
KBANK: Final = "F25D58A0E3E4436EC646B58B1C194C6B505AB1CB6B9DE66C894599222F07B893"
WID = ""
SECRET_KEY = ""
 
class FundError(Exception):
    pass
 
class AmountError(Exception):
    pass
 
def generateToken(token, bKey):
    try:
        if len(str(token)) == 32:
            hexAES = AESCrypt(unhexlify(bKey))
            return hexAES.encrypt(str(token)).hex()
 
        else:
            return "lengthBad"
 
    except ValueError:
        return "badValue"
 
def decipherToken(token, bKey):
    try:
        hexAES = AESCrypt(unhexlify(bKey))
        value = hexAES.decrypt(unhexlify(token))
        return [unhexlify(value[0:8]).decode(CHAR), unhexlify(value[8:16]).decode(CHAR), turnToInt(value[16:24]), turnToInt(value[-8:])]
 
    except:
        print("\nThere was an error with the provided token. Returning to main menu.")
        return "error"
 
def createToken(wIDA, wIDB, amount, counter, bankKey):
    token = generateToken("%s%s%s%s" % (str(wIDA).encode(CHAR).hex().zfill(8), str(wIDB).encode(CHAR).hex().zfill(8), hex(amount).zfill(8), hex(counter).zfill(8)), bankKey)
 
    if token in ["lengthBad", "badValue"]:
        print("\nSomething went wrong. Returning to main menu.")
        return "bad"
 
    else:
        return token
 
def turnToInt(h):
    x = h.find("x")
    newString = "0%s" % h[x:]
    return int(newString, 0)
 
def amountToSend(bal):
    while True:
        try:
            if bal == 0:
                raise FundError
 
            a = int(input("\nPlease enter the amount of money you wish to transfer or 0 to return to the main menu: ").replace(",", ""))
 
            if (len(str(a)) > 7) or (a < 0):
                raise AmountError
 
            if bal < a:
                raise FundError
 
            if a == 0:
                print("\nReturning to main menu.")
                return 0
 
            return a
 
        except ValueError:
            print("\nPlease enter an amount using only numbers.")
 
        except FundError:
            print("\nInsufficient funds. Returning to main menu.")
            return 0
 
        except AmountError:
            print("\nPlease enter an amount under $9,999,999.")
 
def emd(bal, secretKey):
    try:
        print("\nYour wallet secret key needed to create an EMD is:", secretKey.getKey())
        e = input("\nPlease enter the EMD provided by the bank: ")
        bal += int(secretKey.decrypt(unhexlify(e)), 0)
        return bal
 
    except:
        print("\nError decrypting EMD. Returning to main menu.")
        return "error"
 
def getBtokenSync(bankKey):
    while True:
        bToken = input("\nPlease enter the token provided by the other party: ")
 
        if bToken in ["q", "Q"]:
            return "break", bToken
 
        bToken = decipherToken(bToken, bankKey)
 
        if "error" == bToken:
            pass
 
        else:
            counter = int(bToken[-1])
 
            if counter == 0:
                counter += 1
            
            return counter, bToken[0], bToken[1]
 
def syncWallets(bankKey, wID):
    walletB = checkID("the wallet ID of the other party", "wID")
    token = createToken(wID, walletB, 0, 0, bankKey)
 
    if token == "bad" or walletB == "quit":
        return "break", 0
 
    else:
        print("\nYour token is: %s" % token)
        return getBtokenSync(bankKey)
 
def getWalletBTransfer(syncedWallets):
    while True:
        walletB = checkID("the wallet ID of the other party", "wID")
 
        if walletB == "quit":
            print("\nReturning to main menu.")
            return "bad"
 
        if walletB not in syncedWallets:
            print("\nThe wallet ID entered is not synced. Please sync your wallet before proceeding.\nReturning to main menu.")
            return "bad"
        
        else:
            return walletB
 
def transferFunds(syncWallets, bal, wID, bankKey):
    try:
        if not bool(syncWallets):
            print("\nThere is currently no synced wallets. Please sync a wallet before proceeding.\nReturning to main menu.")
            raise ValueError
 
        walletB = getWalletBTransfer(syncWallets)
 
        if (walletB == "bad"):
            raise ValueError
 
        amount = amountToSend(bal)
        token = createToken(wID, walletB, amount, syncWallets[walletB], bankKey)
 
        if (token == "bad") or (amount == 0):
            raise ValueError
 
        else:
            newCounter = syncWallets[walletB]
            newCounter += 1
            print("\nYour token is: %s" % token)
            return newCounter, walletB, amount
    except:
        return 0, 0, "bad"
 
def getTokenReceive(bKey):
    while True:
        try:
            token = input("\nPlease enter the token for receiving your funds: ")
 
            if token in ["q", "Q"]:
                print("\nReturning to main menu.")
                return "main"
 
            v = decipherToken(token, bKey)
 
            if v == "error":
                raise TypeError
 
            else:
                return v
 
        except TypeError:
            pass
 
def checkReceive(v, syncedWallets, wID):
    if v[0] in syncedWallets:
        if syncedWallets[v[0]] == v[-1]:
            if v[1] == wID:
                return [v[2], v[0]]
            else:
                return "notMe"
        else:
            return "badCounter"
    else:
        return "notInSync"
 
def receiveFunds(syncedWallets, bKey):
    if not bool(syncedWallets):
        print("\nThere is currently no synced wallets. Please sync a wallent before proceeding.\nReturning to main menu.")
        return "main"
 
    v = getTokenReceive(bKey)
 
    if v in ["main", "error"]:
        return "main"
 
    return v
 
def checkID(AOrB, t=None):
    while True:
        studentID = input("Please enter %s: " % AOrB)
 
        try:
            if not re.match("^[A-Za-z0-9]*$", studentID):
                raise ValueError
 
            if studentID in ["Q", "q"]:
                return "quit"
 
            if t == "wID":
                if len(studentID) == 4:
                    return studentID
 
            else:
                if len(studentID) >= 4:
                    return studentID
 
            raise ValueError
 
        except ValueError:
            print("\nInvalid ID. Please try again or enter Q to return to the main menu.\n")
 
def main():
    studentID = checkID("your student ID")
 
    if studentID == "quit":
        sys.exit(1)
 
    SECRET_KEY: Final = AESCrypt(studentID)
    WID: Final = studentID[-4:]
    SYNCED_WALLETS = {}
    BALANCE = 0
 
    while True:
        choice = input("\nPlease enter an option:\n1. Receive an EMD\n2. Sync Wallet\n3. Transfer Funds\n4. Receive Funds\n5. View your wallet ID and Balance\n6. Quit\n")
 
        try:
            if choice == "1":
                e = emd(BALANCE, SECRET_KEY)
 
                if e == "error":
                    pass
 
                else:
                    BALANCE = e
                    print("\nUpdated your balance. Your current balance is: ${:,}".format(BALANCE))
 
            elif choice == "2":
                print("\nYour wallet ID is:", WID)
                counter, wIDB, me = syncWallets(KBANK, WID)
 
                if counter == "break":
                    print("\nReturning to main menu.")
                    pass
 
                else:
                    if me == WID:
                        SYNCED_WALLETS[wIDB] = counter
                        print("\nYou are now synced with %s" % wIDB)
                    
                    else:
                        print("\nThe receiver's wallet ID does not match your wallet ID.\nReturning to main menu.")
 
            elif choice == '3':
                try:
                    newBCounter, wIDB, newBalance = transferFunds(SYNCED_WALLETS, BALANCE, WID, KBANK)
 
                    if newBalance == "bad":
                        raise ValueError
 
                    BALANCE -= newBalance
                    SYNCED_WALLETS[wIDB] = newBCounter
                
                except:
                    pass
 
            elif choice == '4':
                v = receiveFunds(SYNCED_WALLETS, KBANK)
                
                if v == "main":
                    pass
                
                amount = checkReceive(v, SYNCED_WALLETS, WID)
 
                if amount == "badCounter":
                    print("\nThe number of times transferring to this user is not the same.\nPlease check to see if there are any transfers that have not been received.\nReturning to main menu.")
 
                elif amount == "notInSync":
                    print("\nYour wallet is not in sync with this user.\nPlease sync with this user to deposit the funds.\nReturning to main menu.")
                
                elif amount == "notMe":
                    print("\nYour are not the recipient of this transfer.\nReturning to main menu.")
 
                else:
                    BALANCE += int(amount[0])
                    SYNCED_WALLETS[amount[1]] += 1
                    print("\nThe amount of ${:,} has been added to your balance.\nYour current balance is ${:,}.\nReturning to main menu.".format(amount[0], BALANCE))
 
            elif choice == '5':
                print("\nYour wallet ID is: %s" % WID)
                print("Your balance is: ${:,}".format(BALANCE))
 
            elif choice == "6":
                print("\nQuitting program.")
                break
 
            else:
                raise ValueError
 
        except ValueError:
            print("\nInvalid option. Please try again.")
 
if __name__ == "__main__":
    main()
