#!/usr/bin/env python3

'''
AES-128-cipher.py: Encrypts and decrypts files using AES-128 in either CBC or CTR mode
'''

import binascii
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random



def endefun():

    print()
    print("You can encrypt plaintexts which will be written to the ciphertextsandkeys\
.txt file, or decrypt ciphertexts in that file.\n")
    
    ende = input("Do you want to encrypt plaintexts or decrypt ciphertexts?\
    Enter 'e' to encrypt, 'd' to decrypt, 'esc' to quit:\n")


    if ende == "e":
        ciptext = input("Plaintext:\n")
        def getkey():
            key = input("Please enter a 16 character key:\n")
            if len(key) != 16:
                print("You have to enter 16 characters.")
                key = getkey()
            return key
        key = getkey()
        def getmode():
            mode = input("What block cipher mode do you want to use? \
Please enter CBC or CTR:\n")
            if mode.upper() != "CBC" and mode.upper() != "CTR":
                print("You may only enter CBC or CTR.")
                mode = getmode()
            return mode
        mode = getmode()
        #we use pycrypto's random number generator here, which is more
        #cryptographically secure than python's own RNG
        iv = Random.get_random_bytes(16)
        
        if mode.upper() == "CBC":
            encryptor = AES.new(key, AES.MODE_CBC, iv)
            def padding(ciptext):
                remain = 16-len(ciptext)%16
                ciptext = bytes(ciptext, 'utf-8') + bytes([remain]*remain)
                return ciptext
            ciptext = padding(ciptext)
            val = binascii.hexlify(iv)
            ciphertext = binascii.hexlify(encryptor.encrypt(ciptext))
            outputkey = binascii.hexlify(bytes(key, 'utf-8'))
            with open("ciphertextsandkeys.txt","a") as f:
                f.write("\n" + "CBC: " + outputkey.decode() + ", " + val.decode() \
                        + ciphertext.decode())
        else:
            counter = Counter.new(128, initial_value=int.from_bytes(binascii.hexlify(iv), \
                                                                    byteorder='big'))
            encryptor = AES.new(key, AES.MODE_CTR, counter = counter)
            val = binascii.hexlify(iv)
            ciphertext = binascii.hexlify(encryptor.encrypt(ciptext))
            outputkey = binascii.hexlify(bytes(key,'utf-8'))
            with open("ciphertextsandkeys.txt","a") as f:
                f.write("\n" + "CTR: " + outputkey.decode() + ", " \
                        + val.decode() +ciphertext.decode())
            f.close()
        print("Your key and ciphertext have been added to ciphertextsandkeys.txt.")

        endefun()
        
    elif ende == "d":

        CBCtextsandkeys = []
        CTRtextsandkeys = []

        f = open("ciphertextsandkeys.txt", "r")
        splitlines = f.read().splitlines()
        for i in range(len(splitlines)):
            if splitlines[i][:3] == "CBC":
                line = [x.strip() for x in splitlines[i].replace(":",",").split(",")]
                line.pop(0)
                #since the 16 byte IV is prepended to the ciphertext, we remove them
                #2 hex digits are 1 byte, so we split off the first 32 hex digits
                #note that the ciphertexts here are a multiple of 16 bytes
                #since that is a requirement for CBC mode, which processes block-by-block
                line.append(line[1][:32])
                line[1] = line[1][32:]
                CBCtextsandkeys.append(line)
            elif splitlines[i][:3] == "CTR":
                line = [x.strip() for x in splitlines[i].replace(":",",").split(",")]
                line.pop(0)
                #similarly, we split the first 32 digits here, but in CTR mode, input
                #ciphertexts can be any length since CTR mode turns AES into a stream cipher
                line.append(line[1][:32])
                line[1] = line[1][32:]
                CTRtextsandkeys.append(line)
            else:
                pass
        f.close()



        def decryptCBC(ciptriple):
            aes = AES.new(binascii.unhexlify(bytes(ciptriple[0],'utf-8')), AES.MODE_CBC, \
                          binascii.unhexlify(bytes(ciptriple[2],'utf-8')))
            plaintext = aes.decrypt(binascii.unhexlify(bytes(ciptriple[1], 'utf-8')))
            return plaintext.decode()

        def decryptCTR(ciptriple):
            #we create a counter here since CTR requires a counter that never repeats so
            #no 2 blocks have the same IV. 
            ctr = Counter.new(128, initial_value=int.from_bytes(bytes(ciptriple[2], 'utf-8'), byteorder = 'big'))
            aes = AES.new(binascii.unhexlify(bytes(ciptriple[0], 'utf-8')),\
                          AES.MODE_CTR, counter=ctr)
            plaintext = aes.decrypt(binascii.unhexlify(bytes(ciptriple[1],'utf-8')))
            return plaintext.decode()

        print("CBC messages:\n")
        i=1
        for ciptriple in CBCtextsandkeys:
            print("Message %s: "% i, decryptCBC(ciptriple))
            i += 1
        print()
        print ("CTR messages:\n")
        i=1

        for ciptriple in CTRtextsandkeys:
            print("Message %s: "% i, decryptCTR(ciptriple))
            i += 1

        endefun()

    elif ende == "esc":
        print("Quitting...")
        
    else:
        print("Invalid entry. Please enter 'e' or 'd'.")
        endefun()

endefun()




