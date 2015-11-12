from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random


def endefun():

    print "\n","You can encrypt plaintexts which will be written to the ciphertextsandkeys\
.txt file, or decrypt ciphertexts in that file.\n"
    
    ende = raw_input("Do you want to encrypt plaintexts or decrypt ciphertexts?\
    Enter 'e' to encrypt, 'd' to decrypt, 'esc' to quit:\n")


    if ende == "e":
        ciptext = raw_input("Plaintext:\n")
        def getkey():
            key = raw_input("Please enter a 16 (ASCII) character key:\n")
            if len(key) != 16:
                print "You have to enter 16 ASCII characters."
                key = getkey()
            return key
        key = getkey()
        def getmode():
            mode = raw_input("What block cipher mode do you want to use? \
Please enter CBC or CTR:\n")
            if mode.upper() != "CBC" and mode.upper() != "CTR":
                print "You may only enter CBC or CTR."
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
                ciptext = bytearray(ciptext, "ascii") + bytearray([remain]*remain)
                return ciptext
            ciptext = str(padding(ciptext))
            val = iv.encode("hex")
            ciphertext = encryptor.encrypt(ciptext).encode("hex")
            outputkey = key.encode("hex")
            with open("ciphertextsandkeys.txt","a") as f:
                f.write("\n" + "CBC: " + outputkey + ", " + val+ciphertext)
        else:
            counter = Counter.new(128, initial_value=long(iv.encode("hex"),16))
            encryptor = AES.new(key, AES.MODE_CTR, counter = counter)
            val = iv.encode("hex")
            ciphertext = encryptor.encrypt(ciptext).encode("hex")
            outputkey = key.encode("hex")
            with open("ciphertextsandkeys.txt","a") as f:
                f.write("\n" + "CTR: " + outputkey + ", " + val +ciphertext)
            f.close()
        print "Your key and ciphertext have been added to ciphertextsandkeys.txt."

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
            aes = AES.new(ciptriple[0].decode("hex"), AES.MODE_CBC, ciptriple[2].decode("hex"))
            plaintext = aes.decrypt(ciptriple[1].decode("hex"))
            return plaintext

        def decryptCTR(ciptriple):
            #we create a counter here since CTR requires a counter that never repeats so
            #no 2 blocks have the same IV. 
            ctr = Counter.new(128, initial_value=long(ciptriple[2],16))
            aes = AES.new(ciptriple[0].decode("hex"), AES.MODE_CTR, counter=ctr)
            plaintext = aes.decrypt(ciptriple[1].decode("hex"))
            return plaintext

        print "CBC messages:\n"
        i=1
        for ciptriple in CBCtextsandkeys:
            print "Message %s: "% i, decryptCBC(ciptriple)
            i += 1

        print "\n","CTR messages:\n"
        i=1

        for ciptriple in CTRtextsandkeys:
            print "Message %s: "% i, decryptCTR(ciptriple)
            i += 1

        endefun()

    elif ende == "esc":
        print "Quitting..."
        
    else:
        print "Invalid entry. Please enter 'e' or 'd'."
        endefun()

endefun()




