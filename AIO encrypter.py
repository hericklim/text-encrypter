import os
from Crypto.Cipher import PKCS1_OAEP
import binascii
from Crypto.PublicKey import RSA
import time
from pathlib import Path
import sys
import os.path
from os import path

def main():
    #defines the path to the keys
    my_file = Path('private_key.pem')

    #checks if the keys already exists
    try:
        my_abs_path = my_file.resolve(strict=True)

#generates the keys in case the file doesn´t already exists
    except FileNotFoundError:
        passcode = input('define a passcode for the private key: ')

        def export_private_key(private_key, filename):
            with open(filename, 'wb') as file:
                file.write(private_key.exportKey('PEM', passcode))
                file.close()

        def export_public_key(public_key1, filename):
            with open(filename, 'wb') as file:
                file.write(public_key1.exportKey('PEM'))
                file.close

        keypair = RSA.generate(2048)
        public_key = keypair.publickey()

        export_private_key(keypair, 'private_key.pem')
        export_public_key(public_key, 'public_key.pem')

    #in case they are already there, this happens
    else:
        time.sleep(1)
        print('you already have your keys')

    def import_public_key(filename):
        with open(filename, 'rb') as file:
            public_key1 = RSA.import_key(file.read())

        return public_key1
    
    public_key = import_public_key('public_key.pem')
    
    time.sleep(1)

    enc_or_dec = input('do you want to encrypt or decrypt your files? (answer with "enc" or "dec"): ')

    #encrypt file ////////////////////////////////////////
    if enc_or_dec == 'enc':
        time.sleep(1)
        encpath = input("insert your file's path, for instance, D:/test.txt.: ")
        tof = str(path.exists(encpath))
        if tof == 'True':
            print('file exists')
        else:
            print("file doesn't exists")
            time.sleep(1)
            return main()
        with open(encpath, 'rb') as originalfile:
            original = originalfile.read()

        encryptor = PKCS1_OAEP.new(public_key)
        encrypted = encryptor.encrypt(original)
        towrite = binascii.hexlify(encrypted)

        g = input('what would you want to name the file? (example: something.txt): ')

        with open(g, 'wb') as enc_file:
            enc_file.write(towrite)
        time.sleep(2)
        y = input('do you want to do something else? Y/N: ')
        if y == 'Y':
            time.sleep(1)
            return main()
        else:
            time.sleep(1)
            print('k, see ya bud')
            time.sleep(2)
            sys.exit()
    #decrypt file //////////////////////////////////////////////////////
    if enc_or_dec == 'dec':
        time.sleep(1)
        def import_private_key(filename):
            passcode2 = input("insert your private key's passcode: ")
            with open(filename, 'rb') as file:
                private_key = RSA.import_key(file.read(), passcode2)
        
            return private_key

        keypair = import_private_key('private_key.pem')
        
        decpath = input("insert your file's path, for instance, D:/test.txt.: ")
        tofd = str(path.exists(decpath))
        if tofd == 'True':
            print('file exists')
        else:
            print("file doesn't exists")
            time.sleep(1)
            return main()
        
        with open(decpath, 'rb') as somefile:
            newfile = somefile.read()
        
        todecrypt = binascii.unhexlify(newfile)
        
        decryptor = PKCS1_OAEP.new(keypair)
        decrypted = decryptor.decrypt(todecrypt)
        decrypted = repr(decrypted)

        n = input('what would you want to name the file? (example: something.txt): ')

        with open(n, 'w') as dec_file:
            dec_file.write(decrypted)
        
        time.sleep(2)
        a = input('do you want to do something else? Y/N: ')
        if a == 'Y':
            time.sleep(1)
            return main()
        else:
            time.sleep(1)
            print('k, see ya bud')
            time.sleep(2)
            sys.exit()
    else:
        print('I doubt you would want to: ', enc_or_dec, ", whatever that means")
        time.sleep(2)
        return main()




main()





