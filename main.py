import time


from Crypto.Random import get_random_bytes

import hashlib
from bcrypt import *
import nltk
from nltk.corpus import words

nltk.download('words')


def hamming_distance(x, y):
  return bin(x ^ y).count('1')

def task1():

    string1 = b'afxff'
    string2 = b'afzff'

    print(hashlib.sha256(string1).digest())
    print(hashlib.sha256(string2).digest())
    print(hamming_distance(int.from_bytes(string1, 'big'), int.from_bytes(string2, 'big')))


    seen = { }
    start_time = time.time()

    while True:
        string = get_random_bytes(16)
        hash = hashlib.sha256(string).digest()
        hash = hex(int.from_bytes(hash, 'big'))[:10]

        if hash in seen and seen.get(hash) != string:
            print(int(hash, 16).bit_length())
            print(hash)
            print(string)
            print(seen.get(hash))
            print("--- %s seconds ---" % (time.time() - start_time))
            return
        seen[hash] = string


task1()


def task2():
    file = open('hashes', 'r')

    # hashpw(<plaintext word>, <29-char salt for bcrypt>)

    plaintext = words.words()
    start_time = time.time()

    for i in file:
        line = i.strip().split(':')
        for text in plaintext:
            if checkpw(text.encode('utf-8'), line[1].encode('utf-8')):
                print(line[1].encode('utf-8'))
                print(text)
    print("--- %s seconds ---" % (time.time() - start_time))

task2()