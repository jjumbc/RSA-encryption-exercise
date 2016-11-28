#Justus Jackson
#CMSC 443 - Fall 2016
#HW6/Project 1
#RSA

from random import randint,getrandbits
from os import remove
from sys import argv
from time import time

#extended euclidean algorithm for GCD
#returns a triple with GCD and the bezout coefficients
def eGCD(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = eGCD(b % a, a)
        return (g, x - (b // a) * y, y)

#modular inverse
#takes in a number and modulo and calculates extended euclidean GCD to find inverse
def modInv(a, m):
    g, x, y = eGCD(a, m)
    if g != 1:
        return False
    else:
        return x % m

#modular exponentiation
#takes in a base, exponent, and modulo and returns the result base^exp mod modulo
#Note: Python actually has a built-in function for this [pow],
#but I already wrote my own version so why not use it
def modExp(b,ex,mod):
    result = 1
    while ex > 0:
        if not ex & 1:
            b = (b * b) % mod
            ex = ex / 2
        else:
            result = (b * result) % mod
            ex = ex - 1
    return result

#512-bit pseudoprime number generator
#generates 512 bit random number and checks primality with Miller-Rabin 10 times
#returns false if not prime or returns the pseudoprime number
def getPrime():
	n = getrandbits(512)
	if not n & 1:
		n += 1
	for i in range(10):
		if not millerRabin(n):
			return False
	return n

#Miller-Rabin Algorithm for checking primality
#Returns true if pseudoprime, false if not
def millerRabin(n):
	s = n - 1
	t = 0
	a = randint(2,n-1)
	while not s & 1:
		s = s // 2
		t += 1
	z = modExp(a,s,n)
	if z != 1:
		i = 0
		while z != (n - 1):
			if i == (t - 1):
				return False
			else:
				i += 1
				z = modExp(z,2,n)
	return True

#Gets p and q, to give phi and 'n' [modulo]
#Using 'b' [exponent] = 65537, generates 'a' [private key]
#Outputs results to terminal and to file for submission
#Took 77 tries to get p, 50 to get q for submitted key
#(took 0.47 seconds)
#Added command line args for generating, encrypting, and decrypting messages
def main():

	if len(argv) not in [2,3] or argv[1] not in ['generate','encrypt','decrypt']:
		print 'Usage: python jackson.py [option] [filename(optional)]'
		print 'Default filename = \'encrypted.txt\''
		print 'generate: Generate new set of keys'
		print 'encrypt: Encrypt a message'
		print 'decrypt: Decrypt a message'
		return 1
	
	#Generate key set
	if argv[1].lower() == 'generate':	
	
		print '\nWarning: This will overwrite key files in this directory.'
		choice = raw_input('Are you sure you want to continue? (Y/N) ')
		if choice.lower() not in ['yes','y','no','n'] or choice.lower() in ['no','n']:
			return 1
		
		start = time()
		p = getPrime()
		q = getPrime()
		#DEBUG#cp = 0
		#DEBUG#cq = 0

		while not p:
			p = getPrime()
			#DEBUG#cp += 1
			
		while not q:
			q = getPrime()
			#DEBUG#cq += 1

		end = time()
		
		phi = (p-1) * (q-1)
		n = p*q

		#Choosing b = 65537 primarily because it is much faster than finding
		#a random <512 bit coprime of phi. 65537 is also a known prime, and large enough
		#to avoid some RSA issues with small exponent values. It is also a Fermat
		#prime [2^2^k + 1] which offers improved performance over other prime numbers.
		b = 65537
		a = modInv(b,phi)

		print 'n =',n
		print 'b =',b
		print 'a =',a
		#DEBUG#print 'tries to get a p =',cp
		#DEBUG#print 'tries to get a q =',cq
		print 'Took %.3f seconds' % (end - start)

		out = open('jackson_key.txt','w')
		private = open('private.txt','w')
		out.write(str(n))
		out.write('\n')
		out.write(str(b))
		out.close()
		private.write(str(n))
		private.write('\n')
		private.write(str(a))
		private.close()
		
	#Encryption
	#Converts plaintext to a single number with the encoding described
	#in Exercise 5.12 then encrypts it via RSA with the generated
	#public key set
	if argv[1].lower() == 'encrypt':
		try:
			modulo,exp = open('jackson_key.txt','r').read().splitlines()
			modulo = int(modulo)
			exp = int(exp)
		except IOError:
			print 'You need to generate keys first!'
			return 1
		except ValueError:
			print 'Your key file is invalid!'
			return 1
		
		message = raw_input("Input your message: ")
		if len(message) == 0:
			print 'Please enter a message!'
			return 1
		message = ''.join([i for i in message if i.isalpha()])

		temp = 0
		for i,c in enumerate(message):
			temp += (ord(c) - 97) * (26 ** (len(message) - (i + 1)))
		
		cipher = modExp(temp,exp,modulo)
		
		if len(argv) == 3:
			file = argv[2]
		else:
			file = 'encrypted.txt'
			
		output = open(file,'w')
		output.write(str(cipher))
	
	#Decryption
	#Performs RSA decryption on a ciphertext and then decodes via the method
	#described in Exercise 5.12
	if argv[1].lower() == 'decrypt':
		
		if len(argv) == 3:
			file = argv[2]
		else:
			file = 'encrypted.txt'
			
		try:
			encrypted = open(file,'r').read()
			encrypted = int(encrypted)
		except IOError:
			print 'File not found!'
			return 1

		try:
			key = open('private.txt','r').read()
			key = int(key)
		except IOError:
			print 'You do not have a key file!'
			return 1
		except ValueError:
			print 'Your key file is invalid!'
			return 1

		try:
			modulo,exp = open('jackson_key.txt','r').read().splitlines()
			modulo = int(modulo)
		except IOError:
			print 'You need to generate keys first!'
			return 1
		except ValueError:
			print 'Your key file is invalid!'
			return 1
		
		x = modExp(encrypted,key,modulo)
		result = ''
		while x:
			x,c = divmod(x,26)
			result = chr(c+97) + result
			
		print 'Decrypted message:', result
		decrypted = open('jackson_xstr.txt','w')
		decrypted.write(result)
		decrypted.close()

#Run program		
main()