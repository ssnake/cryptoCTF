import sys
import os
import Crypto.Cipher.AES
import pdb
from time import gmtime, strftime
from Crypto.Hash import SHA256
from very_bad_encryptor import AES
import hashlib
import subprocess
sha = SHA256.new()
aes = AES()
def str2hex(txt):
	return ':'.join(x.encode('hex') for x in txt)
def readFile(filename):
	with open(filename) as f:
		data = f.read()
	return data
def logResult(padded_chr, key, decrypted):
	dt = strftime('%Y-%m-%d %H:%M:%S', gmtime())
	res = "%s: key=%s decrypted=%s (%s) \n" % (dt, key, decrypted, str2hex(decrypted))
	print res
	with open('brute_attacker.log', 'a') as f:
		f.write(res)
def getHashKey(key):
	key = str(key)
	#sha.update(key)
	#return  map(ord, sha.digest())
	return map(ord, hashlib.sha256(key).digest())
def decrypt(prev_data, padding_data, hash_key):
    size = 16
    plaintext = [0] * 16
    chrOut = ''
    output = aes.decrypt(padding_data, hash_key, len(hash_key))
    for i in range(16):
        plaintext[i] = prev_data[i] ^ output[i]
    for k in range(size):
        chrOut += (chr(plaintext[k]))
    return chrOut
def bruteForce(start, chunk):
	data = readFile('crack.me.output')
#	data = readFile('1.out')
	
	padding_data = data[-16:]
	prev_data = data[-32:][:16]
	padding_data =  map(ord, padding_data)
	prev_data =  map(ord, prev_data)
	for key in range(start, start+chunk):
		hash_key = getHashKey(key)
		#if key == 123:
			#pdb.set_trace()
		decrypted = decrypt(prev_data, padding_data, hash_key)
		padded_chr = ord(decrypted[-1])
		if padded_chr <= 16 and padded_chr > 1:
			real_pad = True
			for i in range(padded_chr):
				real_pad = real_pad and ord(decrypted[-i-1]) == padded_chr
			if real_pad:
				logResult(padded_chr, key, decrypted)
	
def launch_worker(start, chunk):
	subprocess.Popen('python ./brute_attacker.py %s %s' % (int(start), int(chunk)), shell=True,
             stdin=None, stdout=None, stderr=None, close_fds=True)

if __name__ == "__main__":
	print sys.argv
	if len(sys.argv) > 1:
		start = int(sys.argv[1])
		chunk = int(sys.argv[2])
		print "worker mode: start=%s, chunk=%s" %(start, chunk)
		bruteForce(start, chunk)

	else:
		print "launcher mode"
		threads = 8
		chunk = round(100000000 / threads)
		start = 0
		for i in range(threads):
			launch_worker(int(start), int(chunk))
			
			start += chunk
			#break

