"""
Author:             Ian McConachie
Date Created:       05.04.2023
Last Date Modified:	06.06.2023

This file defines the functions necessary for the cryptographic component of
Stegosaurus. See cryptography.md in the docs folder for more detail.
"""

## Global Values

# 16-byte key (In future, we will get from DB)
key = b'0123456701234567'
cons_iv = b'0123456701234567'	# This is like a random seed for CBC mode
# The constant watermark that will be embedded in plaintext onto all imgs
cons_wm = '304b475d1a0d5eba9fc7e3d821076c8bc0f33b813d42977a3dc1902b64924cc8'


## Import Statements

from Crypto.Cipher import AES
#from stegano import lsb
import base64


## Encryption Functions

def AES_setup(key):
	"""
	:inputs:    key     [bytes]
	:returns:   cipher  [AES obj]

	This function sets up an AES cryptosystem after being given the key with
	which to base the symmetric encryption on.
	"""
	cipher = AES.new(key, AES.MODE_CBC, iv=cons_iv) 	# Init AES system (using CBC mode for now)
	return cipher

## Encryption Functions

def AES_encrypt(cipher, data):
	"""
	:inputs:    cipher  [AES obj]
	            data    [bytes]
	:returns:   c_text  [bytes]
	            tag     [bytes]

	This function takes in some data you wish to encrypt (data) and outputs the
	encrypted form of the data by performing encryption with the inputted 
	cipher object.
	"""
	c_text = cipher.encrypt(data)
	c_text = c_text.hex()
	return c_text

def Assemble_msg(cipher, c_data, p_data):
	"""
	:inputs:    cipher  [AES obj]
	            c_data  [bytes]
	            p_data  [bytes]
	:returns:   msg     [str]

	This function takes in the data you want to encypt (c_data), the data you
	want to embed as plaintext (p_data) and a cryptosystem (cipher). With these
	it generates a message to be embedded into an image using steganography.
	"""
	c_text = AES_encrypt(cipher, c_data)
	p_data = p_data.hex()
	msg = c_text + p_data + cons_wm
	return msg

def generate_msg(key, c_data, p_data):
	"""
	:inputs:	key     [bytes]
	            c_data  [bytes]
                  - binary(hash) + binary(username)
	            p_data  [bytes]
	:returns:   msg     [str]

	This is essentially just a function that combines the AES_setup and
	Assemble_msg functions from above into one function for ease of use with
	Flask framework.
	"""
	padding = b'0000000000000000'
	cipher = AES_setup(key)
	msg = Assemble_msg(cipher, c_data, p_data)
	msg = msg + padding.hex()
	return msg


## Decryption Functions

def split_msg(msg):
	"""
	:inputs:    msg        [string]
	:returns:   c_text     [string]
	            p_data     [string]
	            watermark  [string]

	This is a relatively simple function that splits a message into its
	component parts so it can be analyzed.
	"""
	c_text = msg[0:128]      # The first 256 chars are ciphertext
	p_data = msg[128:192]    # The next 128 chars are plaintext 
	watermark = msg[192:256] # The last 128 chars are the constant
	return c_text, p_data, watermark



def AES_decrypt(msg, cipher):
	"""
	:inputs:    cipher     [AES obj]
	:returns:	plaintext  [bytes]

	This function decrypts a cipher text message and returns the plaintext
	in the form of bytes.
	"""
	msg = bytes.fromhex(msg)
	plaintext = cipher.decrypt(msg)
	plaintext = plaintext.hex()
	return plaintext


def interpret_msg(msg, key):
	"""
	:inputs:    msg        [string]
	:returns:	is_steg    [bool]
	            hash_val   [bytes]
	            pt_match   [bool]

	This function takes in a full msg from an image and interprets it in all
	the relevant ways: it sees if the constant watermark is there, it extracts
	the user_id, and it sees if the decrypted section matches the plaintext.
	"""
	is_steg = False
	pt_match = False

	cipher = AES_setup(key)
	#print(len(msg))
	c_text, p_text, watermark = split_msg(msg)

	ct_to_pt = AES_decrypt(c_text, cipher)
	hash_val = bytes.fromhex(ct_to_pt[0:64])
	pt_dcryp = ct_to_pt[64:]


	# Check to see if the constant watermark is there
	if (watermark == cons_wm):
		is_steg = True
	# Check to see if plaintext matches decrypted section
	if (pt_dcryp == p_text):
		pt_match = True

	return is_steg, hash_val, pt_match


## Main Function

def main():
	pass


if __name__ == '__main__':
	main()
