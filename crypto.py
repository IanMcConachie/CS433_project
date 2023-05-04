"""
Author:             Ian McConachie
Date Created:       05.04.2023
Last Date Modified:	05.04.2023

This file defines the functions necessary for the cryptographic component of
Stegosaurus. See cryptography.md in the docs folder for more detail.
"""

## Global Values

# 16-byte key (In future, we will get from DB)
key = b'0123456701234567'
# The constant watermark that will be embedded in plaintext onto all imgs
cons_wm = 'stegosaurus'


## Import Statements

from Crypto.Cipher import AES


## Helper Functions

def AES_setup(key):
	"""
	:inputs:    key     [bytes]
	:returns:   AES     [AES obj]
	            nonce   [bytes]

	This function sets up an AES cryptosystem after being given the key with
	which to base the symmetric encryption on.
	"""
	cipher = AES.new(key, AES.MODE_EAX) 	# Init AES system
	nonce = cipher.nonce		# nonce = number used once
	return cipher, nonce

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
	c_text, tag = cipher.encrypt_and_digest(data)
	c_text = c_text.hex()
	tag = tag.hex()
	return c_text, tag	

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
	c_text, tag = AES_encrypt(cipher, c_data)
	p_data = p_data.hex()
	msg = c_text + tag + p_data + cons_wm		# do we need to include the tag here?
	return msg


## Main Function

def main():
	cipher, nonce = AES_setup(key)
	c_data = b'test_cipher_data'
	p_data = b'test_plain_data'
	msg = Assemble_msg(cipher, c_data, p_data)
	return msg
	


if __name__ == '__main__':
	main()
