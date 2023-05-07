"""
Author:             Ian McConachie
Date Created:       05.04.2023
Last Date Modified:	05.06.2023

This file defines the functions necessary for the cryptographic component of
Stegosaurus. See cryptography.md in the docs folder for more detail.
"""

## Global Values

# 16-byte key (In future, we will get from DB)
key = b'0123456701234567'
# The constant watermark that will be embedded in plaintext onto all imgs
cons_wm = '304b475d1a0d5eba9fc7e3d821076c8bc0f33b813d42977a3dc1902b64924cc8'


## Import Statements

from Crypto.Cipher import AES


## Modular Functions

def AES_setup(key):
	"""
	:inputs:    key     [bytes]
	:returns:   AES     [AES obj]
	            nonce   [bytes]

	This function sets up an AES cryptosystem after being given the key with
	which to base the symmetric encryption on.
	"""
	cipher = AES.new(key, AES.MODE_EAX) 	# Init AES system
	num_once = cipher.nonce		            # nonce = number used once
	return cipher, num_once

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

def generate_msg(key, c_data, p_data):
	"""
	:inputs:	key     [bytes]
	            c_data  [bytes]
	            p_data  [bytes]
	:returns:   msg     [str]

	This is essentially just a function that combines the AES_setup and
	Assemble_msg functions from above into one function for ease of use with
	Flask framework.
	"""
	cipher, num_once = AES_setup(key)
	msg = Assemble_msg(cipher, c_data, p_data)
	return msg


## Main Function

def main():
	c_data = b'304b475d1a0d5eba9fc7e3d821076c8bc0f33b813d42977a3dc1902b64924cc8304b475d1a0d5eba9fc7e3d821076c8bc0f33b813d42977a3dc1902b64924cc8'
	p_data = b'304b475d1a0d5eba9fc7e3d821076c8bc0f33b813d42977a3dc1902b64924cc8'
	msg = generate_msg(key, c_data, p_data)
	print(msg)
	return msg


if __name__ == '__main__':
	main()
