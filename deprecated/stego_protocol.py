"""
Author: 			Ian McConachie
Date Created: 		04.19.2023
Last Date Modified:	04.19.2023

This file contains a python script that outlines a basic functionality of the
Stegosaurus Protocol for embedding digital signatures invisibly into images.
Currently it can take any string message (test_msg in the main function) and
embed it as the digital signature.

This script and the demonstration done in the main function serve as a proof
of concept for this technique.
"""

## Import Statements

from stegano import lsb
import rsa

## Modular Functions

def create_msg(pt_msg, pu_key):
	"""
		:Inputs: 	pt_msg 		[string]
					pu_key 		[bytes]
		:returns:	full_msg	[bytes]
					pt_len		[int]

	This function takes in a plaintext message and a public key that will be
	used to encrypt it. It then returns a message which is the cipher
	message with the plaintext message appended on the end. Along with this
	it returns the length of the plaintext message in bytes which will be used
	later to separate the cipher from the plaintext.
	"""
	byte_msg = pt_msg.encode('utf8')
	pt_len = len(byte_msg)
	en_msg = rsa.encrypt(byte_msg, pu_key)
	full_msg = en_msg + byte_msg
	return (full_msg, pt_len)


def gen_wm_img(img, new_img, full_msg):
	"""
		:Inputs: 	img 		[string]
					new_img 	[string]
					full_msg	[bytes]
		:returns:	None

	This function takes the name of an image that you want to watermark (img),
	the message you want to include in the watermark, and then saves the
	watermarked image under a given name (new_img).
	"""
	str_msg = full_msg.hex()
	secret = lsb.hide(img, str_msg)
	secret.save(new_img)


def verify_img(wm_img, pr_key, pt_len):
	"""
		:Inputs: 	wm_img 		[string]
					pr_key		[bytes]
					pt_len		[int]
		:returns:	verified	[bool]
					pt_msg		[string]

	This function takes in a watermarked image (wm_img) and extracts both the
	cipher text and plain text using pt_len. It then decrypts the cipher text
	using an RSA private key (pr_key) and checks to see if the decrypted
	message matches the plain text. If they match then the image is verified
	and the verified bool is returned as True, otherwise it is False. Along
	with the verification result the plain text message is outputted for
	convenience.	
	"""
	msg = lsb.reveal(wm_img)
	byte_msg = bytes.fromhex(msg)
	decrypted = (rsa.decrypt(byte_msg[:-pt_len], pr_key)).decode('utf8')
	pt_msg = (byte_msg[-pt_len:]).decode('utf8')
	verified = (pt_msg == decrypted)
	return (verified, pt_msg)


## Main Function

def main():
	test_msg = "Hello, World!"
	og_img = "test_imgs/cat.png"
	new_img = "test_imgs/cat-secret.png"

	pu_key, pr_key = rsa.newkeys(1024)

	ret = create_msg(test_msg, pu_key)
	full_msg = ret[0]; pt_len = ret[1]

	gen_wm_img(og_img, new_img, full_msg)

	ret = verify_img(new_img, pr_key, pt_len)
	print(ret)


if __name__ == '__main__':
	main()