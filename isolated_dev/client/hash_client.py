"""
Author:             Ian McConachie
Date Created:       05.06.2023
Last Date Modified:	05.06.2023

This file contains the scripts necessary for the client side application to
generate hash values from the most significant bits from a sampling of pixels.
"""

## Global Values

test_img = 'test_imgs/720x480.jpg'

## Import Statements

from PIL import Image
import hashlib

## Modular Functions

def gen_pix_num(img_name):
	"""
	:inputs:    img_name  [str]
	:returns:   pix_num   [int]

	This function takes in a reference to an img (a string) and returns
	an integer that is representative of the most significant bit of a sample
	of pixels in the image. 
	"""
	im = Image.open(img_name,'r')
	pixel_vals = list(im.getdata())
	pix_flat = [x for tup in pixel_vals for x in tup]
	pix_str = ""
	i = 0
	for num in pix_flat:
		if ((i % 50) == 0):
			bin_val = (bin(num)[2:]).zfill(8)
			msb = bin_val[0]
			pix_str = pix_str + msb
		i += 1
	pix_num = int(pix_str, base=2)
	return pix_num

def hash_num(pix_num):
	"""
	:inputs:    pix_num   [str]
	:returns:   hash_val  [bytes]

	This function takes in an integer and outputs a hash value generated using
	the SHA256 hash protocol. 
	"""
	pix_bytes = pix_num.to_bytes((pix_num.bit_length()+7)//8, 'big')
	h_algo = hashlib.sha256()
	h_algo.update(pix_bytes)
	hash_val = h_algo.digest()
	return hash_val


def gen_hash(img):
	"""
	:inputs:    img       [str]
	:returns:   hash_val  [str]

	This function essentially combines the gen_pix_num and hash_num functions
	above into one function for easier use in Flask API. 
	"""
	pix_num = gen_pix_num(img)
	hash_val = hash_num(pix_num)
	hash_val = hash_val.hex()
	return hash_val


## Main Function

def main():
	hash_val = gen_hash(test_img)
	print(hash_val)
	return None

if __name__ == '__main__':
	main()