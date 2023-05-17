import sys
import os
import argparse

from PIL import Image
from structures import *


def main():
    '''
    Driver function to encode or decode a digital signature in an image
    
    python3 ./main.py -e tykeson.png
    python3 ./main.py -d tykeson_signed.png

    python3 ./main.py -e EMU.png
    pytnon3 ./main.py -d EMU_signed.png
    
    '''

    # Check input validity
    if(len(sys.argv) < 3):
        print("Error! Input format: main.py -flag filename")
        return

    # Create argument parser object
    parser = argparse.ArgumentParser()

    # Define flags
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', action='store_true', help='Encode digital signature in image')
    group.add_argument('-d', action='store_true', help='Decode encrypted message from digital signature')

    # Add positional argument
    parser.add_argument('image_file', type=str, help='Image file name')

    # Parse command-line arguments
    args = parser.parse_args()

    # Take image input
    image_input = sys.argv[2]

    # Load image
    image_handler = ImageHandler(image_input)
    image_handler.load_image()

    # Encoding flag
    if args.e:

        # Process signature
        signature = "5c80a163f47b0435c3c03ea80e736b8ae30d69b5002d2152c52efc1b3c6afb68aceb776cb929134b700d2e60e0c8532dce5cb755f4f8296ed2a18318f2bb93d3fb3043e4825092213e21773a744207c6b48957c01e9c54ae250026376da19f792e7508e58e789346045600197c15a4bef53b21ede07a5d78e0dcc37244120eb85d836bbb9a1279b1da99a24225942f7b33303462343735643161306435656261396663376533643832313037366338626330663333623831336434323937376133646331393032623634393234636338304b475d1a0d5eba9fc7e3d821076c8bc0f33b813d42977a3dc1902b64924cc8"

        # Load encoder
        encoder = SignatureEncoder(signature, image_handler)

        # Encode encrypted message as digital signature
        encoder.encode_signature()

    # Decoding flag
    elif args.d:

        # Load decoder
        decoder = SignatureDecoder(image_handler)

        # Decode encrypted message from signature
        decoder.decode_signature()


if __name__ == "__main__":
    main()

'''
TODOLIST

    Connect with front-end
        Change fixed signature input to be determined by 

'''