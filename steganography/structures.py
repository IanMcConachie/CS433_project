import os
from PIL import Image, ImageShow

class ImageHandler:
    def __init__(self, image_file):
        self.image_file = image_file
        self.image = None
        new_image_path = None

    def load_image(self):
        # Code to load image from file
        try:
            self.image = Image.open(self.image_file)
        except IOError:
            print("Unable to load image file")
        # pass

    def save_image(self, new_image_path):
        try:
            self.image.save(new_image_path)
        except IOError:
            print("Unable to save image")

    def process_image(self):
        # Process the image here
        pass

    def display_image(self):
        try:
            ImageShow.show(self.image)
        except OSError:
            print("Unable to display image")

class SignatureEncoder:
    def __init__(self, signature, img):
        self.signature = signature
        self.img = img

    def encode_signature(self):
        # Code for encoding the digital signature into the image

        # Load image pixel values
        pixels = self.img.image.load()

        # Get image dimensions
        imageWidth = self.img.image.width
        imageHeight = self.img.image.height

        # Get modified pixel distance
        widthStep = imageWidth // 40
        heightStep = imageHeight // 32

        # Define distance buffer
        widthBuff = imageWidth // 64
        heightBuff= imageHeight // 61

        # Convert message into binary
        binary_list = [bin(ord(char))[2:].zfill(8) for char in self.signature]
        messageBin = ''.join(binary_list)
        # print(messageBin)
        # print(binary_list)

        # Set binary increment
        binCount = 0

        # Color select pixels white
        for i in range(40):
            for j in range(32):
                r = pixels[(i * widthStep) + widthBuff, j * heightStep + heightBuff][0]
                g = pixels[(i * widthStep) + widthBuff, j * heightStep + heightBuff][1]
                b = pixels[(i * widthStep) + widthBuff, j * heightStep + heightBuff][2]

                # If pixel r is even and bin is odd
                if r % 2 == 0 and messageBin[binCount] == '1':
                    r += 1
                
                # If pixel r is odd and bin is even
                elif r % 2 == 1 and messageBin[binCount] == '0':
                    r -= 1

                binCount += 1
                # If pixel g is even and bin is odd
                if g % 2 == 0 and messageBin[binCount] == '1':
                    g += 1
                
                # If pixel g is odd and bin is even
                elif g % 2 == 1 and messageBin[binCount] == '0':
                    g -= 1

                binCount += 1

                if (binCount + 1) % 9 != 0:
                    # If pixel b is even and bin is odd
                    if b % 2 == 0 and messageBin[binCount] == '1':
                        b += 1
                
                    # If pixel b is odd and bin is even
                    elif b % 2 == 1 and messageBin[binCount] == '0':
                        b -= 1
                    
                    binCount += 1

                pixels[(i * widthStep) + widthBuff, j * heightStep + heightBuff] = (r, g, b)

        # Save the modified image
        self.img.save_image("modified_image.jpg")

        # pass


class SignatureDecoder:
    def __init__(self, encoded_img):
        self.encoded_img = encoded_img

    def decode_signature(self):
        # Code for decoding the digital signature from the image
        # Get pixel values
        pixels = self.encoded_img.image.load()

        # Get image dimensions
        imageWidth = self.encoded_img.image.width
        imageHeight = self.encoded_img.image.height

        # Get modified pixel distance
        widthStep = imageWidth // 40
        heightStep = imageHeight // 32

        # Define distance buffer
        widthBuff = imageWidth // 64
        heightBuff= imageHeight // 61

        # Declare msg string

        decodedBinMsg = ''

        for i in range(40):
            for j in range(32):
                r = pixels[(i * widthStep) + widthBuff, j * heightStep + heightBuff][0]
                g = pixels[(i * widthStep) + widthBuff, j * heightStep + heightBuff][1]
                b = pixels[(i * widthStep) + widthBuff, j * heightStep + heightBuff][2]

                decodedBinMsg += '0' if r % 2 == 0 else '1'
                decodedBinMsg += '0' if g % 2 == 0 else '1'
                decodedBinMsg += '0' if b % 2 == 0 else '1'

        print("doy")
        # print(decodedBinMsg)

        dividedBin = [decodedBinMsg[i:i+8] for i in range(0, len(decodedBinMsg), 8)]
        # print(dividedBin)

        # Convert signature into message
        text = ''.join([chr(int(binary, 2)) for binary in dividedBin])
        # print(text)
        # if text == self.signature:
        #     print("DOY")
        # else:
        #     print("NOOO")

        
        # print(dividedBin)

        pass


class CryptographyHandler:
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key

    def generate_keys(self):
        # Code to generate cryptographic keys
        pass

    def encrypt_data(self):
        # Code for encrypting data
        pass

    def decrypt_data(self):
        # Code for decrypting data
        pass

    def verify_signature(self):
        # Code for verifying the integrity of the digital signature
        pass


class FileHandler:
    def read_file(self, file_path):
        # Code to read data from a file
        pass

    def write_file(self, data, file_path):
        # Code to write data to a file
        pass


class UserInterface:
    def get_signature(self):
        # Code to get the digital signature from the user
        pass

    def select_image(self):
        # Code to select an image
        pass

    def display_results(self):
        # Code to display the results of the embedding and decoding processes
        pass


'''
TODOLIST

    Determine change of pixel RGB based on encrypted key
        +/-1 to RGB value, ex) 3R 2B 3G : ++(*(+1))*-*/+, create case for if original RGB value is 0/255
        Decoding will be difficult; server only receiving pixels
            server can take sent pixel, take its +/-1 of RGB, and perform check on altered to see if match possible

        alt: 1 pixel RGB per char of key, therefore need 128/3 pixels = 42 + 2/3 pixels rather than 16
            more straightforward to encode, simpler to decode
                simple = more vulnerable, but easier to implement
                    easier > secure, as msg is encrypted still; double security

            NOTEE: 1 key char hypo would need 3 pixels, so real need = 3 * 128 = 384 pixels
                Can't realistically fix scattered selection of pixels, nor select the order without coding a lot of specifics
                    could do pattern (ie: floor(width / 384))
    
            Could hash msg to sign, and try to replicated hashed signature on server side to decode?
                Can't extract msg from sent pixels, but can still verify

            
    Take any terminal inputted img to sign

    Make select pixels scalable with jpg size

    Connect with front-end

    
CURRENT PROBLEM WITH ENCODING

'''