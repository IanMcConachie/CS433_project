import os
from PIL import Image, ImageShow

class ImageHandler:
    def __init__(self, image_file):
        self.image_file = image_file
        self.image = None
        new_image_path = None

    def load_image(self):
        # Load image
        try:
            self.image = Image.open(self.image_file)
        except IOError:
            print("Unable to load image file")

    def save_image(self, new_image_path):
        # Save image to new file path
        try:
            self.image.save(new_image_path)
        except IOError:
            print("Unable to save image")

    def display_image(self):
        # Display image
        try:
            ImageShow.show(self.image)
        except OSError:
            print("Unable to display image")


class SignatureEncoder:
    def __init__(self, signature, img: ImageHandler):
        self.signature = signature
        self.img = img
        self.img_name = img.image_file

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

        # Set binary increment
        binCount = 0

        # Iterate between each fixed pixel to-be encoded
        for i in range(40):
            for j in range(32):
                # Get pixel tuple values
                r = pixels[(i * widthStep) + widthBuff, j * heightStep + heightBuff][0]
                g = pixels[(i * widthStep) + widthBuff, j * heightStep + heightBuff][1]
                b = pixels[(i * widthStep) + widthBuff, j * heightStep + heightBuff][2]

                # If pixel r is even and bin is odd
                if r % 2 == 0 and messageBin[binCount] == '1':
                    r += 1

                # Else if pixel r is odd and bin is even
                elif r % 2 == 1 and messageBin[binCount] == '0':
                    r -= 1
                binCount += 1

                # If pixel g is even and bin is odd
                if g % 2 == 0 and messageBin[binCount] == '1':
                    g += 1

                # Else if pixel g is odd and bin is even
                elif g % 2 == 1 and messageBin[binCount] == '0':
                    g -= 1
                binCount += 1

                # Skip every 3rd pixel's blue value
                if (binCount + 1) % 9 != 0:

                    # If pixel b is even and bin is odd
                    if b % 2 == 0 and messageBin[binCount] == '1':
                        b += 1
                
                    # If pixel b is odd and bin is even
                    elif b % 2 == 1 and messageBin[binCount] == '0':
                        b -= 1
                    binCount += 1

                # Reassign encoded RGB tuple value to pixel
                pixels[(i * widthStep) + widthBuff, j * heightStep + heightBuff] = (r, g, b)

        # Encode 3840th binary into the final pixel r-value
        # Get final pixel tuple values
        lastR = pixels[imageWidth - 1, imageHeight - 1][0]
        lastG = pixels[imageWidth - 1, imageHeight - 1][1]
        lastB = pixels[imageWidth - 1, imageHeight - 1][2]

        # If pixel r is even and bin is odd
        if lastR % 2 == 0 and messageBin[3839] == "1":
            lastR += 1

        # Else if pixel r is odd and bin is even
        elif lastR % 2 == 1 and messageBin[3839] == "0":
            lastR -= 1

        # Reassign encoded RGB tuple value to final pixel
        pixels[imageWidth - 1, imageHeight - 1] = (lastR, lastG, lastB)

        # Save the modified image
        self.new_image_name = self.img_name.replace(".png", "_signed.png")
        self.img.save_image(self.new_image_name)


class SignatureDecoder:
    def __init__(self, encoded_img: ImageHandler):
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

        # Declare raw binary message string
        decodedBinMsg = ''

        # Set binary increment
        binCount = 0

        # Iterate between each fixed pixel to-be decoded
        for i in range(40):
            for j in range(32):
                # Get pixel tuple values
                r = pixels[(i * widthStep) + widthBuff, j * heightStep + heightBuff][0]
                g = pixels[(i * widthStep) + widthBuff, j * heightStep + heightBuff][1]
                b = pixels[(i * widthStep) + widthBuff, j * heightStep + heightBuff][2]

                # if red is even, binary is 0, else 1 because even
                decodedBinMsg += '0' if r % 2 == 0 else '1'
                binCount += 1

                # if green is even, binary is 0, else 1 because even
                decodedBinMsg += '0' if g % 2 == 0 else '1'
                binCount += 1

                # if blue is even, binary is 0, else 1 because even
                # Skip every 3rd pixel's blue value
                if (binCount + 1) % 9 != 0 or binCount + 1 == 3840:
                    decodedBinMsg += '0' if b % 2 == 0 else '1'
                    binCount += 1

        # Decode final pixel r-value to get 3840th binary
        # Get final pixel tuple r-value
        lastChar = pixels[imageWidth - 1, imageHeight - 1][0]

        # if final red is even, binary is 0, else 1 because even
        decodedBinMsg += '0' if lastChar % 2 == 0 else '1'

        # Split raw binary data into 8-bit binary values
        dividedBin = [decodedBinMsg[i:i+8] for i in range(0, len(decodedBinMsg), 8)]

        # Extract encoded message from digital signature
        text = ''.join([chr(int(binary, 2)) for binary in dividedBin])

        # Return text
        print(text)
        # return text


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

    Connect with front-end
        Change fixed signature input to be determined by 

'''