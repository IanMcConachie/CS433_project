from PIL import Image
from structures import *

# # Creating instances of the classes
# image_handler = structures.ImageHandler("image.jpg")
# signature_encoder = structures.SignatureEncoder("signature_data")
# signature_decoder = structures.SignatureDecoder(encoded_image)
# cryptography_handler = structures.CryptographyHandler(private_key, public_key)
# file_handler = structures.FileHandler()
# user_interface = structures.UserInterface()

# # Calling methods on the instances
# image_handler.load_image("image.jpg")
# image_handler.process_image()

# signature_encoder.encode_signature()

# signature_decoder.decode_signature()

# cryptography_handler.generate_keys()
# cryptography_handler.encrypt_data()

# file_handler.read_file("data.txt")
# file_handler.write_file("Hello, World!", "output.txt")

# user_interface.get_signature()
# user_interface.select_image()
# user_interface.display_results()


def main():
    # Load image
    image_handler = ImageHandler("tykeson.jpg")
    image_handler.load_image()

    # Process image
    image_handler.process_image()

    # Process signature
    signature = "5c80a163f47b0435c3c03ea80e736b8ae30d69b5002d2152c52efc1b3c6afb68aceb776cb929134b700d2e60e0c8532dce5cb755f4f8296ed2a18318f2bb93d3fb3043e4825092213e21773a744207c6b48957c01e9c54ae250026376da19f792e7508e58e789346045600197c15a4bef53b21ede07a5d78e0dcc37244120eb85d836bbb9a1279b1da99a24225942f7b33303462343735643161306435656261396663376533643832313037366338626330663333623831336434323937376133646331393032623634393234636338304b475d1a0d5eba9fc7e3d821076c8bc0f33b813d42977a3dc1902b64924cc8"
    # print(len(signature))

    # Load encoder
    encoder = SignatureEncoder(signature, image_handler)
    encoder.encode_signature()

    # Load decoder
    mod_image_handler = ImageHandler("modified_image.jpg")
    mod_image_handler.load_image()

    decoder = SignatureDecoder(mod_image_handler)
    decoder.decode_signature()


    # Save image
    # image_handler.save_image("test_processed.jpg")

    # Display image
    # image_handler.display_image()

if __name__ == "__main__":
    main()