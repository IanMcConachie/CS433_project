from flask import Flask, request, render_template, redirect, url_for, flash, abort, session
import requests
from hash_client import gen_hash
from stegano import lsb
import base64
import os
from crypto import generate_msg, interpret_msg
import hashlib
import base64

# set secret key for session encryption 
app = Flask(__name__)

@app.route("/")
@app.route("/index")
def index():
    """render index.html template for the homepage"""
    return render_template("index.html")


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    # We will have an image
    # stegonograpy
    # hashing 
    
    # 1. hashing based on pixels
    # 2. send hash to server
    # 3. server gonna generate message with 
    #     - cdata = hash + username
    #     - pdata = username
    
    if request.method == 'POST':
        # check if the 'image' file was uploaded
        if 'image' in request.files:
            save_path = './static/images/'
            if not os.path.exists(save_path):
                os.makedirs(save_path)

            image_file = request.files['image']
            img_path = os.path.join(save_path, image_file.filename)
            app.logger.debug(f"IMAGE PATH = {img_path}")
            
            # save image
            image_file.save(img_path)
            
            # generate hash
            img_hash = gen_hash(img_path)
            
            # Everything in below section would happen on server side 
            # ====================================================
            
            # hardcoded user id repr
            user_id = 1
            byte_length = 16
            byte_representation = int(str(user_id), 16).to_bytes(byte_length, 'big')
            
            
            img_hash_bytes = int(img_hash, 16).to_bytes(32, 'big')
            
            # this is a hardcoded but REAL user name hash
            user_hash = "ffebf91de904ea7b8b5a827143ea1b0ac5e1963893a7a1640f546762b7cb290a"
            hashed_username = int(user_hash, 16).to_bytes(32, 'big')
            
            # concat image hash and hashed username
            cdata = img_hash_bytes + hashed_username
            msg = generate_msg(byte_representation, cdata, hashed_username)
            print("msg len", len(msg))
            # ====================================================
            
            encrypted_message_b64 = base64.b64encode(bytes.fromhex(msg))
            app.logger.debug(f"MESSAGE BEING EMBEDDED: {encrypted_message_b64}")
            
            # embed message
            encrypted_image = lsb.hide(img_path, encrypted_message_b64.decode())
            
            # save new image
            encrypted_img_path = os.path.join(save_path, "encrypted.png")
            encrypted_image.save(encrypted_img_path)
            app.logger.debug(f"IMAGE PATH = {encrypted_img_path}")

            return render_template('image.html', image_url=encrypted_img_path)
        
        # Return an error message if no 'image' file was uploaded
        flash("No image file found!")
    return render_template('upload.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    """
    - image with message is uploaded
    - remove encrypted message
    - send encrypted message and hash
    """
    if request.method == 'POST':
        # check if the 'image' file was uploaded
        if 'image' in request.files:
            image_file = request.files['image']
            save_path = 'templates/static/images/'
            if not os.path.exists(save_path):
                os.makedirs(save_path)

            image_file = request.files['image']
            img_path = os.path.join(save_path, image_file.filename)
            image_file.save(img_path)
            
            img_hash = gen_hash(img_path)
            
            # load image with hidden message
            image_with_hidden_message = lsb.reveal(img_path)
            
            # decode encrypted message from base64
            encrypted_message_decoded = base64.b64decode(image_with_hidden_message.encode())
            
            # Everything in below section would happen on server side 
            #=======================================================
            print("=================")
            print(encrypted_message_decoded)
            
            # hex string repr
            msg_string = encrypted_message_decoded.hex()
            print(msg_string)
            print(len(msg_string))
            
            # =============================================
            # NOTICE: I am claiming that the p_text with the hashed user id
            # starts at the 128th byte. agree? I also claim there are 64 hex
            # chars
            # =============================================
            user_hash = msg_string[128:192]
            
            
            # simulates database, key == user hash, val== user_id
            # these are real values from the mysql db
            simulated_db = {
                "b54a95127a4b573f41e335fdbd339dcc2208fbfb1ae0b6fab7599d6e2d6ec754": 2,
                "ffebf91de904ea7b8b5a827143ea1b0ac5e1963893a7a1640f546762b7cb290a": 1
                }
            
            if user_hash in simulated_db:
                user_id = simulated_db[user_hash]
            else:
                print("user hash not in db")
                print(user_hash)
                return render_template('verify.html')
            
            # 16 byte repr of user_id for key
            byte_length = 16
            byte_representation = int(str(user_id), 16).to_bytes(byte_length, 'big')
            
            # ian's fxn
            is_steg, hash_val, pt_match = interpret_msg(msg_string, byte_representation)
            
            # debug
            print(is_steg)
            
            print("decrypted image hash:")
            print(hash_val.hex())
            
            print("calculated image hash:")
            print(img_hash)
            print(pt_match)
            
            # check if valid
            if (is_steg and pt_match) and (hash_val.hex() == img_hash):
                print(f"user is {user_id}")
            else:
                print("no pattern match or no image hash match")
                return render_template('verify.html') 
            #=========================================================
            
            # flash(f"user_id = {user_id}")
            return render_template('verify.html')
        
        # Return an error message if no 'image' file was uploaded
        print("No image file found!")
    return render_template('verify.html')

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
