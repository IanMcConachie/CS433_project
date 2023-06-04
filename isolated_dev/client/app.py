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
            save_path = '/static/images/'
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
            # ====================================================
            
            
            encrypted_message_b64 = base64.b64encode(msg)
            app.logger.debug(f"MESSAGE BEING EMBEDDED: {encrypted_message_b64}")
            
            # embed message
            encrypted_image = lsb.hide(img_path, encrypted_message_b64.decode())
            
            # save new image
            encrypted_img_path = os.path.join(save_path, "encrypted.png")
            encrypted_image.save(encrypted_img_path)
            app.logger.debug(f"IMAGE PATH = {encrypted_img_path}")
            # image_base64 = base64.b64encode(image).decode('utf-8')
            image_url = url_for('static', filename="encrypted.png")
            return render_template('image.html', image_url=image_url)
        
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
        app.logger.debug("line 189")
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
            try:
                app.logger.debug("line 205")
                image_with_hidden_message = lsb.reveal(img_path)
                
                
                # decode encrypted message from base64
                encrypted_message_decoded = base64.b64decode(image_with_hidden_message.encode())
                
                payload = {
                    "image_hash": img_hash,
                    "message": encrypted_message_decoded
                }
                app.logger.debug("line 216")
                response = requests.get(f'http://restapi:5000/verifymessage',
                        payload=payload).json()
                app.logger.debug("line 219")
                if response['message'] == 'Success':
                    owner = response['owner']
                    flash(f"The owner of this image is {owner}")
                else:
                    flash("No owner found for this image")
                return render_template('verify.html')
            except:
                flash("No message detected in image!")
                return render_template('upload.html')
        
        # Return an error message if no 'image' file was uploaded
        flash("No image file found!")
    return render_template('verify.html')

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
