from flask import Flask, request, jsonify, make_response
from flask_restful import Resource, Api
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import declarative_base
from passlib.apps import custom_app_context as pwd_context
from authlib.jose import jwt
from datetime import datetime, timedelta
from authlib.jose.errors import DecodeError, ExpiredTokenError
from configparser import ConfigParser
from crypto import generate_msg, interpret_msg
import hashlib
import base64

app = Flask(__name__)
api = Api(app)

# read configuration values from config.ini file
config = ConfigParser()
config.read('config.ini')

# configure database connection
server = config['database']['server']
dbname = config['database']['dbname']
user = config['database']['user']
password = config['database']['pass']
port = config['database']['port']

engine = create_engine(f"mysql+pymysql://{user}:{password}@{server}:{port}/{dbname}")
Session = sessionmaker(bind=engine)
Base = declarative_base()

# define User model
class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), index=True, unique=True)
    user_hash = Column(String(128), index=True)  
    password_hash = Column(String(128))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)
        
    def hash_username(self, username):
        app.logger.debug(f"USERNAME HASH CALLED")
        self.user_hash = hashlib.sha256(username.encode('utf-8')).hexdigest()
        app.logger.debug(f"***User Hash={self.user_hash}***")
        
    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)
        

# create users table if it does not exist
Base.metadata.create_all(engine)

# define secret key for token generation
jwk = {
  "crv": "P-256",
  "kty": "EC",
  "alg": "ES256",
  "use": "sig",
  "kid": "a32fdd4b146677719ab2372861bded89",
  "d": "5nYhggWQzfPFMkXb7cX2Qv-Kwpyxot1KFwUJeHsLG_o",
  "x": "-uTmTQCbfm2jcQjwEa4cO7cunz5xmWZWIlzHZODEbwk",
  "y": "MwetqNLq70yDUnw-QxirIYqrL-Bpyfh4Z0vWVs_hWCM"
}

def generate_auth_token(payload, expires_in_minutes=60):
    """
    Generate a JWT with the given payload and expiration time.
    
    SOURCE: https://www.scottbrady91.com/python/authlib-python-jwt
    """
    now = datetime.utcnow()
    payload['exp'] = now + timedelta(minutes=expires_in_minutes)
    payload['iat'] = now

    header = {"alg": "ES256"}
    token = jwt.encode(header, payload, jwk)
    return base64.b64encode(token).decode('utf-8')
    
def verify_auth_token(encoded_jwt):
    """
    Verify a JWT and return the payload if valid.

    SOURCE: https://www.scottbrady91.com/python/authlib-python-jwt
    """
    encoded_jwt = base64.b64decode(encoded_jwt)
    try:
        payload = jwt.decode(encoded_jwt, jwk)
        return payload
    except DecodeError:
        return None
    except ExpiredTokenError:
        return None

class Register(Resource):
    def post(self):
        password = request.args.get('password', type=str)
        username = request.args.get('username', type=str)
        app.logger.debug(f"username={username}")
        app.logger.debug(f"pw hash = {password}")
        # check if username is taken
        session = Session()
        user = session.query(User).filter_by(username=username).first()
        app.logger.debug(f"is none = {user is None}")
        if user is not None:
            return make_response(jsonify({'message':'Failure'}), 400)

        # add new user
        user = User(username=username)
        app.logger.debug(f"user created = {user.username}")
        user.hash_password(password)
        app.logger.debug(f"password set = {user.password_hash}")
        user.hash_username(username)
        app.logger.debug(f"user hash = {user.user_hash}")
        session.add(user)
        session.commit()
        return make_response(jsonify({'message':'Success'}), 201)

class Token(Resource):
    def get(self):
        password = request.args.get('password', type=str)
        username = request.args.get('username', type=str)
        
        app.logger.debug("***Log in attempt***")
        app.logger.debug(f"***User={username}***")

        # verify credentials
        session = Session()
        user = session.query(User).filter_by(username=username).first()
        if user is None or not user.verify_password(password):
            app.logger.debug("***Log in failed***")
            return make_response(jsonify({'response':'Failure'}), 401)
        
        app.logger.debug("***Log in success***")
        app.logger.debug(f"***User found = {user.id}***")
        # generate and return token
        token = generate_auth_token({'user_id': user.id})
        app.logger.debug("***TOKEN = {token}***")
        response_success =  {
            "response":"Success", 
            "id":user.id,
            "token":str(token)
        }
        return make_response(jsonify(response_success), 201)
    
""" 
    resource to create message
    - key 
    - user hash
    - pixel hash
    
    return message to client 
    
"""
class GenMessage(Resource):
    def get(self):
        app.logger.debug("Top")
        auth_header = request.headers.get('Authorization')
        app.logger.debug("line 156")
        if auth_header:
            app.logger.debug("line 158")
            # extract token from "Bearer <token>" format
            token = auth_header.split(' ')[1]
            
            # verify token
            payload = verify_auth_token(token)
            if payload:
                expiration_time = datetime.utcfromtimestamp(payload['exp'])
                
                # make sure token not expired
                if expiration_time > datetime.utcnow():
                    app.logger.debug("line 165")
                    
                    # token is valid and user is authenticated
                    user_id = payload['user_id']
                    app.logger.debug(f"USER ID = {user_id}")
                    
                    session = Session()
                    user = session.query(User).filter_by(id=user_id).first()
                    byte_length = 16
                    byte_representation = int(str(user_id), 16).to_bytes(byte_length, 'big')
                    app.logger.debug("line 168")
                    # retrieve image hash from request arguments
                    img_hash_str = request.args.get('hash', type=str)
                    app.logger.debug("line 169")
                    img_hash_bytes = int(img_hash_str, 16).to_bytes(32, 'big')
                    
                    # convert hashed username to bytes
                    app.logger.debug("line 180")
                    hashed_username = int(user.user_hash, 16).to_bytes(32, 'big')
                    
                    # concat image hash and hashed username
                    cdata = img_hash_bytes + hashed_username
                    
                    # generate the message using byte_representation, cdata, and hashed_username
                    app.logger.debug("line 187")
                    msg = generate_msg(byte_representation, cdata, hashed_username)
                    
                    response_success = {
                        "response": "Success",
                        "message": msg
                    }
                    return make_response(jsonify(response_success), 201)
        
        return make_response(jsonify({"response":"Failure"}), 400)
                
        

"""
make some resource to verify message
    - given a message + hash
    - cdata + pdata
interpret_msg
"""
class VerifyMessage(Resource):
    def get(self):
        app.logger.debug("line 220")
        payload = request.form  # access payload
        img_hash = payload.get("image_hash")  
        message = payload.get("message") 
        
        user_hash = message[256:384]
        
        # get user from user hash
        session = Session()
        app.logger.debug("line 229")
        user = session.query(User).filter_by(user_hash=user_hash).first()
        app.logger.debug("line 231")
        # does hash match a user?
        if user is None:
            return make_response(jsonify({'response':'Failure'}), 401)
        app.logger.debug("line 187")
        is_steg, hash_val, pt_match = interpret_msg(message, user.user_id)
        app.logger.debug("line 237")
        # valid message or no?
        # should the hash_val variable be just the image hash?
        if (is_steg and pt_match) and (hash_val.hex() == img_hash):
            response_success = {
                        "response": "Success",
                        "owner": user.username
                    }
            return make_response(jsonify(response_success), 201)
        else:
            return make_response(jsonify({'response':'Failure'}), 401)
        
        

api.add_resource(Register, '/register')  # endpoint for user registration
api.add_resource(Token, '/token')  # endpoint for retrieving authentication token
api.add_resource(GenMessage, '/genmessage')  # endpoint for generating a message
api.add_resource(VerifyMessage, '/verifymessage')  # endpoint for verifying a message


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)