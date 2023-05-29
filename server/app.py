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
from crypto import generate_msg
import hashlib

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
    user_hash = Column(String(128))  
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
SECRET_KEY = 'test1234@#$'

def generate_auth_token(payload, expires_in_minutes=60):
    """
    Generate a JWT with the given payload and expiration time.
    :param payload: The payload to include in the JWT.
    :param expires_in_minutes: The number of minutes until the JWT should expire.
    :return: The encoded JWT.
    """
    now = datetime.utcnow()
    payload['exp'] = now + timedelta(minutes=expires_in_minutes)
    payload['iat'] = now

    header = {'alg': 'HS256'}
    token = jwt.encode(header, payload, SECRET_KEY)
    app.logger.debug(f"***TOKEN = {token}***")
    return token
    
def verify_auth_token(encoded_jwt):
    """
    Verify a JWT and return the payload if valid.
    :param encoded_jwt: The encoded JWT to verify.
    :return: The payload contained in the JWT if the JWT is valid.
    :raises DecodeError: If the JWT is invalid.
    """
    try:
        header, payload = jwt.decode(encoded_jwt, SECRET_KEY, algorithms=['HS256'])
        return payload
    except DecodeError:
        app.logger.debug("***INVALID TOKEN***")
        return None
    except ExpiredTokenError:
        app.logger.debug("***INVALID TOKEN***")
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
        auth_header = request.headers.get('Authorization')
        
        if auth_header:
            # extract token from "Bearer <token>" format
            token = auth_header.split(' ')[1]
            
            # verify token
            payload = verify_auth_token(token)
            if payload:
                # token is valid and user is authenticated
                user_id = payload['user_id']
                
                session = Session()
                user = session.query(User).filter_by(id=user_id).first()
                
                byte_length = 16
                byte_representation = user_id.to_bytes(byte_length, 'big')
                
                # retrieve image hash from request arguments
                img_hash_str = request.args.get('hash', type=str)
                img_hash_bytes = int(img_hash_str, 16).to_bytes(32, 'big')
                
                # convert hashed username to bytes
                hashed_username = int(user.user_hash, 16).to_bytes(32, 'big')
                
                # concat image hash and hashed username
                cdata = img_hash_bytes + hashed_username
                
                # generate the message using byte_representation, cdata, and hashed_username
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
        

api.add_resource(Register, '/register')
api.add_resource(Token, '/token')
api.add_resource(GenMessage, '/genmessage')

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)