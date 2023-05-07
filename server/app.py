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
    password_hash = Column(String(128))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

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

        # check if username is taken
        session = Session()
        user = session.query(User).filter_by(username=username).first()
        if user is not None:
            return make_response(jsonify({'message':'Failure'}), 400)

        # add new user
        user = User(username=username)
        user.hash_password(password)
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
            return {'response':'Failure'}, 401
        
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
        

class UserById(Resource):
    def get(self, id):
        session = Session()
        user = session.query(User).filter_by(id=id).first()
        if user is not None:
            claims = {'sub': user.id, 'name': user.username}
            token = jwt.encode({'alg': 'HS256', 'typ': 'JWT'}, claims, app.config['SECRET_KEY'])
            return jsonify({'id': user.id, 'username': user.username, 'token': token})
        return jsonify({'id': "FAILURE"})

api.add_resource(Register, '/register')
api.add_resource(Token, '/token')
api.add_resource(UserById, '/user/<int:id>')

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)