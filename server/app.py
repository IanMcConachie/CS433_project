from flask import Flask, request, jsonify, make_response
from flask_restful import Resource, Api
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer \
                                  as Serializer, BadSignature, \
                                  SignatureExpired)
import configparser

app = Flask(__name__)
api = Api(app)

# read configuration values from config.ini file
config = configparser.ConfigParser()
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

def generate_auth_token(id, expiration=600):
   s = Serializer(SECRET_KEY, expires_in=expiration)
   return s.dumps({"id":id})

def verify_auth_token(token):
    s = Serializer(SECRET_KEY)
    try:
        data = s.loads(token)
    except SignatureExpired:
        app.logger.debug("***EXPIRED***")
        return None    # valid token, but expired
    except BadSignature:
        app.logger.debug("***BAD SIGNATURE***")
        return None    # invalid token
    return "Success"


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

        # verify credentials
        session = Session()
        user = session.query(User).filter_by(username=username).first()
        if user is None or not user.verify_password(password):
            return {'response':'Failure'}, 401

        # generate and return token
        token = generate_auth_token(user.id)
        return {
            "response":"Success", 
            "id":user.id,
            "token":str(token)[2:-1]
        }, 201

class UserById(Resource):
    def get(self, id):
        session = Session()
        user = session.query(User).filter_by(id=id).first()
        if user is not None:
            return jsonify({'id': user.id, 'username': user.username})
        return jsonify({'id': "FAILURE"})

api.add_resource(Register, '/register')
api.add_resource(Token, '/token')
api.add_resource(UserById, '/user/<int:id>')

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)