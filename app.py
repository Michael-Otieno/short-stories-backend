from flask import Flask,request,jsonify,make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
import datetime
from flask_migrate import Migrate
from flask_swagger_ui import get_swaggerui_blueprint
from werkzeug.utils import send_from_directory
# from flask_script import Server
import os


app = Flask(__name__)
app.config['SECRET_KEY'] ='ABC123'


app.config['SQLALCHEMY_DATABASE_URI']='postgresql+psycopg2://moringa:1234@localhost/short'
# SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")
# if SQLALCHEMY_DATABASE_URI.startswith("postgres://"):
#     SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI.replace("postgres://", "postgresql://", 1)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
# app.add_command('server',Server)
# app.add_command('db',MigrateCommand)


class User(db.Model):
    __tablename__ ='users'

    id=db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    username=db.Column(db.String())
    email=db.Column(db.String(), unique=True)
    story=db.relationship('Story', backref='user', lazy='dynamic')
    password=db.Column(db.String())


    def __repr__(self):
        return f'{self.username}:{self.email}:{self.story}'

class Story(db.Model):
    __tablename__ = 'story'

    id=db.Column(db.Integer, primary_key=True)
    title=db.Column(db.String(50))
    genre=db.Column(db.String(50))
    story=db.Column(db.String())
    user_id=db.Column(db.Integer, db.ForeignKey('users.id'))

    def __repr__(self):
        return f'{self.title}:{self.genre}:{self.story}'

@app.route('/')
def index():
    return 'Welcome to short story api'

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

### swagger specific ###
SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.json'
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Short-Stories-Flask-API"
    }
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)




@app.route('/user/<username>',methods=['GET'])
def get_user(username):
    user=User.query.filter_by(username=username).first()
    print('above line')
    return user

@app.route('/action',methods=['GET'])
def get_action():
    stories = Story.query.filter_by(genre='action').all()
    
    output =[]
    for story in stories:
        story_data = {'title':story.title, 'genre':story.genre,'story':story.story,'author':story.user.username}

        output.append(story_data)
    return {'story':output}


@app.route('/fantasy',methods=['GET'])
def get_fantasy():
    stories = Story.query.filter_by(genre='fantasy').all()
    
    output =[]
    for story in stories:
        story_data = {'title':story.title, 'genre':story.genre,'story':story.story,'author':story.user.username}

        output.append(story_data)
    return {'story':output}


@app.route('/scifi', methods=['GET'])
def get_scifi():
    scifis = Story.query.filter_by(genre='scifi').all()

    output =[]
    for scifi in scifis:
        scifi_data = {'title':scifi.title, 'genre':scifi.genre,'scifi':scifi.story,'author':scifi.user.username}

        output.append(scifi_data)
    return {'scifi':output}



@app.route('/stories',methods=['GET'])
def get_stories():
    stories = Story.query.all()

    output =[]
    for story in stories:
        story_data = {'title':story.title, 'genre':story.genre,'story':story.story,'author':story.user.username}

        output.append(story_data)
    return {'story':output}


@app.route('/new_user',methods=['POST'])
def add_user():
    data=request.get_json()
    existing=User.query.filter_by(username=data['username']).first()
    if existing:
        return jsonify({'message':'username already taken'})

    hashed_password=generate_password_hash(data['password'],method="sha256")
    new_user=User(username=data["username"],email=data["email"],password=hashed_password)

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message':"new user created"})


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message':'token is invalid'}), 401
        return f(current_user, *args, *kwargs)

    return decorated

@app.route('/new_story',methods=['POST'])
@token_required
def add_story(current_user):
    data=request.get_json()
    new_story=Story(title=data["title"],genre=data["genre"],story=data["story"],user_id=current_user.id)

    db.session.add(new_story)
    db.session.commit()

    return jsonify({'message':"new story created"})


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        # return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
        return jsonify({'message':'login required'})
    user = User.query.filter_by(username=auth.username).first()

    if not user:
        # return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
        return jsonify({'message':'User does not exist'})
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})

    if not check_password_hash(user.password, auth.password):
        return jsonify({'message':'Username or password is incorrect'})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})


if __name__ == '__main__':
    app.run(debug=True)

    