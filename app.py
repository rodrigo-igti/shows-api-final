from flask import Flask, request, jsonify
from model import show, episode

# Autenticação e Autorização com JWT
from flask_jwt_extended import JWTManager
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import check_password_hash
from datetime import timedelta

from model import user
from werkzeug.security import generate_password_hash


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PROPAGATE_EXCEPTIONS'] = True
app.config['JSON_SORT_KEYS'] = False


# Escolher uma chave secreta aleatória e FORTE, porque vai ser incorporada na assinatura.
# Podermos obter uma, por exemplo, usando a biblioteca secrets
# Para isto, executar no console Python
# >>> import secrets
# >>> secrets.token_urlsafe(20)
# e o resultado deve ser àtribuído à constante JWT_SECRET_KEY
app.config['JWT_SECRET_KEY'] = 'V7Bx_xhevOdjzJTQRWYKvhjADH4'

# Definir o tempo de validade de cada token criado
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=10)

jwt = JWTManager(app)


@app.route('/signup',methods=['POST'])
def signup():
    request_data = request.get_json()
    username = request_data['username']
    password = request_data['password']
    new_user = user.UserModel(username, generate_password_hash(password))
    try:
        new_user.save_to_db()
        return new_user.json()
    except:
        return {'message': 'Usuário já existe!'}, 409



@app.route('/user/<string:username>')
def get_user(username):
    result = user.UserModel.find_by_username(username)
    if result:
        return result.json()
    return {'message': 'Usuário não encontrado'}, 404


@app.route('/user/<string:username>', methods=['DELETE'])
def delete_user(username):
    result = user.UserModel.find_by_username(username)
    if result:
        result.delete_from_db()
        return {'message': 'Usuário excluído com sucesso!'}, 202
    else:
        return {'message': 'Usuário não encontrado!'}, 404



# Esta rota é para a autenticação
# Com um usuário e senha válidos, ela retorna o token criado
@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")
    result = user.UserModel.find_by_username(username)
    if result and check_password_hash(result.password, password):
        access_token = create_access_token(identity=username, fresh=True)
        return {'token de acesso': access_token}
    else:
        return {'message': 'Usuário ou senha inválido!'}, 401


# Este método fornece a identidade do usuário de um token
@app.route("/autenticado")
@jwt_required()
def logado():
    current_user = get_jwt_identity()
    return {'usuario do token': current_user}, 200


@app.before_first_request
def create_tables():
    alchemy.create_all()

@app.route('/',methods=['GET'])
def home():
    return "API funcionando", 200

@app.route('/show',methods=['POST'])
@jwt_required()
def create_show():
    request_data = request.get_json()
    new_show = show.ShowModel(request_data['name'])
    new_show.save_to_db()
    result = show.ShowModel.find_by_id(new_show.id)
    return jsonify(result.json())

@app.route('/show/<string:name>')
def get_show(name):
    result = show.ShowModel.find_by_name(name)
    if result:
        return result.json()
    return {'message': 'Série não encontrada'}, 404

@app.route('/show/<string:name>/episode',methods=['POST'])
def create_episode_in_show(name):
    request_data = request.get_json()
    parent = show.ShowModel.find_by_name((name))
    if parent:
        new_episode = episode.EpisodeModel(name=request_data['name'],
                                           season=request_data['season'],
                                           show_id=parent.id)
        new_episode.save_to_db()
        return new_episode.json()
    else:
        return {'message':'Série não encontrada'}, 404

@app.route('/show/<int:id>',methods=['DELETE'])
def delete_show(id):
    result = show.ShowModel.find_by_id(id)
    if result:
        result.delete_from_db()
        return {'message':'Excluído com sucesso!'}, 202
    else:
        return {'message': 'Série não encontrada!!'}, 404

@app.route('/episode/<int:id>',methods=['DELETE'])
def delete_episode(id):
    result = episode.EpisodeModel.find_by_id(id)
    if result:
        result.delete_from_db()
        return {'message':'Excluído com sucesso!'}, 202
    else:
        return {'message': 'Episódio não encontrado!'}, 404


@app.route('/shows')
@jwt_required()
def list():
    result = show.ShowModel.list_shows()
    return {'showlist': result}

@app.route('/show',methods=['PUT'])
def update_show():
    request_data = request.get_json()
    result = show.ShowModel.find_by_id(request_data['id'])
    if result:
        result.name = request_data['name']
        result.update()
        return {'message':'Série atualizada com sucesso'}, 200
    else:
        return {'message':'Série não encontrada'}, 404

if __name__ == '__main__':
    from data import alchemy
    alchemy.init_app(app)
    app.run(port=5000, debug=True)
