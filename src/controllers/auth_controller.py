import jwt,os
from flask import request, Response, json, Blueprint
from src.models.user_model import User
from src import db
from src.services.jwt_service import generate_token
from src.library.hashing import hash_password, check_password_hash

# user controller blueprint to be registered with api blueprint
users = Blueprint("users", __name__)

# route for login api/users/signin
@users.route('/login', methods = ["POST"])
def handle_login():
    try: 
        # first check user parameters
        data = request.json
        if "email" and "password" in data:
            # check db for user records
            user = User.query.filter_by(email = data["email"]).first()

            # if user records exists we will check user password
            if user:
                # check user password
                if check_password_hash(user.password, data["password"]):
                    # user password matched, we will generate token
                    
                    token = generate_token(user)
                    return Response(
                            response=json.dumps({'status': "success",
                                                "message": "User Sign In Successful",
                                                "token": token}),
                            status=200,
                            mimetype='application/json'
                        )
                
                else:
                    return Response(
                        response=json.dumps({'status': "failed", "message": "User Password Mistmatched"}),
                        status=401,
                        mimetype='application/json'
                    ) 
            # if there is no user record
            else:
                return Response(
                    response=json.dumps({'status': "failed", "message": "User Record doesn't exist, kindly register"}),
                    status=404,
                    mimetype='application/json'
                ) 
        else:
            # if request parameters are not correct 
            return Response(
                response=json.dumps({'status': "failed", "message": "User Parameters Email and Password are required"}),
                status=400,
                mimetype='application/json'
            )
        
    except Exception as e:
        return Response(
                response=json.dumps({'status': "failed", 
                                     "message": "Error Occured",
                                     "error": str(e)}),
                status=500,
                mimetype='application/json'
            )



# route for login api/users/signup
@users.route('/signup', methods = ["POST"])
def handle_signup():
    try: 
        # first validate required use parameters
        data = request.json
        if "firstname" in data and "lastname" and data and "email" and "password" in data:
            # validate if the user exist 
            user = User.query.filter_by(email = data["email"]).first()
            # usecase if the user doesn't exists
            if not user:
                # creating the user instance of User Model to be stored in DB
                hashed_password=hash_password(data['password'])
                user_obj = User(
                    firstname = data["firstname"],
                    lastname = data["lastname"],
                    email = data["email"],
                    # hashing the password
                    password = hashed_password
                )
                db.session.add(user_obj)
                db.session.commit()

                token = generate_token(user_obj)
                return Response(
                response=json.dumps({'status': "success",
                                    "message": "User Sign up Successful",
                                    "token": token}),
                status=201,
                mimetype='application/json'
            )
            else:
                print(user)
                # if user already exists
                return Response(
                response=json.dumps({'status': "failed", "message": "User already exists kindly use sign in"}),
                status=409,
                mimetype='application/json'
            )
        else:
            # if request parameters are not correct 
            return Response(
                response=json.dumps({'status': "failed", "message": "User Parameters Firstname, Lastname, Email and Password are required"}),
                status=400,
                mimetype='application/json'
            )
        
    except Exception as e:
        return Response(
                response=json.dumps({'status': "failed", 
                                     "message": "Error Occured",
                                     "error": str(e)}),
                status=500,
                mimetype='application/json'
            )