import requests

from datetime import datetime
from datetime import timedelta
from functools import wraps

from flask import Flask
from flask import jsonify
from flask import request
# from flask_jwt import JWT, jwt_required, current_identity
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity, get_jwt_claims
)
from werkzeug.security import safe_str_cmp
from mongoengine import connect
from mongoengine import disconnect
from mongoengine import DoesNotExist

from db_helper import PassCode
from db_helper import PasscodesUsageInfo
from db_helper import AuthUser
from db_helper import CenterUsageInfo
from passcode_helper import random_unique_generator
from passcode_helper import encrypt
from passcode_helper import decrypt
from passcode_helper import generate_qr
from passcode_helper import hash_passcode


app = Flask(__name__)
app.config.from_object('config.DevelopmentConfig')


# class User(object):
#     def __init__(self, id, username, password):
#         self.id = id
#         self.username = username
#         self.password = password
#
#     def __str__(self):
#         return "User(id='%s')" % self.id


# connect(
#         db=app.config["DB_NAME"],
#         username=app.config["DB_USER"],
#         password=app.config["DB_PASSWORD"],
#         host=app.config["DB_HOST"],
#         port=int(app.config["DB_PORT"]),
#         alias="default")
#
#
# try:
#     # Get user authenticated to use center services from db
#     auth_cs_user = AuthUser.objects.get(username=app.config["CENTER_SERVICES_USER"])
# except:
#     auth_cs_user = ""
#
# disconnect(alias="default")
#
# # Have an extendable users' list (authenticated users to use services)
# users = [User(1, app.config["CENTER_SERVICES_USER"], auth_cs_user.password)] if auth_cs_user else []
#
# username_table = {u.username: u for u in users}
# userid_table = {u.id: u for u in users}
#
#
# def authenticate(username, password):
#     user = username_table.get(username, None)
#     password = hash_passcode(password, app.config["SALT"])  # Check hashed password since password is already hashed stored in db
#     if user and safe_str_cmp(user.password.encode('utf-8'), password):
#         return user
#
#
# def identity(payload):
#     user_id = payload['identity']
#     return userid_table.get(user_id, None)



# jwt = JWT(app, authenticate, identity)

jwt = JWTManager(app)


# This is an example of a complex object that we could build
# a JWT from.
class UserObject:
    def __init__(self, username, roles):
        self.username = username
        self.roles = roles


# Create a function that will be called whenever create_access_token
# is used. It will take whatever object is passed into the
# create_access_token method, and lets us define what custom claims
# should be added to the access token.
@jwt.user_claims_loader
def add_claims_to_access_token(user):
    return {'roles': user.roles}


# Create a function that will be called whenever create_access_token
# is used. It will take whatever object is passed into the
# create_access_token method, and lets us define what the identity
# of the access token should be.
@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.username


@app.route('/auth', methods=['POST'])
def login():
    """ Login for authenticating and authorizating users.
    Different roles/permissions for center users and msg users.
    Center users can handle (generate/delete/show etc. passcodes, whereas
    msg users can send messages using the message service.
    :return: access token containing user identity and user roles
    """
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    passcode = request.json.get('passcode', None)


    connect(
            db=app.config["DB_NAME"],
            username=app.config["DB_USER"],
            password=app.config["DB_PASSWORD"],
            host=app.config["DB_HOST"],
            port=int(app.config["DB_PORT"]),
            alias="default")

    auth_user = ""
    user_roles = []

    # Case of user authenticated to use center services
    if username and password:
        # Check hashed password since password is already hashed stored in db
        password = hash_passcode(password, app.config["SALT"])
        try:
            # Check if user is authenticated to use center services from db
            auth_user = AuthUser.objects.get(username=username)
            auth_user = auth_user.username
            user_roles = ["cs_user"]
        except DoesNotExist:
            pass
    else:
        # If user is not authenticated to use center services, check for simple user with passcode
        try:
            hashed_passcode = hash_passcode(passcode, app.config["SALT"])

            passcode = PassCode.objects.get(passcode=hashed_passcode.decode("utf-8"))

            # If passcode is in db and has not expired, then authorize user as sm_user
            if passcode.expiration_date > datetime.now() and passcode.uses_left > 0:
                auth_user = app.config["SEND_MSG_USER"]
                user_roles = ["sm_user"]
        except DoesNotExist:
            pass

    disconnect(alias="default")

    if auth_user and user_roles:
        user = UserObject(username=auth_user, roles=user_roles)
    else:
        return jsonify({"msg": "Not authenticated user"}), 401

    # We can now pass this complex object directly to the
    # create_access_token method. This will allow us to access
    # the properties of this object in the user_claims_loader
    # function, and get the identity of this object from the
    # user_identity_loader function.
    access_token = create_access_token(identity=user)
    ret = {'access_token': access_token}
    return jsonify(ret), 200


def is_authorized(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ret = {
                "current_identity": get_jwt_identity(),  # test
                "current_roles": get_jwt_claims()['roles']  # ['foo', 'bar']
            }

            if role in ret.get("current_roles"):
                return f(*args, **kwargs)
            else:
                # print(role, ret.get("current_roles"))
                return jsonify({"msg": "Not authorized user"}), 401
        return decorated_function
    return decorator


@app.route("/genpass/<lang>/<center_id>")
@app.route("/genpass/<lang>/<center_id>/<mode>")
@app.route("/genpass/<lang>/<center_id>/<mode>/<ftype>")
@jwt_required
@is_authorized(app.config["CENTER_SERVICES_ROLE"])
def generate_passcode(lang, center_id, mode = None, ftype=None, ):
    """ Generate a passcode and store it (hashed) to database with timestamp
    :param lang: language used
    :param center_id: the id of the center creating the passcode
    :param mode: possible values qr or None, so that passcode should also be transformed to a qrcode or not
    :param ftype: in case of qrcode, the file type, possible values are svg, png or None. None corresponds to png
    :return: a json that includes the encrypted passcode as well as a qrcode (only if mode qr was given, else null)
    """

    rand_code = random_unique_generator()
    # print("rand_code: ", rand_code)

    sec_key = app.config["SECRET_KEY"]
    passcode = encrypt(sec_key, rand_code)

    # Store passcode to db hashed
    hashed_key = hash_passcode(rand_code, app.config["SALT"])

    expiration_date = datetime.now() + timedelta(days=30)

    connect(
        db=app.config["DB_NAME"],
        username=app.config["DB_USER"],
        password=app.config["DB_PASSWORD"],
        host=app.config["DB_HOST"],
        port=int(app.config["DB_PORT"]),
        alias="default"
    )

    pass_rec = PassCode(passcode=hashed_key, center_id=center_id, language=lang, revoked=False,
             expiration_date= expiration_date, uses_left=app.config["PASSCODE_MAX_USES"])
    pass_rec.save()

    # If passcodes for this language already exist in db, just increase generated counter
    try:
        pui = PasscodesUsageInfo.objects.get(language=lang)
        pui.generated_passes += 1
    # Otherwise create a new record and initialize generated_passes to 1 and used_passes to 0
    except DoesNotExist:
        pui = PasscodesUsageInfo(language=lang , generated_passes=1, used_passes=0,
                                 total_pass_uses=0, revoked_passes=0)
    pui.save()

    qrcodes_inc = 1 if mode == "qr" else 0  # Increase/init value for center statistics, concerning qrcodes number

    # If passcodes for this medical center already exist in db, just increase generated counter
    try:
        cui = CenterUsageInfo.objects.get(center_id=center_id)
        cui.generated_passes += 1
        cui.qrcodes_generated += qrcodes_inc
    # Otherwise create a new record and initialize generated_passes to 1 and used_passes to 0
    except DoesNotExist:
        cui = CenterUsageInfo(center_id=center_id, generated_passes=1, used_passes=0,
                              total_pass_uses=0, revoked_passes=0, qrcodes_generated=qrcodes_inc)
    cui.save()

    qrcode_url = None
    if mode == "qr":
        # Default filetype is png for qrcode file
        ftype = ftype if ftype in ["svg", "png"] else "png"

        qrcode_url = generate_qr(request, passcode, app.config["QRCODES_DIR"], filetype=ftype)

    response = {"passcode": passcode, "qrcode_url": qrcode_url}

    disconnect(alias="default")

    # Must include the id of the pass in db in result

    return jsonify(response)


@app.route("/showpasses/<center_id>")
@jwt_required
@is_authorized(app.config["CENTER_SERVICES_ROLE"])
def show_passcodes(center_id):
    """ Return all passcode records created by specific center_id
    :param center_id: the id of the center
    :return: the passcode records, "belonging" to the specific center_id
    """

    connect(
        db=app.config["DB_NAME"],
        username=app.config["DB_USER"],
        password=app.config["DB_PASSWORD"],
        host=app.config["DB_HOST"],
        port=int(app.config["DB_PORT"]),
        alias="default"
    )

    try:
        passcodes = PassCode.objects(center_id=center_id)

    except DoesNotExist:
        passcodes = []

    # Encrypting the hashed passcodes to send them as request ids
    center_requests = [{"request_id": encrypt(app.config["SECRET_KEY"], pc.passcode),
                       "expiration_date": pc.expiration_date, "uses_left": pc.uses_left} for pc in passcodes]

    disconnect(alias="default")

    return jsonify(center_requests)


@app.route("/delpass", methods = ['POST'])
@jwt_required
@is_authorized(app.config["CENTER_SERVICES_ROLE"])
def delete_passcode():
    """ Revoke a passcode
    :return: status_code 200 on success, 404 on not found, 500 on other kind of failure
    """

    req_data = request.get_json()
    request_id = req_data.get("request_id")

    status_indication = {200: "OK", 404: "Not Found", 500: "Internal Server Error"}

    ret_val = 500

    connect(
        db=app.config["DB_NAME"],
        username=app.config["DB_USER"],
        password=app.config["DB_PASSWORD"],
        host=app.config["DB_HOST"],
        port=int(app.config["DB_PORT"]),
        alias="default"
    )

    # request_id is the hashed passcode encrypted, get it from show passcodes
    hashed_pass = decrypt(app.config["SECRET_KEY"], request_id)

    try:
        dbpass = PassCode.objects.get(passcode=hashed_pass)
        lang = dbpass.language
        dbpass.revoked = True
        dbpass.save()
        PasscodesUsageInfo.objects(language=lang).update_one(inc__revoked_passes=1)
        CenterUsageInfo.objects(center_id=dbpass.center_id).update_one(inc__revoked_passes=1)
        # dbpass.delete()
        # PasscodesUsageInfo.objects(language=lang).update_one(dec__generated_passes=1)
        ret_val = 200  # Success
    except DoesNotExist:
        ret_val = 404  # Failure


    # response = make_response(status_code)

    disconnect(alias="default")

    ret = {ret_val: status_indication.get(ret_val)}
    return jsonify(ret)


@app.route("/sendmsg", methods = ['POST'])
@jwt_required
@is_authorized(app.config["SEND_MSG_ROLE"])
def send_msg():
    req_data = request.get_json()
    passcode = req_data.get("passcode")
    phone_nums = req_data.get("phone_numbers")
    msg = req_data.get("msg")

    status_indication = {200: "OK", 404: "Not Found", 500: "Internal Server Error"}

    connect(
        db=app.config["DB_NAME"],
        username=app.config["DB_USER"],
        password=app.config["DB_PASSWORD"],
        host=app.config["DB_HOST"],
        port=int(app.config["DB_PORT"]),
        alias="default"
    )

    try:
        hashed_passcode = hash_passcode(passcode, app.config["SALT"])
        passcode = PassCode.objects.get(passcode=hashed_passcode.decode("utf-8"))

        # If passcode is in db and has not expired, then authorize user as sm_user
        if (not passcode.revoked) and passcode.expiration_date > datetime.now() and passcode.uses_left > 0:

            send_url = "{}/sms/send".format(app.config["SMS_SERVER"])
            #
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "api-key": "{}".format(app.config.get("SMS_API_KEY")),
            }

            response = requests.post(send_url, json={"numbers": phone_nums,
                                                     "message": msg}, headers=headers)

            ######################################### Check status code

            resp_json = response.json()
            resp_status = resp_json.get("status")
            resp_results = resp_json.get("results") or []

            if response.status_code == 200:
                # or (
                #         response.status_code == 500 and resp_status == "error" and not (
                #     all(x in resp_msg for x in phone_nums)))
                passcode.uses_left -= 1
                passcode.save()
                pui = PasscodesUsageInfo.objects(language=passcode.language).first()
                cui = CenterUsageInfo.objects(center_id=passcode.center_id).first()
                if passcode.uses_left == app.config["PASSCODE_MAX_USES"] - 1:
                    pui.used_passes += 1
                    cui.used_passes += 1
                pui.total_pass_uses += 1
                cui.total_pass_uses += 1
                pui.save()
                cui.save()
                # if resp_msg:
                #     error_nums = [num for num in phone_nums if num in resp_msg]

            successful_sends = [res.get("to") for res in resp_results if res.get("status") == "queued"]
            ret_val = response.status_code



    except DoesNotExist:
        ret_val = 404
        pass

    disconnect(alias="default")

    return jsonify(ret = {ret_val: status_indication.get(ret_val)}, data=successful_sends)



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7000)
