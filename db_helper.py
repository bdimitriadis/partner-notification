from mongoengine import Document
from mongoengine import StringField
from mongoengine import IntField
from mongoengine import DateTimeField
from mongoengine import BooleanField


class PassCode(Document):
    """ The passcode
    """
    passcode = StringField(max_length=32, required=True, unique=True)  # The 32 "digit" passcode
    center_id = IntField(required=True)  # The id of the medical center that asked for the generation of this passcode
    language = StringField(max_length=2, required=True)  # Language used
    expiration_date = DateTimeField(required=True)  # Expiration date of the passcode
    uses_left = IntField(required=True)  # Counter showing how many times a user can still use the passcode
    revoked = BooleanField(required=True, default=False)


class PasscodesUsageInfo(Document):
    """ The usage statistics for each language, i.e. how many passcodes were generated
    and how many passcodes were used for each language.
    """
    language = StringField(max_length=2, required=True, unique=True)  # Language used
    generated_passes = IntField(required=True)  # Number of generated passcodes
    used_passes = IntField(required=True)  # Number of used passcodes
    total_pass_uses = IntField(required=True)  # Total uses of all passcodes for this language
    revoked_passes = IntField(required=True)  # Revoked passes


class CenterUsageInfo(Document):
    """ The usage statistics for each center, i.e. how many passcodes were generated
    and how many passcodes were revoked for each language.
    """
    center_id = IntField(required=True, unique=True)  # The id of the medical center
    generated_passes = IntField(required=True) # The total passes generated for this center
    used_passes = IntField(required=True)  # Number of used passcodes
    total_pass_uses = IntField(required=True)  # Counter showing how many times passcodes from this center have been used
    revoked_passes = IntField(required=True)  # Revoked passes for this center
    qrcodes_generated = IntField(required=True)  # qr_codes generated for this center


class AuthUser(Document):
    """ Users authenticated to use the services
    """
    username = StringField(max_length=10, required=True, unique=True)
    password = StringField(max_length=32, required=True)  # Hashed password