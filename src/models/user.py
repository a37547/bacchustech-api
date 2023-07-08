from mongoengine import Document, StringField, BooleanField


class User(Document):
    name = StringField(required=True)
    username = StringField(required=True)
    email = StringField(required=True)
    password = StringField(required=True)
    is_active = BooleanField(default=True)
    access_token = StringField(null=True)
    first_login = BooleanField(default=True)
    company = StringField(null=True)
    isAdmin = BooleanField(default=False)
