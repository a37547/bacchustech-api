from mongoengine import Document, StringField, BooleanField


class Company(Document):
    name = StringField(required=True)
    contact = StringField(required=True)
    address = StringField(required=True)
    responsableName = StringField(required=True)
    responsableUsername = StringField(required=True)
    responsableEmail = StringField(required=True)
    approved = BooleanField(null=True)
