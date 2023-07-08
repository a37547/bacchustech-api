from mongoengine import Document, StringField


class Year(Document):
    year = StringField(required=True)
    company_name = StringField(required=True)
