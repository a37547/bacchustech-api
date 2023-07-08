from mongoengine import Document, StringField


class Report(Document):
    grapes_produced_percentage = StringField(null=True)
    grapes_bought_percentage = StringField(null=True)
    year = StringField(required=True)
    company_name = StringField(required=True)
