from mongoengine import Document, StringField


class Cleaning(Document):
    nitric_acid = StringField(null=True)
    phosphoric_acid = StringField(null=True)
    soda_liquid = StringField(null=True)
    solid_sodium_hydroxide = StringField(null=True)
    sodium_hypochlorite = StringField(null=True)
    sodium_sulfate = StringField(null=True)
    year = StringField(required=True)
    company_name = StringField(required=True)
