from mongoengine import Document, StringField, DecimalField


class GeneralData(Document):
    total_grapes_produced = StringField(null=True)
    total_grapes_bought = StringField(null=True)
    total_must_purchased = StringField(null=True)
    total_must_fermented = StringField(null=True)
    brix = StringField(null=True)
    total_must_produced_from_grapes = StringField(null=True)
    total_wine_produced = DecimalField(null=True)
    glass_bottles_35 = DecimalField(null=True)
    glass_bottles_75 = DecimalField(null=True)
    glass_bottles_100 = DecimalField(null=True)
    pet_bottles = DecimalField(null=True)
    bag_in_box_3 = DecimalField(null=True)
    bag_in_box_5 = DecimalField(null=True)
    year = StringField(required=True)
    company_name = StringField(required=True)
