from mongoengine import Document, StringField


class Packing(Document):
    glass_bottles = StringField(null=True)
    pet_bottles = StringField(null=True)
    labels = StringField(null=True)
    corks = StringField(null=True)
    wine_muzzles = StringField(null=True)
    capsules = StringField(null=True)
    aluminum_sheets = StringField(null=True)
    polyethylene_sheets = StringField(null=True)
    crown_caps = StringField(null=True)
    aluminum_crown_caps = StringField(null=True)
    bidule = StringField(null=True)
    aluminum_screw_caps = StringField(null=True)
    pvc = StringField(null=True)
    ldpe_film_wraps = StringField(null=True)
    ldpe_pallet_wraps = StringField(null=True)
    boxes = StringField(null=True)
    year = StringField(required=True)
    company_name = StringField(required=True)
