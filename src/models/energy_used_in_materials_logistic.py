from mongoengine import Document, StringField, BooleanField, FloatField


class EnergyUsedInMaterialsLogistic(Document):
    transported_material = StringField(null=True)
    provider = StringField(null=True)
    distance_by_delivery = FloatField(null=True)
    material_transported_mass = FloatField(null=True)
    vehicle_identification = StringField(null=True)
    vehicle_type = FloatField(null=True)
    own_vehicles = BooleanField(default=False)
    year = StringField(required=True)
    company_name = StringField(required=True)
