from mongoengine import Document, StringField


class EnologicProducts(Document):
    citric_acid = StringField(null=True)
    tartric_acid = StringField(null=True)
    sorbic_acid = StringField(null=True)
    other_acids = StringField(null=True)
    bentonita_caulim = StringField(null=True)
    potassium_bissulfit = StringField(null=True)
    calcium_carbonate = StringField(null=True)
    wood_chips = StringField(null=True)
    arabic_goma = StringField(null=True)
    milk_proteins = StringField(null=True)
    salmoura = StringField(null=True)
    liquid_so2 = StringField(null=True)
    sugar = StringField(null=True)
    taninos = StringField(null=True)
    amonium_sulfate = StringField(null=True)
    diatomito = StringField(null=True)
    etanol = StringField(null=True)
    ovalbumina = StringField(null=True)
    microorganisms = StringField(null=True)
    year = StringField(required=True)
    company_name = StringField(required=True)
