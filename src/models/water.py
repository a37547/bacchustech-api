from mongoengine import Document, IntField, StringField, DecimalField


class Water(Document):
    year = IntField(null=False)
    company_name = StringField(null=False)
    total_water_from_network = IntField(null=True)
    total_water_from_well = IntField(null=True)
    total_water_from_cistern = IntField(null=True)
    total_water_reused = IntField(null=True)
    number_of_cleaning_per_month_on_bottling_different_floors = IntField(
        null=True)
    number_of_cleaning_per_month_on_different_floors = IntField(null=True)
    number_of_cleaning_per_month_on_estabilization = IntField(null=True)
    number_of_cleaning_per_month_on_filling = IntField(null=True)
    number_of_cleaning_per_month_on_filtration = IntField(null=True)
    number_of_cleaning_per_month_on_labeling = IntField(null=True)
    number_of_cleaning_per_month_on_pressing = IntField(null=True)
    number_of_cleaning_per_month_on_sterilization = IntField(null=True)
    number_of_cleaning_per_month_on_trasfega = IntField(null=True)
    water_consumed_by_equipment_cleaning_on_bottling_different_floors = IntField(
        null=True)
    water_consumed_by_equipment_cleaning_on_different_floors = IntField(
        null=True)
    water_consumed_by_equipment_cleaning_on_estabilization = IntField(
        null=True)
    water_consumed_by_equipment_cleaning_on_filling = IntField(null=True)
    water_consumed_by_equipment_cleaning_on_filtration = IntField(null=True)
    water_consumed_by_equipment_cleaning_on_labeling = IntField(null=True)
    water_consumed_by_equipment_cleaning_on_pressing = IntField(null=True)
    water_consumed_by_equipment_cleaning_on_sterilization = IntField(null=True)
    water_consumed_by_equipment_cleaning_on_trasfega = IntField(null=True)

    ph_high_season_generated_water = DecimalField(null=True)
    ph_low_season_generated_water = DecimalField(null=True)
    conductivity_high_season_generated_water = DecimalField(null=True)
    conductivity_low_season_generated_water = DecimalField(null=True)
    turbidity_high_season_generated_water = DecimalField(null=True)
    turbidity_low_season_generated_water = DecimalField(null=True)
    CQO_high_season_generated_water = DecimalField(null=True)
    CQO_low_season_generated_water = DecimalField(null=True)
    CBO_high_season_generated_water = DecimalField(null=True)
    CBO_low_season_generated_water = DecimalField(null=True)
    SST_high_season_generated_water = DecimalField(null=True)
    SST_low_season_generated_water = DecimalField(null=True)
    NTK_high_season_generated_water = DecimalField(null=True)
    NTK_low_season_generated_water = DecimalField(null=True)
    fenois_high_season_generated_water = DecimalField(null=True)
    fenois_low_season_generated_water = DecimalField(null=True)
    fosforo_high_season_generated_water = DecimalField(null=True)
    fosforo_low_season_generated_water = DecimalField(null=True)
    nitratos_high_season_generated_water = DecimalField(null=True)
    nitratos_low_season_generated_water = DecimalField(null=True)
    sulfatos_high_season_generated_water = DecimalField(null=True)
    sulfatos_low_season_generated_water = DecimalField(null=True)
    ferro_high_season_generated_water = DecimalField(null=True)
    ferro_low_season_generated_water = DecimalField(null=True)
    aluminum_high_season_generated_water = DecimalField(null=True)
    aluminum_low_season_generated_water = DecimalField(null=True)
    cadmio_high_season_generated_water = DecimalField(null=True)
    cadmio_low_season_generated_water = DecimalField(null=True)
    cobre_high_season_generated_water = DecimalField(null=True)
    cobre_low_season_generated_water = DecimalField(null=True)
    cromio_high_season_generated_water = DecimalField(null=True)
    cromio_low_season_generated_water = DecimalField(null=True)
    manganes_high_season_generated_water = DecimalField(null=True)
    manganes_low_season_generated_water = DecimalField(null=True)

    ph_high_season_treated_water = DecimalField(null=True)
    ph_low_season_treated_water = DecimalField(null=True)
    conductivity_high_season_treated_water = DecimalField(null=True)
    conductivity_low_season_treated_water = DecimalField(null=True)
    turbidity_high_season_treated_water = DecimalField(null=True)
    turbidity_low_season_treated_water = DecimalField(null=True)
    CQO_high_season_treated_water = DecimalField(null=True)
    CQO_low_season_treated_water = DecimalField(null=True)
    CBO_high_season_treated_water = DecimalField(null=True)
    CBO_low_season_treated_water = DecimalField(null=True)
    SST_high_season_treated_water = DecimalField(null=True)
    SST_low_season_treated_water = DecimalField(null=True)
    NTK_high_season_treated_water = DecimalField(null=True)
    NTK_low_season_treated_water = DecimalField(null=True)
    fenois_high_season_treated_water = DecimalField(null=True)
    fenois_low_season_treated_water = DecimalField(null=True)
    fosforo_high_season_treated_water = DecimalField(null=True)
    fosforo_low_season_treated_water = DecimalField(null=True)
    nitratos_high_season_treated_water = DecimalField(null=True)
    nitratos_low_season_treated_water = DecimalField(null=True)
    sulfatos_high_season_treated_water = DecimalField(null=True)
    sulfatos_low_season_treated_water = DecimalField(null=True)
    ferro_high_season_treated_water = DecimalField(null=True)
    ferro_low_season_treated_water = DecimalField(null=True)
    aluminum_high_season_treated_water = DecimalField(null=True)
    aluminum_low_season_treated_water = DecimalField(null=True)
    cadmio_high_season_treated_water = DecimalField(null=True)
    cadmio_low_season_treated_water = DecimalField(null=True)
    cobre_high_season_treated_water = DecimalField(null=True)
    cobre_low_season_treated_water = DecimalField(null=True)
    cromio_high_season_treated_water = DecimalField(null=True)
    cromio_low_season_treated_water = DecimalField(null=True)
    manganes_high_season_treated_water = DecimalField(null=True)
    manganes_low_season_treated_water = DecimalField(null=True)
