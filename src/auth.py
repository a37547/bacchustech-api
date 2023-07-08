import re
import json
from flask import Blueprint, request
from src.models.report import Report
from src.models.company import Company
from src.models.energy import Energy
from src.models.water import Water
from src.models.energy_used_in_materials_logistic import EnergyUsedInMaterialsLogistic
from src.models.general_data import GeneralData
from src.models.system_admin import SystemAdmin
from src.models.user import User
from src.models.waste import Waste
from src.models.year import Year
from src.models.materials import Materials
from flask_mail import Message
from .extensions import mail
from .extensions import bcrypt
from .extensions import session_flask_session
from werkzeug.security import check_password_hash, generate_password_hash
from passlib.hash import sha256_crypt
import jwt
import datetime
from mongoengine.queryset.visitor import Q

auth = Blueprint("users", __name__, url_prefix="/api/users")
companies = Blueprint("companies", __name__, url_prefix="/api/companies")
general_data = Blueprint("generalData", __name__,
                         url_prefix="/api/generalData")
reports = Blueprint("reports", __name__, url_prefix="/api/reports")


@reports.route('/create', methods=['POST'])
def create_report():
    year = request.json['year']
    company_name = request.json['company_name']
    grapes_produced_percentage = request.json['grapes_produced_percentage']
    grapes_bought_percentage = request.json['grapes_bought_percentage']

    new_report = Report(year=year, company_name=company_name,
                        grapes_bought_percentage=grapes_bought_percentage,
                        grapes_produced_percentage=grapes_produced_percentage
                        )

    new_report.save()
    return {"Result": 0, "Message": "Relatório criado com sucesso"}


@reports.route('/update/<year>/<company>', methods=['PUT'])
def update_report(year, company):
    Report.objects(
        Q(year=year) & Q(company_name=company)).update(
            grapes_produced_percentage=request.json["grapes_produced_percentage"],
            grapes_bought_percentage=request.json["grapes_bought_percentage"]
    )

    return {"Result": 0, "Year": year, "Message": "Relatório editado com sucesso"}


@reports.route('/getByYearAndCompany', methods=['GET'])
def get_report_by_year_and_company():
    year = request.args.get('year')
    company = request.args.get('company_name')

    report = Report.objects(
        Q(year=year) & Q(company_name=company)).first()

    if report == None:
        return {"Result": 1, "Data": None}
    else:
        return {"Result": 0, "Data": json.loads(report.to_json())}


@general_data.route('/create', methods=['POST'])
def create_general_data():
    year = request.json['year']
    company_name = request.json['company_name']
    total_grapes_produced = request.json['total_grapes_produced']
    total_grapes_bought = request.json['total_grapes_bought']
    total_must_purchased = request.json['total_must_purchased']
    total_must_fermented = request.json['total_must_fermented']
    brix = request.json['brix']
    total_must_produced_from_grapes = request.json['total_must_produced_from_grapes']
    total_wine_produced = request.json['total_wine_produced']
    glass_bottles_35 = request.json['glass_bottles_35']
    glass_bottles_75 = request.json['glass_bottles_75']
    glass_bottles_100 = request.json['glass_bottles_100']
    pet_bottles = request.json['pet_bottles']
    bag_in_box_3 = request.json['bag_in_box_3']
    bag_in_box_5 = request.json['bag_in_box_5']

    new_general_data = GeneralData(year=year, company_name=company_name,
                                   total_grapes_produced=total_grapes_produced, total_grapes_bought=total_grapes_bought,
                                   total_must_purchased=total_must_purchased, total_must_fermented=total_must_fermented,
                                   brix=brix, total_must_produced_from_grapes=total_must_produced_from_grapes,
                                   total_wine_produced=total_wine_produced, glass_bottles_35=glass_bottles_35,
                                   glass_bottles_75=glass_bottles_75, glass_bottles_100=glass_bottles_100,
                                   pet_bottles=pet_bottles, bag_in_box_3=bag_in_box_3, bag_in_box_5=bag_in_box_5)

    new_general_data.save()
    return {"Result": 0, "Message": "Dados gerais criados com sucesso"}


@general_data.route('/update/<year>/<company>', methods=['PUT'])
def update_general_data(year, company):
    GeneralData.objects(
        Q(year=year) & Q(company_name=company)).update(
            total_grapes_produced=request.json["total_grapes_produced"],
            total_grapes_bought=request.json["total_grapes_bought"],
            total_must_purchased=request.json["total_must_purchased"],
            total_must_fermented=request.json["total_must_fermented"],
            brix=request.json["brix"],
            total_must_produced_from_grapes=request.json["total_must_produced_from_grapes"],
            total_wine_produced=request.json["total_wine_produced"],
            glass_bottles_35=request.json["glass_bottles_35"],
            glass_bottles_75=request.json["glass_bottles_75"],
            glass_bottles_100=request.json["glass_bottles_100"],
            pet_bottles=request.json["pet_bottles"],
            bag_in_box_3=request.json["bag_in_box_3"],
            bag_in_box_5=request.json["bag_in_box_5"]
    )

    return {"Result": 0, "Year": year, "Message": "Dados gerais editados com sucesso"}


@general_data.route('/getByYearAndCompany', methods=['GET'])
def get_general_data_by_year_and_company():
    year = request.args.get('year')
    company = request.args.get('company_name')

    general_data = GeneralData.objects(
        Q(year=year) & Q(company_name=company)).first()

    if general_data == None:
        return {"Result": 1, "Data": None}
    else:
        return {"Result": 0, "Data": json.loads(general_data.to_json())}


@companies.route('/create', methods=['POST'])
def create_company():
    name = request.json['name']
    contact = request.json['contact']
    address = request.json['address']
    responsableName = request.json['responsableName']
    responsableUsername = request.json['responsableUsername']
    responsableEmail = request.json['responsableEmail']

    # validate if all fields are filled
    for arg in request.json:
        if (request.json[arg] == ''):
            return {"Result": 2, "Message": "O campo " + arg + " é obrigatório", "Data": []}

    # if the code reaches this part, then all fields were filled

    # check if the company is already registered
    company = Company.objects(name=name)
    data = company.to_json()
    json_data = {"Data": json.loads(data)}

    # the company given is not yet registered so let's register it
    if len(json_data["Data"]) == 0:
        newCompany = Company(name=name, contact=contact, address=address, responsableName=responsableName,
                             responsableUsername=responsableUsername, responsableEmail=responsableEmail)
        newCompany.save()
        return {"Result": 0, "Message": "Empresa registada com sucesso"}
    else:
        return {"Result": 2, "Message": "Erro ao registar a empresa - a empresa já está registada"}


@auth.route('/register', methods=['POST'])
def register():
    company_name = request.json['company_name']
    contact = request.json['contact']
    company_address = request.json['company_address']
    name = request.json['name']
    username = request.json['username']
    email = request.json['email']
    password = request.json['password']

    # validate if all fields are filled
    for arg in request.json:
        if (request.json[arg] == ''):
            return {"Result": 2, "Message": "O campo " + arg + " é obrigatório", "Data": []}

    # if the code reaches this part, then all fields were filled

    # validate if contact has 9 numbers
    if (len(contact) != 9 or not contact.isdigit()):
        return {"Result": 2, "Message": "O campo contact tem de ter 9 números", "Data": []}

    # validate if email is valid
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if (not re.fullmatch(regex, email)):
        return {"Result": 2, "Message": "O campo email deve ser um email válido", "Data": []}

    # if the code reaches this part, then all fields were filled and are valid

    # check if the email is already registered
    user = User.objects(email=email)
    data = user.to_json()
    json_data = {"Data": json.loads(data)}

    # check if the company is already registered
    company = Company.objects(name=company_name)
    data2 = company.to_json()
    json_data2 = {"Data": json.loads(data2)}

    # the email given is not yet registered so let's register it
    if len(json_data["Data"]) == 0 and len(json_data2["Data"]) == 0:
        newUser = User(name=name, username=username, email=email,
                       password=password, company=company_name)

        newUser.save()
        return {"Result": 0, "Message": "Utilizador registado com sucesso"}
    # the email given is already registered
    else:
        return {"Result": 2, "Message": "Utilizador e/ou empresa já registado."}


@auth.route('/getCompaniesToApprove', methods=['GET'])
def get_approved_companies():
    if isUserAuthenticated(request.headers.get('Authorization'))["Success"] is not True:
        return {"Result": 2, "Message": "Utilizador não autenticado"}
    else:
        companies = Company.objects(approved=None)
        data = companies.to_json()
        json_data = json.loads(data)
        return {"Result": 0, "Message": "", "Data": json_data}


@auth.route('/setCompanyApprovedState/<name>', methods=['PUT'])
def set_company_approved_state(name):
    if isUserAuthenticated(request.headers.get('Authorization'))["Success"] is not True:
        return {"Result": 2, "Message": "Utilizador não autenticado"}
    else:
        Company.objects(name=name).update(
            approved=request.json['approved'])
        return {"Result": 0, "Message": "A empresa foi aprovada."}


@auth.route('sendEmailAfterSuccessfullRegister', methods=['POST'])
def send_email_after_successfull_register():
    # user = User.objects(email="email2@teste.com").first()
    # return isUserAuthenticated(user, request.json["token"])
    # return {"data": user["access_token"]}
    # checkIfTokenIsValid()
    msg = Message('BacchusTech - Registo efetuado pendente', sender='bb6e8301cdbd3a',
                  recipients=['marcobaiao26@hotmail.com'])
    msg.body = "O registo na plataforma BacchusTech foi efetuado com sucesso. Contudo, apenas após aprovação por parte do administrador do sistema poderá entrar na plataforma"
    mail.send(msg)
    return {"Result": 0, "Message": "Email enviado com sucesso"}


@auth.route('/sendEmailAfterApproval', methods=['POST'])
def send_email_after_approval():
    msg = Message('BacchusTech - Registo aprovado', sender='bb6e8301cdbd3a',
                  recipients=['marcobaiao26@hotmail.com'])
    msg.body = "O registo na plataforma BacchusTech foi aprovado. Poderá agora entrar na plataforma com os dados com que se registou"
    mail.send(msg)
    return {"Result": 0, "Message": "Email enviado com sucesso"}


@auth.route('/createSystemAdmin', methods=['POST'])
def create_system_admin():
    name = request.json['name']
    username = request.json['username']
    email = request.json['email']
    password = request.json['password']
    is_active = request.json['is_active']

    new_system_admin = SystemAdmin(name=name, username=username, email=email,
                                   password=password, is_active=is_active)

    new_system_admin.save()
    return {"Result": 0, "Message": "Administrador de sistema adicionado com sucesso"}


@auth.route('/login', methods=['POST'])
def login():
    email = request.json['email']
    password = request.json['password']

    user = User.objects(email=email).first()
    system_admin = SystemAdmin.objects(email=email).first()

    if user == None:
        if system_admin == None:
            return {"Result": 1, "Message": "O utilizador com o email inserido não existe"}
        else:
            if system_admin["is_active"] is not True:
                return {"Result": 1, "Message": "O utilizador não está ativo"}
            else:
                if bcrypt.check_password_hash(system_admin["password"], password) is not True:
                    return {"Result": 1, "Message": "Email e palavra-passe não coincidem"}
                else:
                    payload = {
                        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, minutes=15, seconds=15),
                        'iat': datetime.datetime.utcnow(),
                        'sub': system_admin["email"],
                        'user': {"email": system_admin["email"], "name": system_admin["name"]}
                    }

                    encoded_jwt = jwt.encode(
                        payload, "secret", algorithm="HS256")

                    system_admin.update(access_token=encoded_jwt)
                    return {"Result": 0, "Message": "Login válido", "Token": encoded_jwt, "Success": True}
    else:
        company = Company.objects(name=user["company"]).first()
        if company["approved"] is not True:
            return {"Result": 1, "Message": "A empresa não foi aprovada"}
        else:
            if user["is_active"] is not True:
                return {"Result": 1, "Message": "O utilizador não está activo"}
            else:
                if bcrypt.check_password_hash(user["password"], password) is not True:
                    return {"Result": 1, "Message": "Email e password não coincidem"}
                else:
                    payload = {
                        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, minutes=15, seconds=15),
                        'iat': datetime.datetime.utcnow(),
                        'sub': user["email"],
                        'user': {"email": user["email"], "name": user["name"], "company": user["company"]}
                    }

                    encoded_jwt = jwt.encode(
                        payload, "secret", algorithm="HS256")

                    user.update(access_token=encoded_jwt)
                    return {"Result": 0, "Message": "Login válido", "Token": encoded_jwt, "Success": True}


def checkIfTokenIsValid(token):
    try:
        payload = jwt.decode(token, "secret", algorithms=["HS256"])
        return {"Result": True, "Message": payload["sub"]}
    except jwt.ExpiredSignatureError:
        return {"Result": False, "Message": 'Signature expired. Please log in again.'}
    except jwt.InvalidTokenError:
        return {"Result": False, "Message": 'Invalid token. Please log in again.'}


def isUserAuthenticated(token):
    user = User.objects(access_token=token).first()
    system_admin = SystemAdmin.objects(access_token=token).first()

    if user == None:
        if system_admin != None and system_admin["is_active"] and token == system_admin["access_token"] and checkIfTokenIsValid(system_admin["access_token"])["Result"]:
            return {"Result": 0, "Message": "User autenticado", "Success": True}
        else:
            return {"Result": 2, "Message": "User não autenticado", "Success": False}

    else:
        if user != None and user["is_active"] and token == user["access_token"] and checkIfTokenIsValid(user["access_token"])["Result"]:
            return {"Result": 0, "Message": "User autenticado", "Success": True}
        else:
            return {"Result": 2, "Message": "User não autenticado", "Success": False}


@auth.route('/getYearsByCompany', methods=['GET'])
def get_years_by_company():
    company_name = request.args.get('company_name')

    years = Year.objects(company_name=company_name)
    data = years.to_json()
    json_data = json.loads(data)

    return {"Result": 0, "Data": json_data}


@auth.route('/addYearToCompany', methods=['POST'])
def add_year_to_company():
    year = request.json["year"]
    company_name = request.json["company_name"]

    newYear = Year(year=year, company_name=company_name)

    newYear.save()

    return {"Result": 0, "Message": "Ano adicionado com successo"}


@auth.route('/getMaterialsByYearAndCompany', methods=['GET'])
def get_materials_by_year_and_company():
    year = request.args.get('year')
    company = request.args.get('company_name')

    materials = Materials.objects(
        Q(year=year) & Q(company_name=company)).first()

    if materials == None:
        return {"Result": 1, "Data": None}
    else:
        return {"Result": 0, "Data": json.loads(materials.to_json())}


@auth.route('/createMaterials', methods=['POST'])
def create_materials():
    year = request.json['year']
    company_name = request.json['company_name']
    citric_acid = request.json['citric_acid']
    tartric_acid = request.json['tartric_acid']
    sorbic_acid = request.json['sorbic_acid']
    other_acids = request.json['other_acids']
    bentonita_caulim = request.json['bentonita_caulim']
    potassium_bissulfit = request.json['potassium_bissulfit']
    calcium_carbonate = request.json['calcium_carbonate']
    wood_chips = request.json['wood_chips']
    arabic_goma = request.json['arabic_goma']
    milk_proteins = request.json['milk_proteins']
    salmoura = request.json['salmoura']
    liquid_so2 = request.json['liquid_so2']
    sugar = request.json['sugar']
    taninos = request.json['taninos']
    amonium_sulfate = request.json['amonium_sulfate']
    diatomito = request.json['diatomito']
    etanol = request.json['etanol']
    ovalbumina = request.json['ovalbumina']
    microorganisms = request.json['microorganisms']
    glass_bottles = request.json['glass_bottles']
    pet_bottles = request.json['pet_bottles']
    labels = request.json['labels']
    corks = request.json['corks']
    wine_muzzles = request.json['wine_muzzles']
    capsules = request.json['capsules']
    aluminum_sheets = request.json['aluminum_sheets']
    polyethylene_sheets = request.json['polyethylene_sheets']
    crown_caps = request.json['crown_caps']
    aluminum_crown_caps = request.json['aluminum_crown_caps']
    bidule = request.json['bidule']
    aluminum_screw_caps = request.json['aluminum_screw_caps']
    pvc = request.json['pvc']
    ldpe_film_wraps = request.json['ldpe_film_wraps']
    ldpe_pallet_wraps = request.json['ldpe_pallet_wraps']
    boxes = request.json['boxes']
    glass_bottles_percentage = request.json['glass_bottles_percentage']
    pet_bottles_percentage = request.json['pet_bottles_percentage']
    labels_percentage = request.json['labels_percentage']
    corks_percentage = request.json['corks_percentage']
    wine_muzzles_percentage = request.json['wine_muzzles_percentage']
    capsules_percentage = request.json['capsules_percentage']
    aluminum_sheets_percentage = request.json['aluminum_sheets_percentage']
    polyethylene_sheets_percentage = request.json['polyethylene_sheets_percentage']
    crown_caps_percentage = request.json['crown_caps_percentage']
    aluminum_crown_caps_percentage = request.json['aluminum_crown_caps_percentage']
    bidule_percentage = request.json['bidule_percentage']
    aluminum_screw_caps_percentage = request.json['aluminum_screw_caps_percentage']
    pvc_percentage = request.json['pvc_percentage']
    ldpe_film_wraps_percentage = request.json['ldpe_film_wraps_percentage']
    ldpe_pallet_wraps_percentage = request.json['ldpe_pallet_wraps_percentage']
    boxes_percentage = request.json['boxes_percentage']
    nitric_acid = request.json['nitric_acid']
    phosphoric_acid = request.json['phosphoric_acid']
    soda_liquid = request.json['soda_liquid']
    solid_sodium_hydroxide = request.json['solid_sodium_hydroxide']
    sodium_hypochlorite = request.json['sodium_hypochlorite']
    sodium_sulfate = request.json['sodium_sulfate']
    antifoam_products = request.json['antifoam_products']
    grease = request.json['grease']
    lubricant_oil_equipment_maintenance = request.json['lubricant_oil_equipment_maintenance']

    new_materials = Materials(year=year, company_name=company_name, citric_acid=citric_acid, tartric_acid=tartric_acid, sorbic_acid=sorbic_acid,
                              other_acids=other_acids, bentonita_caulim=bentonita_caulim, potassium_bissulfit=potassium_bissulfit, calcium_carbonate=calcium_carbonate,
                              wood_chips=wood_chips, arabic_goma=arabic_goma, milk_proteins=milk_proteins, salmoura=salmoura, liquid_so2=liquid_so2,
                              sugar=sugar, taninos=taninos, amonium_sulfate=amonium_sulfate, diatomito=diatomito, etanol=etanol, ovalbumina=ovalbumina,
                              microorganisms=microorganisms, glass_bottles=glass_bottles,
                              pet_bottles=pet_bottles, labels=labels,
                              corks=corks, wine_muzzles=wine_muzzles,
                              capsules=capsules,
                              aluminum_sheets=aluminum_sheets,
                              polyethylene_sheets=polyethylene_sheets,
                              crown_caps=crown_caps,
                              aluminum_crown_caps=aluminum_crown_caps,
                              bidule=bidule,
                              aluminum_screw_caps=aluminum_screw_caps,
                              pvc=pvc,
                              ldpe_film_wraps=ldpe_film_wraps,
                              ldpe_pallet_wraps=ldpe_pallet_wraps,
                              boxes=boxes, glass_bottles_percentage=glass_bottles_percentage,
                              pet_bottles_percentage=pet_bottles_percentage, labels_percentage=labels_percentage,
                              corks_percentage=corks_percentage, wine_muzzles_percentage=wine_muzzles_percentage,
                              capsules_percentage=capsules_percentage,
                              aluminum_sheets_percentage=aluminum_sheets_percentage,
                              polyethylene_sheets_percentage=polyethylene_sheets_percentage,
                              crown_caps_percentage=crown_caps_percentage,
                              aluminum_crown_caps_percentage=aluminum_crown_caps_percentage,
                              bidule_percentage=bidule_percentage,
                              aluminum_screw_caps_percentage=aluminum_screw_caps_percentage,
                              pvc_percentage=pvc_percentage,
                              ldpe_film_wraps_percentage=ldpe_film_wraps_percentage,
                              ldpe_pallet_wraps_percentage=ldpe_pallet_wraps_percentage,
                              boxes_percentage=boxes_percentage,
                              nitric_acid=nitric_acid,
                              phosphoric_acid=phosphoric_acid,
                              soda_liquid=soda_liquid,
                              solid_sodium_hydroxide=solid_sodium_hydroxide,
                              sodium_hypochlorite=sodium_hypochlorite,
                              sodium_sulfate=sodium_sulfate,
                              antifoam_products=antifoam_products,
                              grease=grease,
                              lubricant_oil_equipment_maintenance=lubricant_oil_equipment_maintenance)

    new_materials.save()
    return {"Result": 0, "Message": "Materiais adicionados com sucesso"}


@auth.route('/updateMaterials/<year>/<company>', methods=['PUT'])
def update_materials(year, company):
    Materials.objects(
        Q(year=year) & Q(company_name=company)).update(citric_acid=request.json["citric_acid"],
                                                       tartric_acid=request.json["tartric_acid"],
                                                       sorbic_acid=request.json["sorbic_acid"],
                                                       other_acids=request.json["other_acids"],
                                                       bentonita_caulim=request.json["bentonita_caulim"],
                                                       potassium_bissulfit=request.json["potassium_bissulfit"],
                                                       calcium_carbonate=request.json["calcium_carbonate"],
                                                       wood_chips=request.json["wood_chips"],
                                                       arabic_goma=request.json["arabic_goma"],
                                                       milk_proteins=request.json["milk_proteins"],
                                                       salmoura=request.json["salmoura"],
                                                       liquid_so2=request.json["liquid_so2"],
                                                       sugar=request.json["sugar"],
                                                       taninos=request.json["taninos"],
                                                       amonium_sulfate=request.json["amonium_sulfate"],
                                                       diatomito=request.json["diatomito"],
                                                       etanol=request.json["etanol"],
                                                       ovalbumina=request.json["ovalbumina"],
                                                       microorganisms=request.json["microorganisms"],
                                                       glass_bottles=request.json["glass_bottles"],
                                                       pet_bottles=request.json["pet_bottles"],
                                                       labels=request.json["labels"],
                                                       corks=request.json["corks"],
                                                       wine_muzzles=request.json["wine_muzzles"],
                                                       capsules=request.json["capsules"],
                                                       aluminum_sheets=request.json["aluminum_sheets"],
                                                       polyethylene_sheets=request.json["polyethylene_sheets"],
                                                       crown_caps=request.json["crown_caps"],
                                                       aluminum_crown_caps=request.json["aluminum_crown_caps"],
                                                       bidule=request.json["bidule"],
                                                       aluminum_screw_caps=request.json["aluminum_screw_caps"],
                                                       pvc=request.json["pvc"],
                                                       ldpe_film_wraps=request.json["ldpe_film_wraps"],
                                                       ldpe_pallet_wraps=request.json["ldpe_pallet_wraps"],
                                                       boxes=request.json["boxes"],
                                                       glass_bottles_percentage=request.json[
                                                           "glass_bottles_percentage"],
                                                       pet_bottles_percentage=request.json["pet_bottles_percentage"],
                                                       labels_percentage=request.json["labels_percentage"],
                                                       corks_percentage=request.json["corks_percentage"],
                                                       wine_muzzles_percentage=request.json[
                                                           "wine_muzzles_percentage"],
                                                       capsules_percentage=request.json["capsules_percentage"],
                                                       aluminum_sheets_percentage=request.json[
                                                           "aluminum_sheets_percentage"],
                                                       polyethylene_sheets_percentage=request.json[
                                                           "polyethylene_sheets_percentage"],
                                                       crown_caps_percentage=request.json["crown_caps_percentage"],
                                                       aluminum_crown_caps_percentage=request.json[
                                                           "aluminum_crown_caps_percentage"],
                                                       bidule_percentage=request.json["bidule_percentage"],
                                                       aluminum_screw_caps_percentage=request.json[
                                                           "aluminum_screw_caps_percentage"],
                                                       pvc_percentage=request.json["pvc_percentage"],
                                                       ldpe_film_wraps_percentage=request.json[
                                                           "ldpe_film_wraps_percentage"],
                                                       ldpe_pallet_wraps_percentage=request.json[
                                                           "ldpe_pallet_wraps_percentage"],
                                                       boxes_percentage=request.json["boxes_percentage"],
                                                       nitric_acid=request.json["nitric_acid"],
                                                       phosphoric_acid=request.json["phosphoric_acid"],
                                                       soda_liquid=request.json["soda_liquid"],
                                                       solid_sodium_hydroxide=request.json["solid_sodium_hydroxide"],
                                                       sodium_hypochlorite=request.json["sodium_hypochlorite"],
                                                       sodium_sulfate=request.json["sodium_sulfate"],
                                                       antifoam_products=request.json["antifoam_products"],
                                                       grease=request.json["grease"],
                                                       lubricant_oil_equipment_maintenance=request.json["lubricant_oil_equipment_maintenance"])

    return {"Result": 0, "Year": year, "Message": "Materiais editados com sucesso"}


@auth.route('/createEnergy', methods=['POST'])
def create_energy():
    year = request.json['year']
    company_name = request.json['company_name']
    consumed_electricity_bought = request.json['consumed_electricity_bought']
    natural_gas_bought = request.json['natural_gas_bought']
    diesel_bought = request.json['diesel_bought']
    fuel_oil_bought = request.json['fuel_oil_bought']
    nuclear_bought = request.json['nuclear_bought']
    coal_bought = request.json['coal_bought']
    wind_energy_bought = request.json['wind_energy_bought']
    hidrelectric_bought = request.json['hidrelectric_bought']
    solar_bought = request.json['solar_bought']
    biomass_bought = request.json['biomass_bought']
    biogas_bought = request.json['biogas_bought']
    solid_waste_incineration_bought = request.json['solid_waste_incineration_bought']
    consumed_electricity_produced = request.json['consumed_electricity_produced']
    hidrelectric_produced = request.json['hidrelectric_produced']
    solar_produced = request.json['solar_produced']
    biomass_produced = request.json['biomass_produced']
    biogas_produced = request.json['biogas_produced']
    surplus_entered = request.json['surplus_entered']
    pure_diesel_used_in_company = request.json['pure_diesel_used_in_company']
    pure_gasoline_used_in_company = request.json['pure_gasoline_used_in_company']
    biofuel_used_in_company = request.json['biofuel_used_in_company']
    lubricant_used_in_company = request.json['lubricant_used_in_company']
    butane_used_in_company = request.json['butane_used_in_company']
    propane_used_in_company = request.json['propane_used_in_company']
    gpl_auto_used_in_company = request.json['gpl_auto_used_in_company']
    natural_gas_used_in_company = request.json['natural_gas_used_in_company']
    biogas_used_in_company = request.json['biogas_used_in_company']
    wood_used_in_company = request.json['wood_used_in_company']
    pellets_used_in_company = request.json['pellets_used_in_company']

    new_energy = Energy(year=year, company_name=company_name, consumed_electricity_bought=consumed_electricity_bought,
                        natural_gas_bought=natural_gas_bought, diesel_bought=diesel_bought, fuel_oil_bought=fuel_oil_bought,
                        nuclear_bought=nuclear_bought, coal_bought=coal_bought, wind_energy_bought=wind_energy_bought,
                        hidrelectric_bought=hidrelectric_bought, solar_bought=solar_bought, biomass_bought=biomass_bought,
                        biogas_bought=biogas_bought, solid_waste_incineration_bought=solid_waste_incineration_bought,
                        consumed_electricity_produced=consumed_electricity_produced,
                        hidrelectric_produced=hidrelectric_produced, solar_produced=solar_produced,
                        biomass_produced=biomass_produced, biogas_produced=biogas_produced,
                        surplus_entered=surplus_entered, pure_diesel_used_in_company=pure_diesel_used_in_company,
                        pure_gasoline_used_in_company=pure_gasoline_used_in_company, biofuel_used_in_company=biofuel_used_in_company,
                        lubricant_used_in_company=lubricant_used_in_company,
                        butane_used_in_company=butane_used_in_company, propane_used_in_company=propane_used_in_company,
                        gpl_auto_used_in_company=gpl_auto_used_in_company, natural_gas_used_in_company=natural_gas_used_in_company,
                        biogas_used_in_company=biogas_used_in_company, wood_used_in_company=wood_used_in_company,
                        pellets_used_in_company=pellets_used_in_company)

    new_energy.save()
    return {"Result": 0}


@auth.route('/getEnergyByYearAndCompany', methods=['GET'])
def get_energy_by_year_and_company():
    year = request.args.get('year')
    company = request.args.get('company_name')

    energy = Energy.objects(
        Q(year=year) & Q(company_name=company)).first()

    if energy == None:
        return {"Result": 1, "Data": None}
    else:
        return {"Result": 0, "Data": json.loads(energy.to_json())}


@auth.route('/updateEnergy/<year>/<company>', methods=['PUT'])
def update_energy(year, company):
    Energy.objects(
        Q(year=year) & Q(company_name=company)).update(consumed_electricity_bought=request.json["consumed_electricity_bought"],
                                                       natural_gas_bought=request.json["natural_gas_bought"],
                                                       diesel_bought=request.json["diesel_bought"],
                                                       fuel_oil_bought=request.json["fuel_oil_bought"],
                                                       nuclear_bought=request.json["nuclear_bought"],
                                                       coal_bought=request.json["coal_bought"],
                                                       wind_energy_bought=request.json["wind_energy_bought"],
                                                       hidrelectric_bought=request.json["hidrelectric_bought"],
                                                       solar_bought=request.json["solar_bought"],
                                                       biomass_bought=request.json["biomass_bought"],
                                                       biogas_bought=request.json["biogas_bought"],
                                                       solid_waste_incineration_bought=request.json[
                                                           "solid_waste_incineration_bought"],
                                                       consumed_electricity_produced=request.json[
                                                           "consumed_electricity_produced"],
                                                       hidrelectric_produced=request.json["hidrelectric_produced"],
                                                       solar_produced=request.json["solar_produced"],
                                                       biomass_produced=request.json["biomass_produced"],
                                                       biogas_produced=request.json["biogas_produced"],
                                                       surplus_entered=request.json["surplus_entered"],
                                                       pure_diesel_used_in_company=request.json[
                                                           "pure_diesel_used_in_company"],
                                                       pure_gasoline_used_in_company=request.json[
                                                           "pure_gasoline_used_in_company"],
                                                       biofuel_used_in_company=request.json[
                                                           "biofuel_used_in_company"],
                                                       lubricant_used_in_company=request.json[
                                                           "lubricant_used_in_company"],
                                                       butane_used_in_company=request.json["butane_used_in_company"],
                                                       propane_used_in_company=request.json[
                                                           "propane_used_in_company"],
                                                       gpl_auto_used_in_company=request.json[
                                                           "gpl_auto_used_in_company"],
                                                       natural_gas_used_in_company=request.json[
                                                           "natural_gas_used_in_company"],
                                                       biogas_used_in_company=request.json["biogas_used_in_company"],
                                                       wood_used_in_company=request.json["wood_used_in_company"],
                                                       pellets_used_in_company=request.json["pellets_used_in_company"])

    return {"Result": 0, "Year": year}


@auth.route('/getEnergyUsedInMaterialsLogisticByYearAndCompany', methods=['GET'])
def get_energy_used_in_materials_logistic_by_year_and_company():
    year = request.args.get('year')
    company = request.args.get('company_name')

    energy = EnergyUsedInMaterialsLogistic.objects(
        Q(year=year) & Q(company_name=company)).first()

    if energy == None:
        return {"Result": 1, "Data": None}
    else:
        return {"Result": 0, "Data": json.loads(energy.to_json())}


@auth.route('/createEnergyUsedInMaterialsLogistic', methods=['POST'])
def create_energy_used_in_materials_logistic():
    year = request.json['year']
    company_name = request.json['company_name']
    transported_material = request.json['transported_material']
    provider = request.json['provider']
    distance_by_delivery = request.json['distance_by_delivery']
    material_transported_mass = request.json['material_transported_mass']
    vehicle_identification = request.json['vehicle_identification']
    vehicle_type = request.json['vehicle_type']
    own_vehicles = request.json['own_vehicles']

    energy = EnergyUsedInMaterialsLogistic(year=year, company_name=company_name, transported_material=transported_material,
                                           provider=provider, distance_by_delivery=distance_by_delivery,
                                           material_transported_mass=material_transported_mass, vehicle_identification=vehicle_identification,
                                           vehicle_type=vehicle_type, own_vehicles=own_vehicles)

    energy.save()
    return {"Result": 0, "Message": "Energia usada na logistica adicionada com sucesso"}


@auth.route('/updateEnergyUsedInMaterialsLogistic/<year>/<company>', methods=['PUT'])
def update_energy_used_in_materials_logistic(year, company):
    Materials.objects(
        Q(year=year) & Q(company_name=company)).update(transported_material=request.json["transported_material"],
                                                       provider=request.json["provider"],
                                                       distance_by_delivery=request.json["distance_by_delivery"],
                                                       material_transported_mass=request.json[
                                                           "material_transported_mass"],
                                                       vehicle_identification=request.json["vehicle_identification"],
                                                       vehicle_type=request.json["vehicle_type"],
                                                       own_vehicles=request.json["own_vehicles"])

    return {"Result": 0, "Year": year, "Message": "Energia usada na logistica editada com sucesso"}


@auth.route('/createWaste', methods=['POST'])
def create_waste():
    year = request.json['year']
    company_name = request.json['company_name']
    deceit = request.json['deceit']
    deceit_destination = request.json['deceit_destination']
    bagasse = request.json['bagasse']
    bagasse_destination = request.json['bagasse_destination']
    draff = request.json['draff']
    draff_destination = request.json['draff_destination']
    used_diatomaceous = request.json['used_diatomaceous']
    used_diatomaceous_destination = request.json['used_diatomaceous_destination']
    glass_mixture = request.json['glass_mixture']
    glass_mixture_destination = request.json['glass_mixture_destination']
    plastic_mixture = request.json['plastic_mixture']
    plastic_mixture_destination = request.json['plastic_mixture_destination']
    plastic_hdpe = request.json['plastic_hdpe']
    plastic_hdpe_destination = request.json['plastic_hdpe_destination']
    plastic_ldpe = request.json['plastic_ldpe']
    plastic_ldpe_destination = request.json['plastic_ldpe_destination']
    plastic_pet = request.json['plastic_pet']
    plastic_pet_destination = request.json['plastic_pet_destination']
    plastic_pp = request.json['plastic_pp']
    plastic_pp_destination = request.json['plastic_pp_destination']
    plastic_pvc = request.json['plastic_pvc']
    plastic_pvc_destination = request.json['plastic_pvc_destination']
    paper_mixture = request.json['paper_mixture']
    paper_mixture_destination = request.json['paper_mixture_destination']
    paper_card = request.json['paper_card']
    paper_card_destination = request.json['paper_card_destination']
    glass_municipalities_waste = request.json['glass_municipalities_waste']
    glass_municipalities_waste_destination = request.json['glass_municipalities_waste_destination']
    plastic_metal_municipalities_waste = request.json['plastic_metal_municipalities_waste']
    plastic_metal_municipalities_waste_destination = request.json[
        'plastic_metal_municipalities_waste_destination']
    paper_municipalities_waste = request.json['paper_municipalities_waste']
    paper_municipalities_waste_destination = request.json['paper_municipalities_waste_destination']
    undifferentiated_municipalities_waste = request.json['undifferentiated_municipalities_waste']
    undifferentiated_municipalities_waste_destination = request.json[
        'undifferentiated_municipalities_waste_destination']
    junk_yard_wires_mixture = request.json['junk_yard_wires_mixture']
    junk_yard_wires_mixture_destination = request.json['junk_yard_wires_mixture_destination']
    junk_yard_wires_steel = request.json['junk_yard_wires_steel']
    junk_yard_wires_steel_destination = request.json['junk_yard_wires_steel_destination']
    junk_yard_wires_aluminum = request.json['junk_yard_wires_aluminum']
    junk_yard_wires_aluminum_destination = request.json['junk_yard_wires_aluminum_destination']
    junk_yard_cans_mixture = request.json['junk_yard_cans_mixture']
    junk_yard_cans_mixture_destination = request.json['junk_yard_cans_mixture_destination']
    junk_yard_wood_mixture = request.json['junk_yard_wood_mixture']
    junk_yard_wood_mixture_destination = request.json['junk_yard_wood_mixture_destination']
    junk_yard_domestic_bateries = request.json['junk_yard_domestic_bateries']
    junk_yard_domestic_bateries_destination = request.json['junk_yard_domestic_bateries_destination']
    junk_yard_machines_bateries = request.json['junk_yard_machines_bateries']
    junk_yard_machines_bateries_destination = request.json['junk_yard_machines_bateries_destination']
    junk_yard_tires = request.json['junk_yard_tires']
    junk_yard_tires_destination = request.json['junk_yard_tires_destination']
    junk_yard_informatic_equipment = request.json['junk_yard_informatic_equipment']
    junk_yard_informatic_equipment_destination = request.json[
        'junk_yard_informatic_equipment_destination']
    junk_yard_refrigeration_equipment = request.json['junk_yard_refrigeration_equipment']
    junk_yard_refrigeration_equipment_destination = request.json[
        'junk_yard_refrigeration_equipment_destination']
    junk_yard_machines_oils = request.json['junk_yard_machines_oils']
    junk_yard_machines_oils_destination = request.json['junk_yard_machines_oils_destination']
    sludge = request.json['sludge']
    sludge_destination = request.json['sludge_destination']

    new_waste = Waste(year=year,
                      company_name=company_name,
                      deceit=deceit,
                      deceit_destination=deceit_destination,
                      bagasse=bagasse,
                      bagasse_destination=bagasse_destination,
                      draff=draff,
                      draff_destination=draff_destination,
                      used_diatomaceous=used_diatomaceous,
                      used_diatomaceous_destination=used_diatomaceous_destination,
                      glass_mixture=glass_mixture,
                      glass_mixture_destination=glass_mixture_destination,
                      plastic_mixture=plastic_mixture,
                      plastic_mixture_destination=plastic_mixture_destination,
                      plastic_hdpe=plastic_hdpe, plastic_hdpe_destination=plastic_hdpe_destination,
                      plastic_ldpe=plastic_ldpe,
                      plastic_ldpe_destination=plastic_ldpe_destination, plastic_pet=plastic_pet,
                      plastic_pet_destination=plastic_pet_destination,
                      plastic_pp=plastic_pp,
                      plastic_pp_destination=plastic_pp_destination,
                      plastic_pvc=plastic_pvc, plastic_pvc_destination=plastic_pvc_destination,
                      paper_mixture=paper_mixture, paper_mixture_destination=paper_mixture_destination,
                      paper_card=paper_card,
                      paper_card_destination=paper_card_destination,
                      glass_municipalities_waste=glass_municipalities_waste,
                      glass_municipalities_waste_destination=glass_municipalities_waste_destination,
                      plastic_metal_municipalities_waste=plastic_metal_municipalities_waste,
                      plastic_metal_municipalities_waste_destination=plastic_metal_municipalities_waste_destination,
                      paper_municipalities_waste=paper_municipalities_waste,
                      paper_municipalities_waste_destination=paper_municipalities_waste_destination,
                      undifferentiated_municipalities_waste=undifferentiated_municipalities_waste,
                      undifferentiated_municipalities_waste_destination=undifferentiated_municipalities_waste_destination,
                      junk_yard_wires_mixture=junk_yard_wires_mixture,
                      junk_yard_wires_mixture_destination=junk_yard_wires_mixture_destination,
                      junk_yard_wires_steel=junk_yard_wires_steel,
                      junk_yard_wires_steel_destination=junk_yard_wires_steel_destination,
                      junk_yard_wires_aluminum=junk_yard_wires_aluminum,
                      junk_yard_wires_aluminum_destination=junk_yard_wires_aluminum_destination,
                      junk_yard_cans_mixture=junk_yard_cans_mixture,
                      junk_yard_cans_mixture_destination=junk_yard_cans_mixture_destination,
                      junk_yard_wood_mixture=junk_yard_wood_mixture,
                      junk_yard_wood_mixture_destination=junk_yard_wood_mixture_destination,
                      junk_yard_domestic_bateries=junk_yard_domestic_bateries,
                      junk_yard_domestic_bateries_destination=junk_yard_domestic_bateries_destination,
                      junk_yard_machines_bateries=junk_yard_machines_bateries,
                      junk_yard_machines_bateries_destination=junk_yard_machines_bateries_destination,
                      junk_yard_tires=junk_yard_tires,
                      junk_yard_tires_destination=junk_yard_tires_destination,
                      junk_yard_informatic_equipment=junk_yard_informatic_equipment,
                      junk_yard_informatic_equipment_destination=junk_yard_informatic_equipment_destination,
                      junk_yard_refrigeration_equipment=junk_yard_refrigeration_equipment,
                      junk_yard_refrigeration_equipment_destination=junk_yard_refrigeration_equipment_destination,
                      junk_yard_machines_oils=junk_yard_machines_oils,
                      junk_yard_machines_oils_destination=junk_yard_machines_oils_destination,
                      sludge=sludge,
                      sludge_destination=sludge_destination)

    new_waste.save()
    return {"Result": 0, "Message": "Resíduos adicionados com sucesso"}


@auth.route('/getWasteByYearAndCompany', methods=['GET'])
def get_waste_by_year_and_company():
    year = request.args.get('year')
    company = request.args.get('company_name')

    waste = Waste.objects(
        Q(year=year) & Q(company_name=company)).first()

    if waste == None:
        return {"Result": 1, "Data": None}
    else:
        return {"Result": 0, "Data": json.loads(waste.to_json())}


@auth.route('/updateWaste/<year>/<company>', methods=['PUT'])
def update_waste(year, company):
    Waste.objects(
        Q(year=year) & Q(company_name=company)).update(
            deceit=request.json["deceit"],
            deceit_destination=request.json["deceit_destination"],
            bagasse=request.json["bagasse"],
            bagasse_destination=request.json["bagasse_destination"],
            draff=request.json["draff"],
            draff_destination=request.json["draff_destination"],
            used_diatomaceous=request.json["used_diatomaceous"],
            used_diatomaceous_destination=request.json["used_diatomaceous_destination"],
            glass_mixture=request.json["glass_mixture"],
            glass_mixture_destination=request.json["glass_mixture_destination"],
            plastic_mixture=request.json["plastic_mixture"],
            plastic_mixture_destination=request.json["plastic_mixture_destination"],
            plastic_hdpe=request.json["plastic_hdpe"],
            plastic_hdpe_destination=request.json["plastic_hdpe_destination"],
            plastic_ldpe=request.json["plastic_ldpe"],
            plastic_ldpe_destination=request.json["plastic_ldpe_destination"],
            plastic_pet=request.json["plastic_pet"],
            plastic_pet_destination=request.json["plastic_pet_destination"],
            plastic_pp=request.json["plastic_pp"],
            plastic_pp_destination=request.json["plastic_pp_destination"],
            plastic_pvc=request.json["plastic_pvc"],
            plastic_pvc_destination=request.json["plastic_pvc_destination"],
            paper_mixture=request.json["paper_mixture"],
            paper_mixture_destination=request.json["paper_mixture_destination"],
            paper_card=request.json["paper_card"],
            paper_card_destination=request.json["paper_card_destination"],
            glass_municipalities_waste=request.json["glass_municipalities_waste"],
            glass_municipalities_waste_destination=request.json[
                "glass_municipalities_waste_destination"],
            plastic_metal_municipalities_waste=request.json["plastic_metal_municipalities_waste"],
            plastic_metal_municipalities_waste_destination=request.json[
                "plastic_metal_municipalities_waste_destination"],
            paper_municipalities_waste=request.json["paper_municipalities_waste"],
            paper_municipalities_waste_destination=request.json[
                "paper_municipalities_waste_destination"],
            undifferentiated_municipalities_waste=request.json["undifferentiated_municipalities_waste"],
            undifferentiated_municipalities_waste_destination=request.json[
                "undifferentiated_municipalities_waste_destination"],
            junk_yard_wires_mixture=request.json["junk_yard_wires_mixture"],
            junk_yard_wires_mixture_destination=request.json["junk_yard_wires_mixture_destination"],
            junk_yard_wires_steel=request.json["junk_yard_wires_steel"],
            junk_yard_wires_steel_destination=request.json["junk_yard_wires_steel_destination"],
            junk_yard_wires_aluminum=request.json["junk_yard_wires_aluminum"],
            junk_yard_wires_aluminum_destination=request.json["junk_yard_wires_aluminum_destination"],
            junk_yard_cans_mixture=request.json["junk_yard_cans_mixture"],
            junk_yard_cans_mixture_destination=request.json["junk_yard_cans_mixture_destination"],
            junk_yard_wood_mixture=request.json["junk_yard_wood_mixture"],
            junk_yard_wood_mixture_destination=request.json["junk_yard_wood_mixture_destination"],
            junk_yard_domestic_bateries=request.json["junk_yard_domestic_bateries"],
            junk_yard_domestic_bateries_destination=request.json[
                "junk_yard_domestic_bateries_destination"],
            junk_yard_machines_bateries=request.json["junk_yard_machines_bateries"],
            junk_yard_machines_bateries_destination=request.json[
                "junk_yard_machines_bateries_destination"],
            junk_yard_tires=request.json["junk_yard_tires"],
            junk_yard_tires_destination=request.json["junk_yard_tires_destination"],
            junk_yard_informatic_equipment=request.json["junk_yard_informatic_equipment"],
            junk_yard_informatic_equipment_destination=request.json[
                "junk_yard_informatic_equipment_destination"],
            junk_yard_refrigeration_equipment=request.json["junk_yard_refrigeration_equipment"],
            junk_yard_refrigeration_equipment_destination=request.json[
                "junk_yard_refrigeration_equipment_destination"],
            junk_yard_machines_oils=request.json["junk_yard_machines_oils"],
            junk_yard_machines_oils_destination=request.json["junk_yard_machines_oils_destination"],
            sludge=request.json["sludge"],
            sludge_destination=request.json["sludge_destination"]
    )

    return {"Result": 0, "Year": year, "Message": "Resíduos editados com sucesso"}


@auth.route('/createWater', methods=['POST'])
def create_water():
    year = request.json['year']
    company_name = request.json['company_name']
    total_water_from_network = request.json['total_water_from_network']
    total_water_from_well = request.json['total_water_from_well']
    total_water_from_cistern = request.json['total_water_from_cistern']
    total_water_reused = request.json['total_water_reused']
    number_of_cleaning_per_month_on_bottling_different_floors = request.json[
        'number_of_cleaning_per_month_on_bottling_different_floors']
    number_of_cleaning_per_month_on_different_floors = request.json[
        'number_of_cleaning_per_month_on_different_floors']
    number_of_cleaning_per_month_on_estabilization = request.json[
        'number_of_cleaning_per_month_on_estabilization']
    number_of_cleaning_per_month_on_filling = request.json['number_of_cleaning_per_month_on_filling']
    number_of_cleaning_per_month_on_filtration = request.json[
        'number_of_cleaning_per_month_on_filtration']
    number_of_cleaning_per_month_on_labeling = request.json[
        'number_of_cleaning_per_month_on_labeling']
    number_of_cleaning_per_month_on_pressing = request.json[
        'number_of_cleaning_per_month_on_pressing']
    number_of_cleaning_per_month_on_sterilization = request.json[
        'number_of_cleaning_per_month_on_sterilization']
    number_of_cleaning_per_month_on_trasfega = request.json[
        'number_of_cleaning_per_month_on_trasfega']
    water_consumed_by_equipment_cleaning_on_bottling_different_floors = request.json[
        'water_consumed_by_equipment_cleaning_on_bottling_different_floors']
    water_consumed_by_equipment_cleaning_on_different_floors = request.json[
        'water_consumed_by_equipment_cleaning_on_different_floors']
    water_consumed_by_equipment_cleaning_on_estabilization = request.json[
        'water_consumed_by_equipment_cleaning_on_estabilization']
    water_consumed_by_equipment_cleaning_on_filling = request.json[
        'water_consumed_by_equipment_cleaning_on_filling']
    water_consumed_by_equipment_cleaning_on_filtration = request.json[
        'water_consumed_by_equipment_cleaning_on_filtration']
    water_consumed_by_equipment_cleaning_on_labeling = request.json[
        'water_consumed_by_equipment_cleaning_on_labeling']
    water_consumed_by_equipment_cleaning_on_pressing = request.json[
        'water_consumed_by_equipment_cleaning_on_pressing']
    water_consumed_by_equipment_cleaning_on_sterilization = request.json[
        'water_consumed_by_equipment_cleaning_on_sterilization']
    water_consumed_by_equipment_cleaning_on_trasfega = request.json[
        'water_consumed_by_equipment_cleaning_on_trasfega']

    ph_high_season_generated_water = request.json[
        'ph_high_season_generated_water']
    ph_low_season_generated_water = request.json[
        'ph_low_season_generated_water']
    conductivity_high_season_generated_water = request.json[
        'conductivity_high_season_generated_water']
    conductivity_low_season_generated_water = request.json[
        'conductivity_low_season_generated_water']
    turbidity_high_season_generated_water = request.json[
        'turbidity_high_season_generated_water']
    turbidity_low_season_generated_water = request.json[
        'turbidity_low_season_generated_water']
    CQO_high_season_generated_water = request.json[
        'CQO_high_season_generated_water']
    CQO_low_season_generated_water = request.json[
        'CQO_low_season_generated_water']
    CBO_high_season_generated_water = request.json[
        'CBO_high_season_generated_water']
    CBO_low_season_generated_water = request.json[
        'CBO_low_season_generated_water']
    SST_high_season_generated_water = request.json[
        'SST_high_season_generated_water']
    SST_low_season_generated_water = request.json[
        'SST_low_season_generated_water']
    NTK_high_season_generated_water = request.json[
        'NTK_high_season_generated_water']
    NTK_low_season_generated_water = request.json[
        'NTK_low_season_generated_water']
    fenois_high_season_generated_water = request.json[
        'fenois_high_season_generated_water']
    fenois_low_season_generated_water = request.json[
        'fenois_low_season_generated_water']
    fosforo_high_season_generated_water = request.json[
        'fosforo_high_season_generated_water']
    fosforo_low_season_generated_water = request.json[
        'fosforo_low_season_generated_water']
    nitratos_high_season_generated_water = request.json[
        'nitratos_high_season_generated_water']
    nitratos_low_season_generated_water = request.json[
        'nitratos_low_season_generated_water']
    sulfatos_high_season_generated_water = request.json[
        'sulfatos_high_season_generated_water']
    sulfatos_low_season_generated_water = request.json[
        'sulfatos_low_season_generated_water']
    ferro_high_season_generated_water = request.json[
        'ferro_high_season_generated_water']
    ferro_low_season_generated_water = request.json[
        'ferro_low_season_generated_water']
    aluminum_high_season_generated_water = request.json[
        'aluminum_high_season_generated_water']
    aluminum_low_season_generated_water = request.json[
        'aluminum_low_season_generated_water']
    cadmio_high_season_generated_water = request.json[
        'cadmio_high_season_generated_water']
    cadmio_low_season_generated_water = request.json[
        'cadmio_low_season_generated_water']
    cobre_high_season_generated_water = request.json[
        'cobre_high_season_generated_water']
    cobre_low_season_generated_water = request.json[
        'cobre_low_season_generated_water']
    cromio_high_season_generated_water = request.json[
        'cromio_high_season_generated_water']
    cromio_low_season_generated_water = request.json[
        'cromio_low_season_generated_water']
    manganes_high_season_generated_water = request.json[
        'manganes_high_season_generated_water']
    manganes_low_season_generated_water = request.json[
        'manganes_low_season_generated_water']

    ph_high_season_treated_water = request.json[
        'ph_high_season_treated_water']
    ph_low_season_treated_water = request.json[
        'ph_low_season_treated_water']
    conductivity_high_season_treated_water = request.json[
        'conductivity_high_season_treated_water']
    conductivity_low_season_treated_water = request.json[
        'conductivity_low_season_treated_water']
    turbidity_high_season_treated_water = request.json[
        'turbidity_high_season_treated_water']
    turbidity_low_season_treated_water = request.json[
        'turbidity_low_season_treated_water']
    CQO_high_season_treated_water = request.json[
        'CQO_high_season_treated_water']
    CQO_low_season_treated_water = request.json[
        'CQO_low_season_treated_water']
    CBO_high_season_treated_water = request.json[
        'CBO_high_season_treated_water']
    CBO_low_season_treated_water = request.json[
        'CBO_low_season_treated_water']
    SST_high_season_treated_water = request.json[
        'SST_high_season_treated_water']
    SST_low_season_treated_water = request.json[
        'SST_low_season_treated_water']
    NTK_high_season_treated_water = request.json[
        'NTK_high_season_treated_water']
    NTK_low_season_treated_water = request.json[
        'NTK_low_season_treated_water']
    fenois_high_season_treated_water = request.json[
        'fenois_high_season_treated_water']
    fenois_low_season_treated_water = request.json[
        'fenois_low_season_treated_water']
    fosforo_high_season_treated_water = request.json[
        'fosforo_high_season_treated_water']
    fosforo_low_season_treated_water = request.json[
        'fosforo_low_season_treated_water']
    nitratos_high_season_treated_water = request.json[
        'nitratos_high_season_treated_water']
    nitratos_low_season_treated_water = request.json[
        'nitratos_low_season_treated_water']
    sulfatos_high_season_treated_water = request.json[
        'sulfatos_high_season_treated_water']
    sulfatos_low_season_treated_water = request.json[
        'sulfatos_low_season_treated_water']
    ferro_high_season_treated_water = request.json[
        'ferro_high_season_treated_water']
    ferro_low_season_treated_water = request.json[
        'ferro_low_season_treated_water']
    aluminum_high_season_treated_water = request.json[
        'aluminum_high_season_treated_water']
    aluminum_low_season_treated_water = request.json[
        'aluminum_low_season_treated_water']
    cadmio_high_season_treated_water = request.json[
        'cadmio_high_season_treated_water']
    cadmio_low_season_treated_water = request.json[
        'cadmio_low_season_treated_water']
    cobre_high_season_treated_water = request.json[
        'cobre_high_season_treated_water']
    cobre_low_season_treated_water = request.json[
        'cobre_low_season_treated_water']
    cromio_high_season_treated_water = request.json[
        'cromio_high_season_treated_water']
    cromio_low_season_treated_water = request.json[
        'cromio_low_season_treated_water']
    manganes_high_season_treated_water = request.json[
        'manganes_high_season_treated_water']
    manganes_low_season_treated_water = request.json[
        'manganes_low_season_treated_water']

    water = Water(year=year, company_name=company_name,
                  total_water_from_network=total_water_from_network,
                  total_water_from_well=total_water_from_well, total_water_from_cistern=total_water_from_cistern,
                  total_water_reused=total_water_reused, number_of_cleaning_per_month_on_bottling_different_floors=number_of_cleaning_per_month_on_bottling_different_floors,
                  number_of_cleaning_per_month_on_different_floors=number_of_cleaning_per_month_on_different_floors,
                  number_of_cleaning_per_month_on_estabilization=number_of_cleaning_per_month_on_estabilization,
                  number_of_cleaning_per_month_on_filling=number_of_cleaning_per_month_on_filling,
                  number_of_cleaning_per_month_on_filtration=number_of_cleaning_per_month_on_filtration,
                  number_of_cleaning_per_month_on_labeling=number_of_cleaning_per_month_on_labeling,
                  number_of_cleaning_per_month_on_pressing=number_of_cleaning_per_month_on_pressing,
                  number_of_cleaning_per_month_on_sterilization=number_of_cleaning_per_month_on_sterilization,
                  number_of_cleaning_per_month_on_trasfega=number_of_cleaning_per_month_on_trasfega,
                  water_consumed_by_equipment_cleaning_on_bottling_different_floors=water_consumed_by_equipment_cleaning_on_bottling_different_floors,
                  water_consumed_by_equipment_cleaning_on_different_floors=water_consumed_by_equipment_cleaning_on_different_floors,
                  water_consumed_by_equipment_cleaning_on_estabilization=water_consumed_by_equipment_cleaning_on_estabilization,
                  water_consumed_by_equipment_cleaning_on_filling=water_consumed_by_equipment_cleaning_on_filling,
                  water_consumed_by_equipment_cleaning_on_filtration=water_consumed_by_equipment_cleaning_on_filtration,
                  water_consumed_by_equipment_cleaning_on_labeling=water_consumed_by_equipment_cleaning_on_labeling,
                  water_consumed_by_equipment_cleaning_on_pressing=water_consumed_by_equipment_cleaning_on_pressing,
                  water_consumed_by_equipment_cleaning_on_sterilization=water_consumed_by_equipment_cleaning_on_sterilization,
                  water_consumed_by_equipment_cleaning_on_trasfega=water_consumed_by_equipment_cleaning_on_trasfega,

                  ph_high_season_generated_water=ph_high_season_generated_water,
                  ph_low_season_generated_water=ph_low_season_generated_water,
                  conductivity_high_season_generated_water=conductivity_high_season_generated_water,
                  conductivity_low_season_generated_water=conductivity_low_season_generated_water,
                  turbidity_high_season_generated_water=turbidity_high_season_generated_water,
                  turbidity_low_season_generated_water=turbidity_low_season_generated_water,
                  CQO_high_season_generated_water=CQO_high_season_generated_water,
                  CQO_low_season_generated_water=CQO_low_season_generated_water,
                  CBO_high_season_generated_water=CBO_high_season_generated_water,
                  CBO_low_season_generated_water=CBO_low_season_generated_water,
                  SST_high_season_generated_water=SST_high_season_generated_water,
                  SST_low_season_generated_water=SST_low_season_generated_water,
                  NTK_high_season_generated_water=NTK_high_season_generated_water,
                  NTK_low_season_generated_water=NTK_low_season_generated_water,
                  fenois_high_season_generated_water=fenois_high_season_generated_water,
                  fenois_low_season_generated_water=fenois_low_season_generated_water,
                  fosforo_high_season_generated_water=fosforo_high_season_generated_water,
                  fosforo_low_season_generated_water=fosforo_low_season_generated_water,
                  nitratos_high_season_generated_water=nitratos_high_season_generated_water,
                  nitratos_low_season_generated_water=nitratos_low_season_generated_water,
                  sulfatos_high_season_generated_water=sulfatos_high_season_generated_water,
                  sulfatos_low_season_generated_water=sulfatos_low_season_generated_water,
                  ferro_high_season_generated_water=ferro_high_season_generated_water,
                  ferro_low_season_generated_water=ferro_low_season_generated_water,
                  aluminum_high_season_generated_water=aluminum_high_season_generated_water,
                  aluminum_low_season_generated_water=aluminum_low_season_generated_water,
                  cadmio_high_season_generated_water=cadmio_high_season_generated_water,
                  cadmio_low_season_generated_water=cadmio_low_season_generated_water,
                  cobre_high_season_generated_water=cobre_high_season_generated_water,
                  cobre_low_season_generated_water=cobre_low_season_generated_water,
                  cromio_high_season_generated_water=cromio_high_season_generated_water,
                  cromio_low_season_generated_water=cromio_low_season_generated_water,
                  manganes_high_season_generated_water=manganes_high_season_generated_water,
                  manganes_low_season_generated_water=manganes_low_season_generated_water,
                  ph_high_season_treated_water=ph_high_season_treated_water,
                  ph_low_season_treated_water=ph_low_season_treated_water,
                  conductivity_high_season_treated_water=conductivity_high_season_treated_water,
                  conductivity_low_season_treated_water=conductivity_low_season_treated_water,
                  turbidity_high_season_treated_water=turbidity_high_season_treated_water,
                  turbidity_low_season_treated_water=turbidity_low_season_treated_water,
                  CQO_high_season_treated_water=CQO_high_season_treated_water,
                  CQO_low_season_treated_water=CQO_low_season_treated_water,
                  CBO_high_season_treated_water=CBO_high_season_treated_water,
                  CBO_low_season_treated_water=CBO_low_season_treated_water,
                  SST_high_season_treated_water=SST_high_season_treated_water,
                  SST_low_season_treated_water=SST_low_season_treated_water,
                  NTK_high_season_treated_water=NTK_high_season_treated_water,
                  NTK_low_season_treated_water=NTK_low_season_treated_water,
                  fenois_high_season_treated_water=fenois_high_season_treated_water,
                  fenois_low_season_treated_water=fenois_low_season_treated_water,
                  fosforo_high_season_treated_water=fosforo_high_season_treated_water,
                  fosforo_low_season_treated_water=fosforo_low_season_treated_water,
                  nitratos_high_season_treated_water=nitratos_high_season_treated_water,
                  nitratos_low_season_treated_water=nitratos_low_season_treated_water,
                  sulfatos_high_season_treated_water=sulfatos_high_season_treated_water,
                  sulfatos_low_season_treated_water=sulfatos_low_season_treated_water,
                  ferro_high_season_treated_water=ferro_high_season_treated_water,
                  ferro_low_season_treated_water=ferro_low_season_treated_water,
                  aluminum_high_season_treated_water=aluminum_high_season_treated_water,
                  aluminum_low_season_treated_water=aluminum_low_season_treated_water,
                  cadmio_high_season_treated_water=cadmio_high_season_treated_water,
                  cadmio_low_season_treated_water=cadmio_low_season_treated_water,
                  cobre_high_season_treated_water=cobre_high_season_treated_water,
                  cobre_low_season_treated_water=cobre_low_season_treated_water,
                  cromio_high_season_treated_water=cromio_high_season_treated_water,
                  cromio_low_season_treated_water=cromio_low_season_treated_water,
                  manganes_high_season_treated_water=manganes_high_season_treated_water,
                  manganes_low_season_treated_water=manganes_low_season_treated_water)

    water.save()
    return {"Result": 0}


@auth.route('/getWaterByYearAndCompany', methods=['GET'])
def get_water_by_year_and_company():
    year = request.args.get('year')
    company = request.args.get('company_name')

    water = Water.objects(
        Q(year=year) & Q(company_name=company)).first()

    if water == None:
        return {"Result": 1, "Data": None}
    else:
        return {"Result": 0, "Data": json.loads(water.to_json())}


@auth.route('/updateWater/<year>/<company>', methods=['PUT'])
def update_water(year, company):
    Water.objects(
        Q(year=year) & Q(company_name=company)).update(
            total_water_from_network=request.json["total_water_from_network"],
            total_water_from_well=request.json["total_water_from_well"],
            total_water_from_cistern=request.json["total_water_from_cistern"],
            total_water_reused=request.json["total_water_reused"],
            number_of_cleaning_per_month_on_bottling_different_floors=request.json[
                "number_of_cleaning_per_month_on_bottling_different_floors"],
            number_of_cleaning_per_month_on_different_floors=request.json[
                "number_of_cleaning_per_month_on_different_floors"],
            number_of_cleaning_per_month_on_estabilization=request.json[
                "number_of_cleaning_per_month_on_estabilization"],
            number_of_cleaning_per_month_on_filling=request.json[
                "number_of_cleaning_per_month_on_filling"],
            number_of_cleaning_per_month_on_filtration=request.json[
                "number_of_cleaning_per_month_on_filtration"],
            number_of_cleaning_per_month_on_labeling=request.json[
                "number_of_cleaning_per_month_on_labeling"],
            number_of_cleaning_per_month_on_pressing=request.json[
                "number_of_cleaning_per_month_on_pressing"],
            number_of_cleaning_per_month_on_sterilization=request.json[
                "number_of_cleaning_per_month_on_sterilization"],
            number_of_cleaning_per_month_on_trasfega=request.json[
                "number_of_cleaning_per_month_on_trasfega"],
            water_consumed_by_equipment_cleaning_on_bottling_different_floors=request.json[
                "water_consumed_by_equipment_cleaning_on_bottling_different_floors"],
            water_consumed_by_equipment_cleaning_on_different_floors=request.json[
                "water_consumed_by_equipment_cleaning_on_different_floors"],
            water_consumed_by_equipment_cleaning_on_estabilization=request.json[
                "water_consumed_by_equipment_cleaning_on_estabilization"],
            water_consumed_by_equipment_cleaning_on_filling=request.json[
                "water_consumed_by_equipment_cleaning_on_filling"],
            water_consumed_by_equipment_cleaning_on_filtration=request.json[
                "water_consumed_by_equipment_cleaning_on_filtration"],
            water_consumed_by_equipment_cleaning_on_labeling=request.json[
                "water_consumed_by_equipment_cleaning_on_labeling"],
            water_consumed_by_equipment_cleaning_on_pressing=request.json[
                "water_consumed_by_equipment_cleaning_on_pressing"],
            water_consumed_by_equipment_cleaning_on_sterilization=request.json[
                "water_consumed_by_equipment_cleaning_on_sterilization"],
            water_consumed_by_equipment_cleaning_on_trasfega=request.json[
                "water_consumed_by_equipment_cleaning_on_trasfega"],

            ph_high_season_generated_water=request.json[
                'ph_high_season_generated_water'],
            ph_low_season_generated_water=request.json[
                'ph_low_season_generated_water'],
            conductivity_high_season_generated_water=request.json[
                'conductivity_high_season_generated_water'],
            conductivity_low_season_generated_water=request.json[
                'conductivity_low_season_generated_water'],
            turbidity_high_season_generated_water=request.json[
                'turbidity_high_season_generated_water'],
            turbidity_low_season_generated_water=request.json[
                'turbidity_low_season_generated_water'],
            CQO_high_season_generated_water=request.json[
                'CQO_high_season_generated_water'],
            CQO_low_season_generated_water=request.json[
                'CQO_low_season_generated_water'],
            CBO_high_season_generated_water=request.json[
                'CBO_high_season_generated_water'],
            CBO_low_season_generated_water=request.json[
                'CBO_low_season_generated_water'],
            SST_high_season_generated_water=request.json[
                'SST_high_season_generated_water'],
            SST_low_season_generated_water=request.json[
                'SST_low_season_generated_water'],
            NTK_high_season_generated_water=request.json[
                'NTK_high_season_generated_water'],
            NTK_low_season_generated_water=request.json[
                'NTK_low_season_generated_water'],
            fenois_high_season_generated_water=request.json[
                'fenois_high_season_generated_water'],
            fenois_low_season_generated_water=request.json[
                'fenois_low_season_generated_water'],
            fosforo_high_season_generated_water=request.json[
                'fosforo_high_season_generated_water'],
            fosforo_low_season_generated_water=request.json[
                'fosforo_low_season_generated_water'],
            nitratos_high_season_generated_water=request.json[
                'nitratos_high_season_generated_water'],
            nitratos_low_season_generated_water=request.json[
                'nitratos_low_season_generated_water'],
            sulfatos_high_season_generated_water=request.json[
                'sulfatos_high_season_generated_water'],
            sulfatos_low_season_generated_water=request.json[
                'sulfatos_low_season_generated_water'],
            ferro_high_season_generated_water=request.json[
                'ferro_high_season_generated_water'],
            ferro_low_season_generated_water=request.json[
                'ferro_low_season_generated_water'],
            aluminum_high_season_generated_water=request.json[
                'aluminum_high_season_generated_water'],
            aluminum_low_season_generated_water=request.json[
                'aluminum_low_season_generated_water'],
            cadmio_high_season_generated_water=request.json[
                'cadmio_high_season_generated_water'],
            cadmio_low_season_generated_water=request.json[
                'cadmio_low_season_generated_water'],
            cobre_high_season_generated_water=request.json[
                'cobre_high_season_generated_water'],
            cobre_low_season_generated_water=request.json[
                'cobre_low_season_generated_water'],
            cromio_high_season_generated_water=request.json[
                'cromio_high_season_generated_water'],
            cromio_low_season_generated_water=request.json[
                'cromio_low_season_generated_water'],
            manganes_high_season_generated_water=request.json[
                'manganes_high_season_generated_water'],
            manganes_low_season_generated_water=request.json[
                'manganes_low_season_generated_water'],

        ph_high_season_treated_water=request.json[
                'ph_high_season_treated_water'],
            ph_low_season_treated_water=request.json[
                'ph_low_season_treated_water'],
            conductivity_high_season_treated_water=request.json[
                'conductivity_high_season_treated_water'],
            conductivity_low_season_treated_water=request.json[
                'conductivity_low_season_treated_water'],
            turbidity_high_season_treated_water=request.json[
                'turbidity_high_season_treated_water'],
            turbidity_low_season_treated_water=request.json[
                'turbidity_low_season_treated_water'],
            CQO_high_season_treated_water=request.json[
                'CQO_high_season_treated_water'],
            CQO_low_season_treated_water=request.json[
                'CQO_low_season_treated_water'],
            CBO_high_season_treated_water=request.json[
                'CBO_high_season_treated_water'],
            CBO_low_season_treated_water=request.json[
                'CBO_low_season_treated_water'],
            SST_high_season_treated_water=request.json[
                'SST_high_season_treated_water'],
            SST_low_season_treated_water=request.json[
                'SST_low_season_treated_water'],
            NTK_high_season_treated_water=request.json[
                'NTK_high_season_treated_water'],
            NTK_low_season_treated_water=request.json[
                'NTK_low_season_treated_water'],
            fenois_high_season_treated_water=request.json[
                'fenois_high_season_treated_water'],
            fenois_low_season_treated_water=request.json[
                'fenois_low_season_treated_water'],
            fosforo_high_season_treated_water=request.json[
                'fosforo_high_season_treated_water'],
            fosforo_low_season_treated_water=request.json[
                'fosforo_low_season_treated_water'],
            nitratos_high_season_treated_water=request.json[
                'nitratos_high_season_treated_water'],
            nitratos_low_season_treated_water=request.json[
                'nitratos_low_season_treated_water'],
            sulfatos_high_season_treated_water=request.json[
                'sulfatos_high_season_treated_water'],
            sulfatos_low_season_treated_water=request.json[
                'sulfatos_low_season_treated_water'],
            ferro_high_season_treated_water=request.json[
                'ferro_high_season_treated_water'],
            ferro_low_season_treated_water=request.json[
                'ferro_low_season_treated_water'],
            aluminum_high_season_treated_water=request.json[
                'aluminum_high_season_treated_water'],
            aluminum_low_season_treated_water=request.json[
                'aluminum_low_season_treated_water'],
            cadmio_high_season_treated_water=request.json[
                'cadmio_high_season_treated_water'],
            cadmio_low_season_treated_water=request.json[
                'cadmio_low_season_treated_water'],
            cobre_high_season_treated_water=request.json[
                'cobre_high_season_treated_water'],
            cobre_low_season_treated_water=request.json[
                'cobre_low_season_treated_water'],
            cromio_high_season_treated_water=request.json[
                'cromio_high_season_treated_water'],
            cromio_low_season_treated_water=request.json[
                'cromio_low_season_treated_water'],
            manganes_high_season_treated_water=request.json[
                'manganes_high_season_treated_water'],
            manganes_low_season_treated_water=request.json[
                'manganes_low_season_treated_water']
    )

    return {"Result": 0, "Year": year}
