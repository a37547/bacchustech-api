from flask import Flask
import os
from mongoengine import *
from flask_cors import CORS


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)

    cors = CORS(app, resources={
        r"/*": {
            "origins": "*"
        }
    })

    app.config["MONGODB_SETTINGS"] = [
        {
            "db": "bacchustech",
            "host": "localhost",
            "port": 27017,
            "alias": "default",
        }
    ]

    app.config['MAIL_SERVER'] = 'smtp.mailtrap.io'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USERNAME'] = 'bb6e8301cdbd3a'
    app.config['MAIL_PASSWORD'] = 'd110de6f1f575d'
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USE_SSL'] = False
    app.config["SESSION_PERMANENT"] = False
    app.config["SESSION_TYPE"] = "filesystem"

    connect('bacchustech')

    if test_config is None:
        app.config.from_mapping(SECRET_KEY=os.environ.get("SECRET_KEY"))

    else:
        app.config.from_mapping(test_config)

    from src.extensions import mail
    from src.extensions import login_manager
    from src.extensions import bcrypt
    from src.extensions import session_flask_session
    mail.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    session_flask_session.init_app(app)

    with app.app_context():
        from src.auth import auth
        from src.auth import companies
        from src.auth import general_data
        from src.auth import reports
        app.register_blueprint(auth)
        app.register_blueprint(companies)
        app.register_blueprint(general_data)
        app.register_blueprint(reports)

    return app
