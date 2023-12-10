from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_login import LoginManager

# init SQLAlchemy so we can use it later in our models
db = SQLAlchemy()

if __name__ == "__main__":
    app = Flask(__name__)

    Bootstrap(app)

    app.config.from_pyfile('config')

    db.init_app(app)

    # Login manager
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    from models import User


    @login_manager.user_loader
    def load_user(user_id):
        # since the user_id is just the primary key of our user table, use it in the query for the user
        return User.query.get(int(user_id))


    # Routes
    # blueprint for auth routes in our app
    from auth import auth as auth_blueprint

    app.register_blueprint(auth_blueprint)

    # blueprint for non-auth parts of app
    from main import build_main_blueprint

    main_blueprint = build_main_blueprint(app)
    app.register_blueprint(main_blueprint)

    app.debug = True

    app.run(host='localhost')
