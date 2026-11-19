from flask import Blueprint, g, jsonify, request
from flask_login import current_user

from .models import User, db
from .policy import requires

bp = Blueprint("api", __name__, url_prefix="/api")


@bp.get("/me")
@requires("self_access")
def me():
    return jsonify(id=current_user.id, username=current_user.username,
                   role=current_user.role, email=current_user.email)


@bp.put("/users/<int:uid>/email")
@requires("change_email", load=lambda uid: db.session.get(User, uid))
def set_email(uid):
    user = g.policy_object
    user.email = request.get_json()["email"]
    db.session.commit()
    return jsonify(status="ok")
