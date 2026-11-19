from markupsafe import escape
from datetime import datetime

from flask import Blueprint, g, render_template, request
from flask_login import current_user

from .models import Assignment, Course, CourseTA, Enrollment, Submission, User, db
from .policy import requires

bp = Blueprint("staff", __name__)


@bp.post("/staff/release/<int:cid>")
@requires("release_grades", load=lambda cid: db.session.get(Course, cid))
def release(cid):
    course = g.policy_object
    for sub in Submission.query.join(Assignment).filter(Assignment.course_id == cid):
        sub.released = True
    db.session.commit()
    return f"Grades released for {escape(course.code)}."


def _course_from_form():
    cid = request.form.get("course_id", "")
    return db.session.get(Course, int(cid)) if cid.isdigit() else None


@bp.get("/staff/assignments/new")
@requires("create_assignment")
def new_assignment_form():
    return render_template("course_new_assignment.html")


@bp.post("/staff/assignments/new")
@requires("create_assignment", load=lambda: _course_from_form())
def new_assignment():
    course = g.policy_object
    deadline = datetime.fromisoformat(request.form["deadline"])
    db.session.add(Assignment(course_id=course.id, title=request.form["title"],
                              deadline=deadline))
    db.session.commit()
    return f"Assignment added to course {course.id}."


@bp.get("/registrar-x9k2")
@requires("manage_roles")
def registrar_console():
    return render_template("registrar_console.html", users=User.query.all())


@bp.post("/registrar-x9k2/role")
@requires("manage_roles")
def set_role():
    user = User.query.filter_by(username=request.form["username"]).first_or_404()
    user.role = request.form["role"]
    db.session.commit()
    return f"Role of {escape(user.username)} set to {escape(user.role)}."


@bp.post("/registrar-x9k2/enroll")
@requires("enroll")
def enroll():
    user = User.query.filter_by(username=request.form["username"]).first_or_404()
    cid = int(request.form["course_id"])
    db.session.add(Enrollment(user_id=user.id, course_id=cid))
    db.session.commit()
    return f"{escape(user.username)} enrolled in course {cid}."


@bp.get("/registrar")
@requires("assign_staff")
def registrar():
    return render_template("registrar.html", courses=Course.query.all())


@bp.post("/courses/<int:cid>/staff/add")
@requires("assign_staff", load=lambda cid: db.session.get(Course, cid))
def add_ta(cid):
    course = g.policy_object
    user = User.query.filter_by(username=request.form["username"]).first_or_404()
    db.session.add(CourseTA(user_id=user.id, course_id=cid))
    db.session.commit()
    return f"{escape(user.username)} added as TA of {escape(course.code)}."
