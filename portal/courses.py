from markupsafe import escape
from flask import Blueprint, g, render_template, request
from flask_login import current_user

from .models import Assignment, Course, Submission, db, utcnow
from .policy import requires

bp = Blueprint("courses", __name__)


@bp.get("/")
@requires("self_access")
def dashboard():
    ids = current_user.enrolled_in | current_user.staff_of
    courses = Course.query.filter(Course.id.in_(ids)).all() if ids else []
    return render_template("dashboard.html", courses=courses)


@bp.get("/courses/<int:cid>/materials")
@requires("view_material", load=lambda cid: db.session.get(Course, cid))
def materials(cid):
    return render_template("materials.html", course=g.policy_object)


@bp.post("/assignments/<int:aid>/submit")
@requires("submit", load=lambda aid: db.session.get(Assignment, aid))
def submit(aid):
    assignment = g.policy_object
    sub = Submission.query.filter_by(assignment_id=aid, student_id=current_user.id).first()
    if sub is None:
        sub = Submission(assignment_id=aid, student_id=current_user.id)
        db.session.add(sub)
    sub.body = request.form.get("body", "")
    db.session.commit()
    return render_template("submission.html", sub=sub)


@bp.get("/submissions/<int:sid>")
@requires("view_submission", load=lambda sid: db.session.get(Submission, sid))
def view_submission(sid):
    return render_template("submission.html", sub=g.policy_object)


@bp.post("/submissions/<int:sid>/grade")
@requires("grade", load=lambda sid: db.session.get(Submission, sid))
def grade(sid):
    sub = g.policy_object
    sub.grade = request.form.get("grade")
    db.session.commit()
    return f"Grade for submission {sub.id} set to {escape(sub.grade)}."


@bp.post("/submissions/<int:sid>/change")
@requires("change_grade", load=lambda sid: db.session.get(Submission, sid))
def change(sid):
    sub = g.policy_object
    return render_template("change_confirm.html", sub=sub,
                           grade=request.form.get("grade"))


@bp.post("/submissions/<int:sid>/change/confirm")
@requires("change_grade", load=lambda sid: db.session.get(Submission, sid))
def change_confirm(sid):
    sub = g.policy_object
    if request.form.get("confirmed") == "true":
        sub.grade = request.form.get("grade")
        db.session.commit()
        return f"Grade for submission {sub.id} changed to {escape(sub.grade)}."
    return "Change cancelled."


@bp.get("/gradebook/<int:cid>")
@requires("view_gradebook", load=lambda cid: db.session.get(Course, cid))
def gradebook(cid):
    course = g.policy_object
    subs = (Submission.query.join(Assignment)
            .filter(Assignment.course_id == cid).all())
    return render_template("gradebook.html", course=course, subs=subs)
