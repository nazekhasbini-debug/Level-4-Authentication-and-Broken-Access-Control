"""Access control policy for the Course Portal.

  ROLE_PERMISSIONS   RBAC: which permissions each role could ever use
  CONDITIONS         ABAC: one function per permission, (user, obj, ctx) -> bool
  can()              step 1 RBAC, step 2 ABAC; anything unknown is denied
  requires()         declare the permission a route needs, next to the route
  install(app)       one before_request hook that checks every request
"""
import secrets

from flask import abort, g, request, session
from flask_login import current_user

from datetime import timedelta

from .models import Extension, utcnow

STUDENT, TA, INSTRUCTOR, REGISTRAR, CHAIR = "student", "ta", "instructor", "registrar", "chair"
ALL_ROLES = {STUDENT, TA, INSTRUCTOR, REGISTRAR, CHAIR}

ROLE_PERMISSIONS = {
    # --- lecture table (R1-R6) ---
    "view_material":     {STUDENT, TA, INSTRUCTOR},
    "submit":             {STUDENT},
    "view_grade":         {STUDENT},
    "create_assignment":  {INSTRUCTOR},
    "grade":              {TA, INSTRUCTOR},
    "change_grade":       {INSTRUCTOR},
    "enroll":             {REGISTRAR},
    # --- added for the 7 attacks ---
    "view_gradebook":     {TA, INSTRUCTOR, CHAIR},   # N1: chair added, view only
    "release_grades":     {INSTRUCTOR},
    "manage_roles":       {REGISTRAR},
    "assign_staff":       {REGISTRAR},
    # --- plain "signed in" pages: no object, every role may use them ---
    "self_access":        ALL_ROLES,
    "change_email":       ALL_ROLES,
    "view_submission":    {STUDENT, TA, INSTRUCTOR},
}


def _no_object(user, obj, ctx):
    return True


def _has_extension(user, assignment):
    return Extension.query.filter_by(
        student_id=user.id, assignment_id=assignment.id).first() is not None


CAMPUS_PREFIXES = ("10.", "127.")


CONDITIONS = {
    # R1: course in enrolled_in or in staff_of
    "view_material": lambda user, obj, ctx: obj.id in (user.enrolled_in | user.staff_of),
    # R2: course in enrolled_in, before the deadline.
    # N2: a student with an approved extension may submit up to 3 days late.
    "submit": lambda user, obj, ctx: (
        obj.course_id in user.enrolled_in and (
            utcnow() < obj.deadline or (
                utcnow() < obj.deadline + timedelta(days=3)
                and _has_extension(user, obj)))),
    # R3: own submission, and it is released
    "view_grade": lambda user, obj, ctx: (
        obj.student_id == user.id and obj.released),
    # R4: course in teaches (object missing only on the blank "new assignment" form)
    "create_assignment": lambda user, obj, ctx: (
        True if obj is None else obj.id in user.teaches),
    # R5: course in staff_of, not released.
    # N4: a TA who is also enrolled in the course may never grade it.
    "grade": lambda user, obj, ctx: (
        obj.course_id in user.staff_of
        and obj.course_id not in user.enrolled_in
        and not obj.released),
    # R5: course in teaches, grade already released, before the grade deadline.
    # N3: only from the campus network.
    "change_grade": lambda user, obj, ctx: (
        obj.course_id in user.teaches
        and obj.released
        and utcnow() < obj.course.grade_deadline
        and (ctx or {}).get("network") == "campus"),
    # R6: none
    "enroll": _no_object,
    # attack 2: course in staff_of.
    # N1: a department chair may also view (not change) every course in
    # their own department.
    "view_gradebook": lambda user, obj, ctx: (
        obj.id in user.staff_of
        or (user.role == CHAIR and obj.department == user.department)),
    # attack 3: course in teaches
    "release_grades": lambda user, obj, ctx: obj.id in user.teaches,
    # attack 1: none
    "manage_roles": _no_object,
    # attack 7: none
    "assign_staff": _no_object,
    # own submissions, or anything in a course you staff
    "view_submission": lambda user, obj, ctx: (
        obj.student_id == user.id or obj.course_id in user.staff_of),
    # attack 5: only your own account
    "change_email": lambda user, obj, ctx: obj is not None and obj.id == user.id,
    "self_access": _no_object,
}


def can(user, perm, obj=None, ctx=None):
    if user is None or not getattr(user, "is_authenticated", False):
        return False
    roles = ROLE_PERMISSIONS.get(perm)
    if roles is None or user.role not in roles:
        return False
    condition = CONDITIONS.get(perm)
    if condition is None:
        return False
    try:
        return bool(condition(user, obj, ctx))
    except AttributeError:
        return False


def requires(perm, load=None):
    """Declare the permission a route needs, and how to load the object it is
    about. `load` is called with the route's URL keyword arguments and must
    return the object or None if it does not exist."""
    def deco(f):
        f._policy = (perm, load)
        return f
    return deco


PUBLIC_ENDPOINTS = {"auth.login", "auth.logout", "auth.forgot", "auth.reset",
                     "robots", "static"}

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def build_ctx():
    # request.remote_addr is the actual TCP peer address Werkzeug saw; it is
    # never read from a client-supplied header (X-Forwarded-For and friends
    # are ignored on purpose), so a forged header cannot move this value.
    addr = request.remote_addr or ""
    campus = addr.startswith(CAMPUS_PREFIXES)
    return {"network": "campus" if campus else "external"}


def install(app):
    @app.before_request
    def enforce_policy():
        endpoint = request.endpoint
        if endpoint is None:
            return  # Flask will 404 this itself
        if endpoint in PUBLIC_ENDPOINTS:
            return

        if not current_user.is_authenticated:
            abort(401)

        view = app.view_functions.get(endpoint)
        rule = getattr(view, "_policy", None)
        if rule is None:
            abort(403)  # a route nobody declared a rule for is refused
        perm, load = rule

        # Check the role first: cheap, and it tells an attacker nothing about
        # whether any particular object id exists.
        roles = ROLE_PERMISSIONS.get(perm)
        if roles is None or current_user.role not in roles:
            abort(404 if load else 403)

        obj = None
        if load is not None:
            obj = load(**request.view_args)
            if obj is None:
                abort(404)

        if not can(current_user, perm, obj, build_ctx()):
            abort(404 if load else 403)

        g.policy_object = obj

        if request.method in UNSAFE_METHODS:
            sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
            expected = session.get("csrf_token") or ""
            if not expected or not secrets.compare_digest(sent, expected):
                abort(403)
