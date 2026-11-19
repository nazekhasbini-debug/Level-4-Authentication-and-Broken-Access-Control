"""N1-N4: three test cases per new rule (twelve in all), at least two denials
each. N3 also needs one test that sends a forged header from an outside
address and expects a refusal.
"""
from conftest import login

from portal.models import Course, CourseTA, Enrollment, Extension, db
from portal.policy import can

CAMPUS = {"network": "campus"}
EXTERNAL = {"network": "external"}


# ---------------------------------------------------------------------------
# N1: a department chair can VIEW (not change) the grades of every course in
# their own department.
# ---------------------------------------------------------------------------

def test_n1_chair_views_gradebook_in_own_department(world):
    assert can(world["chair"], "view_gradebook", world["cmps215"], CAMPUS) is True


def test_n1_student_still_cannot_view_gradebook(world):
    assert can(world["lina"], "view_gradebook", world["cmps215"], CAMPUS) is False


def test_n1_chair_cannot_view_gradebook_of_another_department(world, app):
    with app.app_context():
        other = Course(code="MATH 101", title="Calculus", department="MATH",
                       instructor_id=world["dr_haddad"].id,
                       grade_deadline=world["cmps215"].grade_deadline)
        db.session.add(other)
        db.session.commit()
        assert can(world["chair"], "view_gradebook", other, CAMPUS) is False


def test_n1_chair_cannot_change_grades(world):
    # N1 says VIEW only: chair was never added to change_grade's roles.
    assert can(world["chair"], "change_grade", world["sub_rel_215"], CAMPUS) is False


# ---------------------------------------------------------------------------
# N2: a student with an approved extension can submit up to 3 days after the
# deadline.
# ---------------------------------------------------------------------------

def test_n2_late_submission_without_extension_is_denied(world):
    assert can(world["lina"], "submit", world["a3_late"]) is False


def test_n2_late_submission_with_extension_is_allowed(world, app):
    with app.app_context():
        db.session.add(Extension(student_id=world["lina"].id,
                                 assignment_id=world["a3_late"].id,
                                 granted_by_id=world["dr_haddad"].id))
        db.session.commit()
        assert can(world["lina"], "submit", world["a3_late"]) is True


def test_n2_extension_does_not_help_once_the_grace_period_is_over(world, app):
    with app.app_context():
        from datetime import timedelta
        from portal.models import Assignment, utcnow
        old = Assignment(course_id=world["cmps215"].id, title="A0 Ancient",
                         deadline=utcnow() - timedelta(days=10))
        db.session.add(old)
        db.session.flush()
        db.session.add(Extension(student_id=world["lina"].id, assignment_id=old.id,
                                 granted_by_id=world["dr_haddad"].id))
        db.session.commit()
        assert can(world["lina"], "submit", old) is False


# ---------------------------------------------------------------------------
# N3: instructors can change a released grade only from the campus network.
# ---------------------------------------------------------------------------

def test_n3_change_grade_from_campus_is_allowed(world):
    assert can(world["dr_haddad"], "change_grade", world["sub_rel_215"], CAMPUS) is True


def test_n3_change_grade_from_outside_is_denied(world):
    assert can(world["dr_haddad"], "change_grade", world["sub_rel_215"], EXTERNAL) is False


def test_n3_forged_header_from_an_outside_address_is_still_denied(client):
    from portal.models import Submission
    login(client, "dr_haddad")
    token = client.csrf_token()
    before = db.session.get(Submission, 1).grade
    r = client.post(
        "/submissions/1/change/confirm",
        data={"grade": "A+", "confirmed": "true", "csrf_token": token},
        headers={"X-Forwarded-For": "127.0.0.1"},   # claims to be on campus
        environ_overrides={"REMOTE_ADDR": "8.8.8.8"},  # the real TCP peer
    )
    assert r.status_code in (403, 404)
    db.session.expire_all()
    assert db.session.get(Submission, 1).grade == before


# ---------------------------------------------------------------------------
# N4: a TA who is also enrolled in a course must never grade that course.
# ---------------------------------------------------------------------------

def test_n4_ta_enrolled_in_the_same_course_cannot_grade_it(world):
    # rana is both a TA and a student of CMPS 202 (seed.py)
    assert can(world["rana_ta"], "grade", world["sub_open_202"]) is False


def test_n4_ta_not_enrolled_can_still_grade(world):
    assert can(world["omar_ta"], "grade", world["sub_open_215"]) is True


def test_n4_newly_conflicted_ta_is_denied(world, app):
    # sami is already enrolled in CMPS 202; make him a TA of it too.
    with app.app_context():
        db.session.add(CourseTA(user_id=world["sami"].id, course_id=world["cmps202"].id))
        db.session.commit()
        sami = world["sami"]
        sami.role = "ta"
        assert can(sami, "grade", world["sub_open_202"]) is False
