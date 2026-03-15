from fastapi import FastAPI, APIRouter, Depends, HTTPException, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import uuid
import jwt
import bcrypt
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime, timezone, timedelta
import random

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

JWT_SECRET = os.environ.get('JWT_SECRET', 'smartcampus_jwt_secret_2024_xK9mP2vL8qR3')
JWT_ALGORITHM = 'HS256'

app = FastAPI(title="Smart Campus Management System API")

# --- YAHAN CORS MIDDLEWARE ADD KIYA GAYA HAI ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Ye line tumhare Phone aur PC dono ko allow karegi
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# -----------------------------------------------

api_router = APIRouter(prefix="/api")
security = HTTPBearer()
logger = logging.getLogger(__name__)

# ─── Auth Helpers ───────────────────────────────────────────────────────────────

def hash_pw(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_pw(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str, role: str, name: str, email: str) -> str:
    payload = {
        'user_id': user_id, 'role': role, 'name': name, 'email': email,
        'exp': datetime.now(timezone.utc) + timedelta(hours=24)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user = await db.users.find_one({'id': payload['user_id']}, {'_id': 0, 'password_hash': 0})
        if not user:
            raise HTTPException(status_code=401, detail='User not found')
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail='Token expired')
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail='Invalid token')

# ─── Pydantic Models ───────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: str
    password: str

class StudentCreate(BaseModel):
    full_name: str
    roll_number: str
    enrollment_number: str = ""
    email: str
    phone: str = ""
    gender: str = "Male"
    date_of_birth: str = ""
    address: str = ""
    department_id: str = ""
    semester: int = 1
    section: str = "A"
    admission_date: str = ""
    status: str = "active"

class FacultyCreate(BaseModel):
    name: str
    faculty_id_number: str
    department_id: str = ""
    designation: str = ""
    email: str
    phone: str = ""

class DepartmentCreate(BaseModel):
    name: str
    code: str
    head_faculty_id: str = ""
    description: str = ""

class SubjectCreate(BaseModel):
    name: str
    code: str
    department_id: str = ""
    semester: int = 1
    credits: int = 3

class AttendanceBulkCreate(BaseModel):
    subject_id: str
    date: str
    records: List[dict]

class MarksCreate(BaseModel):
    student_id: str
    subject_id: str
    internal_marks: float = 0
    practical_marks: float = 0
    final_marks: float = 0

class NoticeCreate(BaseModel):
    title: str
    description: str
    priority: str = "medium"
    audience: str = "all"

class ComplaintCreate(BaseModel):
    title: str
    description: str

class ComplaintUpdate(BaseModel):
    status: str
    remarks: str = ""

def calc_grade(pct):
    if pct >= 90: return 'A+'
    if pct >= 80: return 'A'
    if pct >= 70: return 'B+'
    if pct >= 60: return 'B'
    if pct >= 50: return 'C'
    if pct >= 40: return 'D'
    return 'F'

# ─── AUTH ROUTES ────────────────────────────────────────────────────────────────

@api_router.post("/auth/login")
async def login(req: LoginRequest):
    user = await db.users.find_one({'email': req.email}, {'_id': 0})
    if not user or not verify_pw(req.password, user['password_hash']):
        raise HTTPException(status_code=401, detail='Invalid email or password')
    token = create_token(user['id'], user['role'], user['name'], user['email'])
    return {
        'token': token,
        'user': {'id': user['id'], 'email': user['email'], 'name': user['name'], 'role': user['role']}
    }

@api_router.get("/auth/me")
async def get_me(user=Depends(get_current_user)):
    return user

# ─── STUDENT ROUTES ─────────────────────────────────────────────────────────────

@api_router.get("/students")
async def get_students(user=Depends(get_current_user), search: str = "", department_id: str = "", semester: int = 0, status: str = "", page: int = 1, limit: int = 50):
    query = {}
    if search:
        query['$or'] = [
            {'full_name': {'$regex': search, '$options': 'i'}},
            {'roll_number': {'$regex': search, '$options': 'i'}},
            {'email': {'$regex': search, '$options': 'i'}}
        ]
    if department_id: query['department_id'] = department_id
    if semester > 0: query['semester'] = semester
    if status: query['status'] = status
    
    total = await db.students.count_documents(query)
    students = await db.students.find(query, {'_id': 0}).skip((page - 1) * limit).limit(limit).to_list(limit)
    return {'students': students, 'total': total, 'page': page, 'pages': max(1, (total + limit - 1) // limit)}

@api_router.get("/students/{student_id}")
async def get_student(student_id: str, user=Depends(get_current_user)):
    student = await db.students.find_one({'id': student_id}, {'_id': 0})
    if not student:
        raise HTTPException(status_code=404, detail='Student not found')
    return student

@api_router.post("/students")
async def create_student(data: StudentCreate, user=Depends(get_current_user)):
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail='Not authorized')
    student_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    
    await db.users.insert_one({
        'id': user_id, 'email': data.email,
        'password_hash': hash_pw('student123'),
        'name': data.full_name, 'role': 'student'
    })
    
    student = {'id': student_id, 'user_id': user_id, **data.model_dump(), 'created_at': datetime.now(timezone.utc).isoformat()}
    await db.students.insert_one(student)
    student.pop('_id', None)
    return student

@api_router.put("/students/{student_id}")
async def update_student(student_id: str, data: StudentCreate, user=Depends(get_current_user)):
    if user['role'] not in ['admin', 'faculty']:
        raise HTTPException(status_code=403, detail='Not authorized')
    
    result = await db.students.update_one({'id': student_id}, {'$set': data.model_dump()})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail='Student not found')
        
    updated = await db.students.find_one({'id': student_id}, {'_id': 0})
    if updated.get('user_id'):
        await db.users.update_one({'id': updated.get('user_id')}, {'$set': {'name': data.full_name, 'email': data.email}})
    return updated

@api_router.delete("/students/{student_id}")
async def delete_student(student_id: str, user=Depends(get_current_user)):
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail='Not authorized')
        
    student = await db.students.find_one({'id': student_id}, {'_id': 0})
    if not student:
        raise HTTPException(status_code=404, detail='Student not found')
        
    await db.students.delete_one({'id': student_id})
    if student.get('user_id'):
        await db.users.delete_one({'id': student['user_id']})
        
    await db.attendance.delete_many({'student_id': student_id})
    await db.marks.delete_many({'student_id': student_id})
    return {'message': 'Student deleted successfully'}

# ─── FACULTY ROUTES ─────────────────────────────────────────────────────────────

@api_router.get("/faculty")
async def get_faculty_list(user=Depends(get_current_user), search: str = "", department_id: str = ""):
    query = {}
    if search:
        query['$or'] = [
            {'name': {'$regex': search, '$options': 'i'}},
            {'email': {'$regex': search, '$options': 'i'}},
            {'faculty_id_number': {'$regex': search, '$options': 'i'}}
        ]
    if department_id:
        query['department_id'] = department_id
    faculty = await db.faculty.find(query, {'_id': 0}).to_list(100)
    return {'faculty': faculty}

@api_router.post("/faculty")
async def create_faculty(data: FacultyCreate, user=Depends(get_current_user)):
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail='Not authorized')
    fac_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    
    await db.users.insert_one({
        'id': user_id, 'email': data.email,
        'password_hash': hash_pw('faculty123'),
        'name': data.name, 'role': 'faculty'
    })
    
    fac = {'id': fac_id, 'user_id': user_id, **data.model_dump(), 'created_at': datetime.now(timezone.utc).isoformat()}
    await db.faculty.insert_one(fac)
    fac.pop('_id', None)
    return fac

@api_router.put("/faculty/{faculty_id}")
async def update_faculty(faculty_id: str, data: FacultyCreate, user=Depends(get_current_user)):
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail='Not authorized')
    
    result = await db.faculty.update_one({'id': faculty_id}, {'$set': data.model_dump()})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail='Faculty not found')
    fac = await db.faculty.find_one({'id': faculty_id}, {'_id': 0})
    return fac

@api_router.delete("/faculty/{faculty_id}")
async def delete_faculty(faculty_id: str, user=Depends(get_current_user)):
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail='Not authorized')
        
    fac = await db.faculty.find_one({'id': faculty_id}, {'_id': 0})
    if not fac:
        raise HTTPException(status_code=404, detail='Faculty not found')
        
    await db.faculty.delete_one({'id': faculty_id})
    if fac.get('user_id'):
        await db.users.delete_one({'id': fac['user_id']})
    return {'message': 'Faculty deleted successfully'}

# ─── DEPARTMENT ROUTES ──────────────────────────────────────────────────────────

@api_router.get("/departments")
async def get_departments(user=Depends(get_current_user)):
    depts = await db.departments.find({}, {'_id': 0}).to_list(50)
    return {'departments': depts}

@api_router.post("/departments")
async def create_department(data: DepartmentCreate, user=Depends(get_current_user)):
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail='Not authorized')
    dept = {'id': str(uuid.uuid4()), **data.model_dump(), 'created_at': datetime.now(timezone.utc).isoformat()}
    await db.departments.insert_one(dept)
    dept.pop('_id', None)
    return dept

@api_router.put("/departments/{dept_id}")
async def update_department(dept_id: str, data: DepartmentCreate, user=Depends(get_current_user)):
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail='Not authorized')
    await db.departments.update_one({'id': dept_id}, {'$set': data.model_dump()})
    dept = await db.departments.find_one({'id': dept_id}, {'_id': 0})
    if not dept:
        raise HTTPException(status_code=404, detail='Department not found')
    return dept

@api_router.delete("/departments/{dept_id}")
async def delete_department(dept_id: str, user=Depends(get_current_user)):
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail='Not authorized')
    await db.departments.delete_one({'id': dept_id})
    return {'message': 'Department deleted'}

# ─── SUBJECT ROUTES ─────────────────────────────────────────────────────────────

@api_router.get("/subjects")
async def get_subjects(user=Depends(get_current_user), department_id: str = "", semester: int = 0):
    query = {}
    if department_id: query['department_id'] = department_id
    if semester > 0: query['semester'] = semester
    subjects = await db.subjects.find(query, {'_id': 0}).to_list(100)
    return {'subjects': subjects}

@api_router.post("/subjects")
async def create_subject(data: SubjectCreate, user=Depends(get_current_user)):
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail='Not authorized')
    subj = {'id': str(uuid.uuid4()), **data.model_dump(), 'created_at': datetime.now(timezone.utc).isoformat()}
    await db.subjects.insert_one(subj)
    subj.pop('_id', None)
    return subj

@api_router.put("/subjects/{subject_id}")
async def update_subject(subject_id: str, data: SubjectCreate, user=Depends(get_current_user)):
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail='Not authorized')
    await db.subjects.update_one({'id': subject_id}, {'$set': data.model_dump()})
    subj = await db.subjects.find_one({'id': subject_id}, {'_id': 0})
    return subj

@api_router.delete("/subjects/{subject_id}")
async def delete_subject(subject_id: str, user=Depends(get_current_user)):
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail='Not authorized')
    await db.subjects.delete_one({'id': subject_id})
    return {'message': 'Subject deleted'}

# ─── ATTENDANCE ROUTES ──────────────────────────────────────────────────────────

@api_router.get("/attendance")
async def get_attendance(user=Depends(get_current_user), student_id: str = "", subject_id: str = "", date_val: str = Query("", alias="date"), page: int = 1, limit: int = 100):
    query = {}
    if user['role'] == 'student':
        student = await db.students.find_one({'user_id': user['id']}, {'_id': 0})
        if student: query['student_id'] = student['id']
    elif student_id:
        query['student_id'] = student_id
        
    if subject_id: query['subject_id'] = subject_id
    if date_val: query['date'] = date_val
    
    total = await db.attendance.count_documents(query)
    records = await db.attendance.find(query, {'_id': 0}).sort('date', -1).skip((page - 1) * limit).limit(limit).to_list(limit)
    return {'attendance': records, 'total': total}

@api_router.post("/attendance/bulk")
async def bulk_attendance(data: AttendanceBulkCreate, user=Depends(get_current_user)):
    if user['role'] not in ['admin', 'faculty']:
        raise HTTPException(status_code=403, detail='Not authorized')
        
    records = []
    for r in data.records:
        records.append({
            'id': str(uuid.uuid4()), 'student_id': r['student_id'],
            'subject_id': data.subject_id, 'date': data.date,
            'status': r['status'], 'marked_by': user['id'],
            'created_at': datetime.now(timezone.utc).isoformat()
        })
        
    if records:
        await db.attendance.delete_many({'date': data.date, 'subject_id': data.subject_id})
        await db.attendance.insert_many(records)
        
    return {'message': f'{len(records)} attendance records saved', 'count': len(records)}

@api_router.get("/attendance/summary/{student_id}")
async def attendance_summary(student_id: str, user=Depends(get_current_user)):
    pipeline = [
        {'$match': {'student_id': student_id}},
        {'$group': {
            '_id': '$subject_id',
            'total': {'$sum': 1},
            'present': {'$sum': {'$cond': [{'$eq': ['$status', 'present']}, 1, 0]}},
            'absent': {'$sum': {'$cond': [{'$eq': ['$status', 'absent']}, 1, 0]}},
            'late': {'$sum': {'$cond': [{'$eq': ['$status', 'late']}, 1, 0]}}
        }}
    ]
    results = await db.attendance.aggregate(pipeline).to_list(50)
    subjects = {s['id']: s['name'] for s in await db.subjects.find({}, {'_id': 0}).to_list(100)}
    
    summary = []
    for r in results:
        total = r['total']
        percentage = round((r['present'] + r['late']) / total * 100, 1) if total > 0 else 0
        summary.append({
            'subject_id': r['_id'], 'subject_name': subjects.get(r['_id'], 'Unknown'),
            'total': total, 'present': r['present'], 'absent': r['absent'], 'late': r['late'],
            'percentage': percentage
        })
    return {'summary': summary}

# ─── MARKS ROUTES ───────────────────────────────────────────────────────────────

@api_router.get("/marks")
async def get_marks(user=Depends(get_current_user), student_id: str = "", subject_id: str = ""):
    query = {}
    if user['role'] == 'student':
        student = await db.students.find_one({'user_id': user['id']}, {'_id': 0})
        if student: query['student_id'] = student['id']
    elif student_id:
        query['student_id'] = student_id
        
    if subject_id: query['subject_id'] = subject_id
    marks = await db.marks.find(query, {'_id': 0}).to_list(500)
    return {'marks': marks}

@api_router.post("/marks")
async def create_marks(data: MarksCreate, user=Depends(get_current_user)):
    if user['role'] not in ['admin', 'faculty']:
        raise HTTPException(status_code=403, detail='Not authorized')
        
    total = data.internal_marks + data.practical_marks + data.final_marks
    percentage = round(total, 1)
    grade = calc_grade(percentage)
    result_status = 'Pass' if percentage >= 40 else 'Fail'
    
    mark_data = {
        **data.model_dump(), 'total': total, 'percentage': percentage,
        'grade': grade, 'result_status': result_status, 'entered_by': user['id']
    }
    
    existing = await db.marks.find_one({'student_id': data.student_id, 'subject_id': data.subject_id})
    if existing:
        await db.marks.update_one(
            {'student_id': data.student_id, 'subject_id': data.subject_id},
            {'$set': mark_data}
        )
    else:
        mark_data['id'] = str(uuid.uuid4())
        mark_data['created_at'] = datetime.now(timezone.utc).isoformat()
        await db.marks.insert_one(mark_data)
        
    result = await db.marks.find_one({'student_id': data.student_id, 'subject_id': data.subject_id}, {'_id': 0})
    return result

# ─── NOTICE ROUTES ──────────────────────────────────────────────────────────────

@api_router.get("/notices")
async def get_notices(user=Depends(get_current_user)):
    query = {}
    if user['role'] == 'student':
        query['$or'] = [{'audience': 'all'}, {'audience': 'students'}]
    elif user['role'] == 'faculty':
        query['$or'] = [{'audience': 'all'}, {'audience': 'faculty'}]
        
    notices = await db.notices.find(query, {'_id': 0}).sort('created_at', -1).to_list(100)
    return {'notices': notices}

@api_router.post("/notices")
async def create_notice(data: NoticeCreate, user=Depends(get_current_user)):
    if user['role'] not in ['admin', 'faculty']:
        raise HTTPException(status_code=403, detail='Not authorized')
        
    notice = {
        'id': str(uuid.uuid4()), **data.model_dump(),
        'posted_by': user['name'], 'posted_by_id': user['id'],
        'date': datetime.now(timezone.utc).strftime('%Y-%m-%d'),
        'created_at': datetime.now(timezone.utc).isoformat()
    }
    await db.notices.insert_one(notice)
    notice.pop('_id', None)
    return notice

@api_router.delete("/notices/{notice_id}")
async def delete_notice(notice_id: str, user=Depends(get_current_user)):
    if user['role'] not in ['admin', 'faculty']:
        raise HTTPException(status_code=403, detail='Not authorized')
    await db.notices.delete_one({'id': notice_id})
    return {'message': 'Notice deleted'}

# ─── COMPLAINT ROUTES ───────────────────────────────────────────────────────────

@api_router.get("/complaints")
async def get_complaints(user=Depends(get_current_user), status_filter: str = Query("", alias="status")):
    query = {}
    if user['role'] == 'student':
        student = await db.students.find_one({'user_id': user['id']}, {'_id': 0})
        if student: query['student_id'] = student['id']
        
    if status_filter: query['status'] = status_filter
    complaints = await db.complaints.find(query, {'_id': 0}).sort('created_at', -1).to_list(100)
    return {'complaints': complaints}

@api_router.post("/complaints")
async def create_complaint(data: ComplaintCreate, user=Depends(get_current_user)):
    student = await db.students.find_one({'user_id': user['id']}, {'_id': 0})
    complaint = {
        'id': str(uuid.uuid4()),
        'student_id': student['id'] if student else "",
        'student_name': user['name'],
        **data.model_dump(), 'status': 'pending', 'remarks': '',
        'created_at': datetime.now(timezone.utc).isoformat(),
        'updated_at': datetime.now(timezone.utc).isoformat()
    }
    await db.complaints.insert_one(complaint)
    complaint.pop('_id', None)
    return complaint

@api_router.put("/complaints/{complaint_id}")
async def update_complaint(complaint_id: str, data: ComplaintUpdate, user=Depends(get_current_user)):
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail='Not authorized')
        
    result = await db.complaints.update_one(
        {'id': complaint_id},
        {'$set': {'status': data.status, 'remarks': data.remarks, 'updated_at': datetime.now(timezone.utc).isoformat()}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail='Complaint not found')
        
    complaint = await db.complaints.find_one({'id': complaint_id}, {'_id': 0})
    return complaint

# ─── DASHBOARD ROUTES ───────────────────────────────────────────────────────────

@api_router.get("/dashboard/stats")
async def dashboard_stats(user=Depends(get_current_user)):
    total_students = await db.students.count_documents({})
    total_faculty = await db.faculty.count_documents({})
    total_departments = await db.departments.count_documents({})
    total_subjects = await db.subjects.count_documents({})
    total_notices = await db.notices.count_documents({})
    pending_complaints = await db.complaints.count_documents({'status': 'pending'})
    
    total_att = await db.attendance.count_documents({})
    present_att = await db.attendance.count_documents({'status': {'$in': ['present', 'late']}})
    avg_attendance = round((present_att / total_att) * 100, 1) if total_att > 0 else 0
    
    dept_stats = await db.students.aggregate([
        {'$group': {'_id': '$department_id', 'count': {'$sum': 1}}}
    ]).to_list(50)
    
    depts = {d['id']: d['name'] for d in await db.departments.find({}, {'_id': 0}).to_list(50)}
    dept_distribution = [{'name': depts.get(d['_id'], 'Unknown'), 'count': d['count']} for d in dept_stats]
    
    attendance_trend = []
    for i in range(6, -1, -1):
        day = datetime.now(timezone.utc) - timedelta(days=i)
        date_str = day.strftime('%Y-%m-%d')
        day_name = day.strftime('%a')
        
        day_total = await db.attendance.count_documents({'date': date_str})
        day_present = await db.attendance.count_documents({'date': date_str, 'status': {'$in': ['present', 'late']}})
        pct = round((day_present / day_total) * 100, 1) if day_total > 0 else 0
        attendance_trend.append({'date': date_str, 'day': day_name, 'percentage': pct})
        
    recent_notices = await db.notices.find({}, {'_id': 0}).sort('created_at', -1).limit(5).to_list(5)
    recent_complaints = await db.complaints.find({}, {'_id': 0}).sort('created_at', -1).limit(5).to_list(5)
    
    return {
        'total_students': total_students, 'total_faculty': total_faculty,
        'total_departments': total_departments, 'total_subjects': total_subjects,
        'total_notices': total_notices, 'pending_complaints': pending_complaints,
        'avg_attendance': avg_attendance, 'dept_distribution': dept_distribution,
        'attendance_trend': attendance_trend, 'recent_notices': recent_notices,
        'recent_complaints': recent_complaints
    }

@api_router.get("/dashboard/student")
async def student_dashboard(user=Depends(get_current_user)):
    student = await db.students.find_one({'user_id': user['id']}, {'_id': 0})
    if not student:
        raise HTTPException(status_code=404, detail='Student profile not found')
        
    student_id = student['id']
    
    att_pipeline = [
        {'$match': {'student_id': student_id}},
        {'$group': {'_id': None, 'total': {'$sum': 1}, 'present': {'$sum': {'$cond': [{'$in': ['$status', ['present', 'late']]}, 1, 0]}}}}
    ]
    att_result = await db.attendance.aggregate(att_pipeline).to_list(1)
    att_pct = round((att_result[0]['present'] / att_result[0]['total']) * 100, 1) if att_result and att_result[0]['total'] > 0 else 0
    
    marks = await db.marks.find({'student_id': student_id}, {'_id': 0}).to_list(50)
    subjects = {s['id']: s for s in await db.subjects.find({}, {'_id': 0}).to_list(100)}
    for m in marks:
        subj = subjects.get(m['subject_id'], {})
        m['subject_name'] = subj.get('name', 'Unknown')
        m['subject_code'] = subj.get('code', '')
        
    avg_marks = round(sum(m['percentage'] for m in marks) / len(marks), 1) if marks else 0
    
    notices = await db.notices.find({'$or': [{'audience': 'all'}, {'audience': 'students'}]}, {'_id': 0})\
        .sort('created_at', -1).limit(5).to_list(5)
        
    complaints = await db.complaints.find({'student_id': student_id}, {'_id': 0}).sort('created_at', -1).to_list(10)
    dept = await db.departments.find_one({'id': student.get('department_id')}, {'_id': 0})
    
    return {
        'student': student, 'department': dept, 'attendance_percentage': att_pct,
        'marks': marks, 'avg_marks': avg_marks, 'notices': notices,
        'complaints': complaints, 'total_subjects': len(marks)
    }

@api_router.get("/dashboard/faculty")
async def faculty_dashboard(user=Depends(get_current_user)):
    faculty = await db.faculty.find_one({'user_id': user['id']}, {'_id': 0})
    if not faculty:
        raise HTTPException(status_code=404, detail='Faculty profile not found')
        
    dept = await db.departments.find_one({'id': faculty.get('department_id', '')}, {'_id': 0})
    subjects = await db.subjects.find({'department_id': faculty.get('department_id', '')}, {'_id': 0}).to_list(50)
    students_count = await db.students.count_documents({'department_id': faculty.get('department_id', '')})
    notices = await db.notices.find({}, {'_id': 0}).sort('created_at', -1).limit(5).to_list(5)
    
    return {
        'faculty': faculty, 'department': dept, 'subjects': subjects,
        'students_count': students_count, 'notices': notices
    }

# ─── SEED DATA ──────────────────────────────────────────────────────────────────

@api_router.post("/seed")
async def seed_data():
    existing = await db.users.count_documents({})
    if existing > 0:
        return {'message': 'Data already seeded', 'seeded': False}
        
    dept_cs_id, dept_ec_id, dept_me_id = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    departments = [
        {'id': dept_cs_id, 'name': 'Computer Science', 'code': 'CS', 'head_faculty_id': '', 'description': 'Department of Computer Science and Engineering', 'created_at': datetime.now(timezone.utc).isoformat()},
        {'id': dept_ec_id, 'name': 'Electronics & Communication', 'code': 'EC', 'head_faculty_id': '', 'description': 'Department of Electronics and Communication Engineering', 'created_at': datetime.now(timezone.utc).isoformat()},
        {'id': dept_me_id, 'name': 'Mechanical Engineering', 'code': 'ME', 'head_faculty_id': '', 'description': 'Department of Mechanical Engineering', 'created_at': datetime.now(timezone.utc).isoformat()}
    ]
    
    subj_ids = [str(uuid.uuid4()) for _ in range(5)]
    subjects = [
        {'id': subj_ids[0], 'name': 'Data Structures & Algorithms', 'code': 'CS301', 'department_id': dept_cs_id, 'semester': 3, 'credits': 4, 'created_at': datetime.now(timezone.utc).isoformat()},
        {'id': subj_ids[1], 'name': 'Database Management Systems', 'code': 'CS302', 'department_id': dept_cs_id, 'semester': 3, 'credits': 4, 'created_at': datetime.now(timezone.utc).isoformat()},
        {'id': subj_ids[2], 'name': 'Computer Networks', 'code': 'CS501', 'department_id': dept_cs_id, 'semester': 5, 'credits': 3, 'created_at': datetime.now(timezone.utc).isoformat()},
        {'id': subj_ids[3], 'name': 'Digital Electronics', 'code': 'EC301', 'department_id': dept_ec_id, 'semester': 3, 'credits': 4, 'created_at': datetime.now(timezone.utc).isoformat()},
        {'id': subj_ids[4], 'name': 'Thermodynamics', 'code': 'ME301', 'department_id': dept_me_id, 'semester': 3, 'credits': 3, 'created_at': datetime.now(timezone.utc).isoformat()}
    ]
    
    admin_id = str(uuid.uuid4())
    users = [
        {'id': admin_id, 'email': 'admin@smartcampus.edu', 'password_hash': hash_pw('admin123'), 'name': 'Campus Administrator', 'role': 'admin'}
    ]
    
    faculty_data = [
        ("Dr. Rajesh Kumar", "FAC001", dept_cs_id, "Professor", "rajesh.kumar@smartcampus.edu", "+91 9876543210"),
        ("Dr. Priya Sharma", "FAC002", dept_cs_id, "Associate Professor", "priya.sharma@smartcampus.edu", "+91 9876543211"),
        ("Dr. Amit Patel", "FAC003", dept_ec_id, "Professor", "amit.patel@smartcampus.edu", "+91 9876543212"),
        ("Dr. Neha Singh", "FAC004", dept_me_id, "Assistant Professor", "neha.singh@smartcampus.edu", "+91 9876543213"),
        ("Dr. Sanjay Verma", "FAC005", dept_cs_id, "Assistant Professor", "sanjay.verma@smartcampus.edu", "+91 9876543214")
    ]
    
    faculty_records = []
    for name, fid, dept, desig, email, phone in faculty_data:
        uid, fac_id = str(uuid.uuid4()), str(uuid.uuid4())
        users.append({'id': uid, 'email': email, 'password_hash': hash_pw('faculty123'), 'name': name, 'role': 'faculty'})
        faculty_records.append({'id': fac_id, 'user_id': uid, 'name': name, 'faculty_id_number': fid, 'department_id': dept, 'designation': desig, 'email': email, 'phone': phone, 'created_at': datetime.now(timezone.utc).isoformat()})
        
    departments[0]['head_faculty_id'] = faculty_records[0]['id']
    departments[1]['head_faculty_id'] = faculty_records[2]['id']
    departments[2]['head_faculty_id'] = faculty_records[3]['id']
    
    student_data = [
        ("Aarav Mehta", "CS2023001", "EN2023001", "aarav.mehta@smartcampus.edu", "Male", dept_cs_id, 3, "A"),
        ("Priya Gupta", "CS2023002", "EN2023002", "priya.gupta@smartcampus.edu", "Female", dept_cs_id, 3, "A"),
        ("Rohan Singh", "CS2023003", "EN2023003", "rohan.singh@smartcampus.edu", "Male", dept_cs_id, 3, "A"),
        ("Sneha Patel", "CS2023004", "EN2023004", "sneha.patel@smartcampus.edu", "Female", dept_cs_id, 3, "B"),
        ("Vivek Kumar", "CS2023005", "EN2023005", "vivek.kumar@smartcampus.edu", "Male", dept_cs_id, 3, "B"),
        ("Ananya Reddy", "CS2022001", "EN2022001", "ananya.reddy@smartcampus.edu", "Female", dept_cs_id, 5, "A"),
        ("Karan Joshi", "CS2022002", "EN2022002", "karan.joshi@smartcampus.edu", "Male", dept_cs_id, 5, "A"),
        ("Ishita Sharma", "CS2022003", "EN2022003", "ishita.sharma@smartcampus.edu", "Female", dept_cs_id, 5, "A"),
        ("Aditya Verma", "EC2023001", "EN2023006", "aditya.verma@smartcampus.edu", "Male", dept_ec_id, 3, "A"),
        ("Meera Iyer", "EC2023002", "EN2023007", "meera.iyer@smartcampus.edu", "Female", dept_ec_id, 3, "A"),
        ("Rahul Nair", "EC2023003", "EN2023008", "rahul.nair@smartcampus.edu", "Male", dept_ec_id, 3, "B"),
        ("Pooja Desai", "EC2023004", "EN2023009", "pooja.desai@smartcampus.edu", "Female", dept_ec_id, 3, "B"),
        ("Arjun Malhotra", "EC2022001", "EN2022004", "arjun.malhotra@smartcampus.edu", "Male", dept_ec_id, 5, "A"),
        ("Divya Saxena", "EC2022002", "EN2022005", "divya.saxena@smartcampus.edu", "Female", dept_ec_id, 5, "A"),
        ("Nikhil Chauhan", "ME2023001", "EN2023010", "nikhil.chauhan@smartcampus.edu", "Male", dept_me_id, 3, "A"),
        ("Riya Agarwal", "ME2023002", "EN2023011", "riya.agarwal@smartcampus.edu", "Female", dept_me_id, 3, "A"),
        ("Siddharth Rao", "ME2023003", "EN2023012", "siddharth.rao@smartcampus.edu", "Male", dept_me_id, 3, "B"),
        ("Kavya Jain", "ME2022001", "EN2022006", "kavya.jain@smartcampus.edu", "Female", dept_me_id, 5, "A"),
        ("Manish Tiwari", "ME2022002", "EN2022007", "manish.tiwari@smartcampus.edu", "Male", dept_me_id, 5, "A"),
        ("Tanya Bhatia", "ME2022003", "EN2022008", "tanya.bhatia@smartcampus.edu", "Female", dept_me_id, 5, "B")
    ]
    
    student_records = []
    for name, roll, enroll, email, gender, dept, sem, sec in student_data:
        uid, sid = str(uuid.uuid4()), str(uuid.uuid4())
        users.append({'id': uid, 'email': email, 'password_hash': hash_pw('student123'), 'name': name, 'role': 'student'})
        student_records.append({
            'id': sid, 'user_id': uid, 'full_name': name, 'roll_number': roll,
            'enrollment_number': enroll, 'email': email, 'phone': f'+91 98{random.randint(10000000,99999999)}',
            'gender': gender, 'date_of_birth': f'{random.randint(2000,2003)}-{random.randint(1,12):02d}-{random.randint(1,28):02d}',
            'address': f'{random.randint(1,500)}, Sector {random.randint(1,50)}, New Delhi',
            'department_id': dept, 'semester': sem, 'section': sec,
            'admission_date': '2023-08-01' if sem <= 3 else '2022-08-01',
            'status': 'active', 'created_at': datetime.now(timezone.utc).isoformat()
        })
        
    attendance_records = []
    for student in student_records:
        student_subjects = [s for s in subjects if s['department_id'] == student['department_id'] and s['semester'] == student['semester']]
        for subj in student_subjects:
            for day_offset in range(14):
                day_dt = datetime.now(timezone.utc) - timedelta(days=day_offset)
                if day_dt.weekday() >= 5: continue
                attendance_records.append({
                    'id': str(uuid.uuid4()), 'student_id': student['id'], 'subject_id': subj['id'],
                    'date': day_dt.strftime('%Y-%m-%d'),
                    'status': random.choices(['present', 'absent', 'late'], weights=[80, 10, 10])[0],
                    'marked_by': faculty_records[0]['id'], 'created_at': datetime.now(timezone.utc).isoformat()
                })
                
    marks_records = []
    for student in student_records:
        student_subjects = [s for s in subjects if s['department_id'] == student['department_id'] and s['semester'] == student['semester']]
        for subj in student_subjects:
            internal, practical, final = round(random.uniform(15, 30), 1), round(random.uniform(10, 20), 1), round(random.uniform(20, 50), 1)
            total = round(internal + practical + final, 1)
            marks_records.append({
                'id': str(uuid.uuid4()), 'student_id': student['id'], 'subject_id': subj['id'],
                'internal_marks': internal, 'practical_marks': practical, 'final_marks': final,
                'total': total, 'percentage': round(total, 1), 'grade': calc_grade(total),
                'result_status': 'Pass' if total >= 40 else 'Fail',
                'entered_by': faculty_records[0]['id'], 'created_at': datetime.now(timezone.utc).isoformat()
            })
            
    notices = [
        {'id': str(uuid.uuid4()), 'title': 'Mid-Semester Examination Schedule', 'description': 'Mid-semester examinations for all departments commence from March 15, 2025. Collect hall tickets from the examination cell by March 10.', 'priority': 'high', 'audience': 'all', 'posted_by': 'Campus Administrator', 'posted_by_id': admin_id, 'date': '2025-03-01', 'created_at': datetime.now(timezone.utc).isoformat()},
        {'id': str(uuid.uuid4()), 'title': 'Annual Sports Day Registration', 'description': 'Register for Annual Sports Day events. Last date: March 20. Contact your class representative for details.', 'priority': 'medium', 'audience': 'students', 'posted_by': 'Dr. Rajesh Kumar', 'posted_by_id': faculty_records[0]['id'], 'date': '2025-02-28', 'created_at': (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()},
        {'id': str(uuid.uuid4()), 'title': 'Faculty Development Program', 'description': 'Two-day FDP on "AI in Education" on March 25-26. All faculty members confirm attendance.', 'priority': 'medium', 'audience': 'faculty', 'posted_by': 'Campus Administrator', 'posted_by_id': admin_id, 'date': '2025-02-25', 'created_at': (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()},
        {'id': str(uuid.uuid4()), 'title': 'Library Hours Extended', 'description': 'Library open till 9 PM during examination period. Reading room and computer lab available for exam preparation.', 'priority': 'low', 'audience': 'all', 'posted_by': 'Campus Administrator', 'posted_by_id': admin_id, 'date': '2025-02-20', 'created_at': (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()},
        {'id': str(uuid.uuid4()), 'title': 'Campus Placement Drive - TCS', 'description': 'TCS placement drive on April 5, 2025. Eligible students (6th sem+, 60%+ aggregate) register on placement portal by March 28.', 'priority': 'high', 'audience': 'students', 'posted_by': 'Dr. Priya Sharma', 'posted_by_id': faculty_records[1]['id'], 'date': '2025-02-18', 'created_at': (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()}
    ]
    
    complaints = [
        {'id': str(uuid.uuid4()), 'student_id': student_records[0]['id'], 'student_name': 'Aarav Mehta', 'title': 'Wi-Fi Issues in Lab 3', 'description': 'Wi-Fi in Computer Lab 3 has been intermittent for a week, affecting practical sessions.', 'status': 'in_progress', 'remarks': 'IT team investigating router replacement.', 'created_at': (datetime.now(timezone.utc) - timedelta(days=5)).isoformat(), 'updated_at': (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()},
        {'id': str(uuid.uuid4()), 'student_id': student_records[3]['id'], 'student_name': 'Sneha Patel', 'title': 'Broken Projector in Room 201', 'description': 'Projector in classroom 201 display is flickering during lectures.', 'status': 'pending', 'remarks': '', 'created_at': (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(), 'updated_at': (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()},
        {'id': str(uuid.uuid4()), 'student_id': student_records[8]['id'], 'student_name': 'Aditya Verma', 'title': 'Request for Extra Lab Hours', 'description': 'Need additional lab hours for Digital Electronics project. Current 2-hour slots insufficient.', 'status': 'resolved', 'remarks': 'Extra lab hours approved for Saturday mornings.', 'created_at': (datetime.now(timezone.utc) - timedelta(days=15)).isoformat(), 'updated_at': (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()},
        {'id': str(uuid.uuid4()), 'student_id': student_records[14]['id'], 'student_name': 'Nikhil Chauhan', 'title': 'Water Cooler Not Working', 'description': 'Water cooler near ME department not cooling properly. Needs repair.', 'status': 'pending', 'remarks': '', 'created_at': (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(), 'updated_at': (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()},
        {'id': str(uuid.uuid4()), 'student_id': student_records[5]['id'], 'student_name': 'Ananya Reddy', 'title': 'Attendance Discrepancy', 'description': 'Computer Networks attendance shows 2 incorrect absences. Have evidence of attendance.', 'status': 'in_progress', 'remarks': 'Forwarded to subject teacher for verification.', 'created_at': (datetime.now(timezone.utc) - timedelta(days=7)).isoformat(), 'updated_at': (datetime.now(timezone.utc) - timedelta(days=4)).isoformat()}
    ]
    
    await db.users.insert_many(users)
    await db.departments.insert_many(departments)
    await db.subjects.insert_many(subjects)
    await db.faculty.insert_many(faculty_records)
    await db.students.insert_many(student_records)
    if attendance_records: await db.attendance.insert_many(attendance_records)
    if marks_records: await db.marks.insert_many(marks_records)
    await db.notices.insert_many(notices)
    await db.complaints.insert_many(complaints)
    
    logger.info(f"Seeded: {len(users)} users, {len(student_records)} students, {len(faculty_records)} faculty, {len(attendance_records)} attendance, {len(marks_records)} marks")
    return {'message': 'Demo data seeded successfully', 'seeded': True}

# ─── APP CONFIG ─────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    count = await db.users.count_documents({})
    if count == 0:
        await seed_data()
        logger.info("Demo data seeded on startup")

app.include_router(api_router)

# Note: CORS Middleware humne shuru mein move kar diya hai taaki routing se pehle load ho.

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

@app.on_event("shutdown")
async def shutdown():
    client.close()
