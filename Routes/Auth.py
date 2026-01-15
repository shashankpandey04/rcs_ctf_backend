from fastapi import APIRouter, HTTPException, Body, Request
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from Utils.Mongo import db
import jwt
import os
from dotenv import load_dotenv
import bcrypt
from datetime import datetime, timedelta
import pytz
from Utils.Utils import generate_refresh_token
from slowapi import Limiter
from slowapi.util import get_remote_address

load_dotenv()

router = APIRouter()
JWT_SECRET = os.getenv("JWT_SECRET")
limiter = Limiter(key_func=get_remote_address)

# Pydantic models for request validation
class TeamMember(BaseModel):
    name: str
    email: EmailStr
    contact_no: str

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    contact_no: str
    where_you_reside: str
    uni_id: Optional[str] = "N/A"
    uni_name: Optional[str] = "N/A"
    team_name: str
    team_members: List[TeamMember] = []

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class LogoutRequest(BaseModel):
    refresh_token: str

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str
    token: str

@router.post("/register")
@limiter.limit("20/hour")
async def register(request: Request, data: RegisterRequest):
    """
    Register a new user with team details.
    Also creates individual accounts for each team member.
    Team members' initial password is their contact number.
    """
    # Check if team leader email already exists
    email = data.email.lower()
    existing_user = db.users.find_one({"email": email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Check if team name already exists
    existing_team = db.users.find_one({"team_name": data.team_name.replace(" ", "_").lower()})
    if existing_team:
        raise HTTPException(status_code=400, detail="Team name already taken")
    
    # Hash password for team leader
    hashed_password = bcrypt.hashpw(data.password.encode('utf-8'), bcrypt.gensalt())
    
    current_time = datetime.now(pytz.utc)
    
    # Create team leader document
    team_leader_doc = {
        "name": data.name,
        "email": email,
        "password": hashed_password,
        "contact_no": data.contact_no,
        "where_you_reside": data.where_you_reside,
        "uni_id": data.uni_id,
        "uni_name": data.uni_name,
        "team_name": data.team_name,
        "team_members": [member.dict() for member in data.team_members],
        "registered_at": current_time,
        "is_admin": False,
        "is_team_leader": True,
        "score": 0,
        "solved_challenges": []
    }
    
    # Insert team leader into database
    result = db.users.insert_one(team_leader_doc)
    team_leader_id = result.inserted_id
    
    # Create accounts for team members (skip if already exists)
    team_member_ids = []
    members_created = 0
    members_skipped = 0
    skipped_emails = []
    
    for member in data.team_members:
        member_email = member.email.lower()
        
        # Check if member already has an account
        existing_member = db.users.find_one({"email": member_email})
        if existing_member:
            # Skip this member - they already have an account
            members_skipped += 1
            skipped_emails.append(member.email)
            team_member_ids.append(str(existing_member['_id']))
            continue
        
        # Password is their contact number (they can change it later)
        member_password = bcrypt.hashpw(member.contact_no.encode('utf-8'), bcrypt.gensalt())
        
        member_doc = {
            "name": member.name,
            "email": member_email,
            "password": member_password,
            "contact_no": member.contact_no,
            "where_you_reside": data.where_you_reside,  # Same as team leader
            "uni_id": data.uni_id,  # Same as team leader
            "uni_name": data.uni_name,  # Same as team leader
            "team_name": data.team_name,
            "team_leader_id": str(team_leader_id),
            "registered_at": current_time,
            "is_admin": False,
            "is_team_leader": False,
            "is_team_member": True,
            "score": 0,
            "solved_challenges": []
        }
        
        member_result = db.users.insert_one(member_doc)
        team_member_ids.append(str(member_result.inserted_id))
        members_created += 1
    
    # Update team leader with team member IDs
    if team_member_ids:
        db.users.update_one(
            {"_id": team_leader_id},
            {"$set": {"team_member_ids": team_member_ids}}
        )
    
    # Generate tokens and log the team leader in immediately
    refresh_token = generate_refresh_token()
    db.users.update_one({"_id": team_leader_id}, {"$set": {"refresh_token": refresh_token}})
    
    # Create JWT payload for team leader
    payload = {
        "user_id": str(team_leader_id),
        "name": data.name,
        "email": email,
        "team_name": data.team_name,
        "is_admin": False,
        "is_team_leader": True,
        "registered_at": current_time.isoformat(),
        "exp": datetime.now(pytz.utc) + timedelta(hours=2),
        "refresh_token": refresh_token
    }
    
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    
    # Build response message
    message_parts = []
    if members_created > 0:
        message_parts.append(f"{members_created} new team member account(s) created")
    if members_skipped > 0:
        message_parts.append(f"{members_skipped} member(s) skipped (already have accounts)")
    
    message = "Team registered successfully. " + ". ".join(message_parts) if message_parts else "Team registered successfully."
    if members_created > 0:
        message += ". New members can login with their email and contact number as password."
    
    response = {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": str(team_leader_id),
            "name": data.name,
            "email": email,
            "team_name": data.team_name,
            "is_team_leader": True
        },
        "message": message
    }
    
    if skipped_emails:
        response["skipped_members"] = skipped_emails
    
    return response

@router.post("/login")
@limiter.limit("30/15minutes")
async def login(request: Request, data: LoginRequest):
    """
    Login with email and password
    """
    email = data.email.lower()
    user = db.users.find_one({"email": email})
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Verify password
    if not bcrypt.checkpw(data.password.encode('utf-8'), user['password']):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Generate new refresh token
    refresh_token = generate_refresh_token()
    db.users.update_one({"_id": user['_id']}, {"$set": {"refresh_token": refresh_token}})
    
    # Create JWT payload
    payload = {
        "user_id": str(user['_id']),
        "name": user.get('name', ''),
        "email": user['email'],
        "team_name": user.get('team_name', ''),
        "is_admin": user.get('is_admin', False),
        "registered_at": user.get('registered_at', datetime.now(pytz.utc)).isoformat() if isinstance(user.get('registered_at'), datetime) else str(user.get('registered_at', '')),
        "exp": datetime.now(pytz.utc) + timedelta(hours=2),
        "refresh_token": refresh_token
    }
    
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": str(user['_id']),
            "name": user.get('name', ''),
            "email": user['email'],
            "team_name": user.get('team_name', ''),
            "is_admin": user.get('is_admin', False)
        }
    }

@router.post("/refresh")
@limiter.limit("100/hour")
async def refresh_token_endpoint(request: Request, data: RefreshTokenRequest):
    """
    Refresh access token using refresh token
    """
    user = db.users.find_one({"refresh_token": data.refresh_token})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    # Generate new refresh token
    new_refresh_token = generate_refresh_token()
    db.users.update_one({"_id": user['_id']}, {"$set": {"refresh_token": new_refresh_token}})

    # Create new JWT payload
    payload = {
        "user_id": str(user['_id']),
        "name": user.get('name', ''),
        "email": user['email'],
        "team_name": user.get('team_name', ''),
        "is_admin": user.get('is_admin', False),
        "exp": datetime.now(pytz.utc) + timedelta(hours=2),
        "refresh_token": new_refresh_token
    }
    
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    
    return {
        "access_token": token,
        "token_type": "bearer"
    }

@router.post("/logout")
@limiter.limit("50/hour")
async def logout(request: Request, data: LogoutRequest):
    """
    Logout by invalidating refresh token
    """
    user = db.users.find_one({"refresh_token": data.refresh_token})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    # Remove refresh token from user document
    db.users.update_one({"_id": user['_id']}, {"$unset": {"refresh_token": ""}})
    
    return {"detail": "Logged out successfully"}

@router.get("/me")
@limiter.limit("100/minute")
async def get_current_user(request: Request, token: str):
    """
    Get current user information from token
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user_id = payload.get('user_id')
        
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user = db.users.find_one({"_id": user_id})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        return {
            "id": str(user['_id']),
            "name": user.get('name', ''),
            "email": user['email'],
            "team_name": user.get('team_name', ''),
            "is_admin": user.get('is_admin', False),
            "score": user.get('score', 0),
            "contact_no": user.get('contact_no', ''),
            "where_you_reside": user.get('where_you_reside', ''),
            "uni_id": user.get('uni_id', ''),
            "uni_name": user.get('uni_name', ''),
            "team_members": user.get('team_members', [])
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

@router.post("/change-password")
@limiter.limit("10/hour")
async def change_password(request: Request, data: ChangePasswordRequest):
    """
    Change user password. Requires old password verification.
    Useful for team members to change from their initial contact number password.
    """
    try:
        # Decode token to get user_id
        payload = jwt.decode(data.token, JWT_SECRET, algorithms=["HS256"])
        user_id = payload.get('user_id')
        
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Get user from database
        from bson.objectid import ObjectId
        user = db.users.find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Verify old password
        if not bcrypt.checkpw(data.old_password.encode('utf-8'), user['password']):
            raise HTTPException(status_code=401, detail="Current password is incorrect")
        
        # Hash new password
        new_hashed_password = bcrypt.hashpw(data.new_password.encode('utf-8'), bcrypt.gensalt())
        
        # Update password in database
        db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"password": new_hashed_password}}
        )
        
        return {"detail": "Password changed successfully"}
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
