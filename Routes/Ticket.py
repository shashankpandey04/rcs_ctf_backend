from fastapi import APIRouter, HTTPException, Header, Request, Depends
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, Literal
from Utils.Mongo import db
import jwt
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
import pytz
import hmac
import hashlib
import secrets
import string
import logging
from slowapi import Limiter
from slowapi.util import get_remote_address

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

router = APIRouter()
JWT_SECRET = os.getenv("JWT_SECRET")
RAZORPAY_WEBHOOK_SECRET = os.getenv("RAZORPAY_WEBHOOK_SECRET", "secret_key_here")
ADMIN_SECRET_KEY = os.getenv("ADMIN_SECRET_KEY", "secure_admin_key_here")
limiter = Limiter(key_func=get_remote_address)

# Ticket configuration with default limits (can be overridden via DB)
DEFAULT_TICKET_CONFIG = {
    "lpu": {"price": 200, "limit": 200, "name": "LPU Student"},
    "external": {"price": 300, "limit": 300, "name": "External Student"},
    "professional": {"price": 500, "limit": 100, "name": "Professional"}
}

# Global variables for caching
TICKET_CONFIG = {}
LAST_CONFIG_LOAD = None
CONFIG_CACHE_TTL = 300  # Cache for 5 minutes

def get_ticket_config(force_reload=False):
    """
    Get ticket configuration with caching
    Automatically reloads from DB if cache expires or force_reload is True
    """
    global TICKET_CONFIG, LAST_CONFIG_LOAD
    
    now = datetime.now(pytz.utc)
    
    # Check if cache needs refresh
    if force_reload or LAST_CONFIG_LOAD is None or \
       (now - LAST_CONFIG_LOAD).total_seconds() > CONFIG_CACHE_TTL:
        load_ticket_config()
    
    return TICKET_CONFIG

def load_ticket_config():
    """Load ticket configuration from database, use defaults if not present"""
    global TICKET_CONFIG, LAST_CONFIG_LOAD
    try:
        config_doc = db.ticket_limits.find_one({"_id": "global"})
        if config_doc and config_doc.get("tiers"):
            TICKET_CONFIG = config_doc.get("tiers", DEFAULT_TICKET_CONFIG.copy())
            logger.info(f"✅ Loaded ticket config from database")
        else:
            TICKET_CONFIG = DEFAULT_TICKET_CONFIG.copy()
            logger.info("Using default ticket configuration")
        LAST_CONFIG_LOAD = datetime.now(pytz.utc)
    except Exception as e:
        logger.error(f"Error loading ticket config: {e}")
        TICKET_CONFIG = DEFAULT_TICKET_CONFIG.copy()
        LAST_CONFIG_LOAD = datetime.now(pytz.utc)

# Initialize database collections on startup
def init_ticket_system():
    """Initialize ticket system with default values if not present"""
    try:
        # Ensure ticket_config exists
        if not db.ticket_config.find_one({"_id": "global"}):
            db.ticket_config.insert_one({
                "_id": "global",
                "enabled": False,
                "updated_at": datetime.now(pytz.utc),
                "created_at": datetime.now(pytz.utc)
            })
            logger.info("✅ Initialized ticket_config collection")
        
        # Ensure ticket limits config exists
        if not db.ticket_limits.find_one({"_id": "global"}):
            db.ticket_limits.insert_one({
                "_id": "global",
                "tiers": DEFAULT_TICKET_CONFIG.copy(),
                "updated_at": datetime.now(pytz.utc),
                "created_at": datetime.now(pytz.utc)
            })
            logger.info("✅ Initialized ticket_limits collection with defaults")
        
        # Ensure ticket categories exist
        for tier in ["lpu", "external", "professional"]:
            if not db.tickets_categories.find_one({"tier": tier}):
                db.tickets_categories.insert_one({
                    "tier": tier,
                    "count": 0,
                    "created_at": datetime.now(pytz.utc)
                })
                logger.info(f"✅ Initialized {tier} tier")
        
        # Create indexes for better performance
        db.tickets.create_index([("email", 1), ("status", 1)])
        db.tickets.create_index([("payment_id", 1)], unique=True, sparse=True)
        db.razorpay_events.create_index([("event_id", 1)], unique=True, sparse=True)
        logger.info("✅ Database indexes created")
        
        # Load ticket configuration
        load_ticket_config()
        
    except Exception as e:
        logger.error(f"❌ Error initializing ticket system: {e}")

# Initialize on module load
init_ticket_system()

# Pydantic models with validation
class TicketToggleRequest(BaseModel):
    secret_key: str = Field(..., min_length=8)
    enabled: bool

class TicketCheckRequest(BaseModel):
    email: EmailStr
    secret_key: str = Field(..., min_length=8)

class TicketStatusResponse(BaseModel):
    status: str
    message: str
    data: Optional[dict] = None

# Helper functions
def secretTokenGenerator(length=32):
    """Generate secure random token for tickets"""
    if length < 16:
        length = 16
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

def verify_token(authorization: str = Header(None)):
    """Verify JWT token from Authorization header"""
    if not authorization:
        logger.warning("Missing authorization header")
        raise HTTPException(status_code=401, detail="Authorization header missing")
    
    try:
        token = authorization.replace("Bearer ", "").strip()
        if not token:
            raise HTTPException(status_code=401, detail="Invalid token format")
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("Expired token attempt")
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        raise HTTPException(status_code=401, detail="Token verification failed")

def get_current_tier() -> str:
    """
    Determine the current active ticket tier based on sold counts and availability
    Handles missing database documents gracefully
    """
    try:
        # Check if tickets are enabled globally
        config = db.ticket_config.find_one({"_id": "global"})
        if not config:
            logger.warning("Ticket config not found, initializing...")
            init_ticket_system()
            return "closed"
        
        if not config.get("enabled", False):
            return "closed"
        
        # Get current ticket limits (with cache)
        ticket_config = get_ticket_config()
        
        # Check each tier in order
        for tier in ["lpu", "external", "professional"]:
            tier_doc = db.tickets_categories.find_one({"tier": tier})
            if not tier_doc:
                # Initialize missing tier
                db.tickets_categories.insert_one({
                    "tier": tier,
                    "count": 0,
                    "created_at": datetime.now(pytz.utc)
                })
                sold = 0
            else:
                sold = int(tier_doc.get("count", 0))
            
            limit = ticket_config[tier]["limit"]
            
            if sold < limit:
                return tier
        
        return "sold_out"
    except Exception as e:
        logger.error(f"Error in get_current_tier: {e}")
        return "closed"

def get_ticket_price(tier: str) -> float:
    """Get price for a specific tier (uses dynamic config)"""
    config = get_ticket_config()
    return config.get(tier, {}).get("price", 0.0)

def check_availability(tier: str) -> bool:
    """
    Check if tickets are available for a specific tier
    Handles missing documents gracefully
    """
    try:
        # Check global enable/disable
        config = db.ticket_config.find_one({"_id": "global"})
        if not config:
            logger.warning("Ticket config not found")
            return False
        
        if not config.get("enabled", False):
            return False
        
        # Get current ticket limits (with cache)
        ticket_config = get_ticket_config()
        
        if tier not in ticket_config:
            logger.warning(f"Invalid tier: {tier}")
            return False
        
        limit = ticket_config[tier]["limit"]
        
        doc = db.tickets_categories.find_one({"tier": tier})
        if not doc:
            # Initialize missing tier
            db.tickets_categories.insert_one({
                "tier": tier,
                "count": 0,
                "created_at": datetime.now(pytz.utc)
            })
            sold = 0
        else:
            sold = int(doc.get("count", 0))
        
        return sold < limit
    except Exception as e:
        logger.error(f"Error checking availability for {tier}: {e}")
        return False

def get_tier_stats():
    """
    Get statistics for all ticket tiers
    Handles missing documents gracefully
    """
    stats = {}
    try:
        # Get current ticket limits (with cache)
        ticket_config = get_ticket_config()
        
        for tier, config in ticket_config.items():
            tier_doc = db.tickets_categories.find_one({"tier": tier})
            if not tier_doc:
                # Initialize missing tier
                db.tickets_categories.insert_one({
                    "tier": tier,
                    "count": 0,
                    "created_at": datetime.now(pytz.utc)
                })
                sold = 0
            else:
                sold = int(tier_doc.get("count", 0))
            
            stats[tier] = {
                "name": config["name"],
                "price": config["price"],
                "limit": config["limit"],
                "sold": sold,
                "available": sold < config["limit"],
                "remaining": max(0, config["limit"] - sold)
            }
    except Exception as e:
        logger.error(f"Error getting tier stats: {e}")
        # Return default stats
        ticket_config = get_ticket_config()
        for tier, config in ticket_config.items():
            stats[tier] = {
                "name": config["name"],
                "price": config["price"],
                "limit": config["limit"],
                "sold": 0,
                "available": True,
                "remaining": config["limit"]
            }
    
    return stats

# Routes
@router.post("/admin/update-limits")
@limiter.limit("10/hour")
async def update_ticket_limits(
    request: Request,
    secret_key: str = Header(..., alias="X-Admin-Secret"),
    lpu_limit: int = None,
    external_limit: int = None,
    professional_limit: int = None
):
    """
    Update ticket limits for all tiers (admin only)
    Requires admin secret key in header
    """
    try:
        if secret_key != ADMIN_SECRET_KEY:
            logger.warning(f"Invalid admin secret key in /admin/update-limits from {request.client.host}")
            raise HTTPException(status_code=403, detail="Invalid secret key")
        
        # Validate inputs
        if (lpu_limit is None or lpu_limit <= 0) and \
           (external_limit is None or external_limit <= 0) and \
           (professional_limit is None or professional_limit <= 0):
            raise HTTPException(status_code=400, detail="At least one valid limit must be provided")
        
        # Get current config
        new_config = TICKET_CONFIG.copy()
        
        # Update limits
        if lpu_limit and lpu_limit > 0:
            new_config["lpu"]["limit"] = lpu_limit
        if external_limit and external_limit > 0:
            new_config["external"]["limit"] = external_limit
        if professional_limit and professional_limit > 0:
            new_config["professional"]["limit"] = professional_limit
        
        # Save to database
        db.ticket_limits.update_one(
            {"_id": "global"},
            {
                "$set": {
                    "tiers": new_config,
                    "updated_at": datetime.now(pytz.utc)
                }
            },
            upsert=True
        )
        
        # Reload config
        load_ticket_config()
        
        logger.info(f"✅ Ticket limits updated by admin: {get_ticket_config()}")
        
        return {
            "status": "success",
            "message": "Ticket limits updated successfully",
            "limits": get_ticket_config()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating ticket limits: {e}")
        raise HTTPException(status_code=500, detail="Failed to update limits")

@router.get("/admin/current-limits")
@limiter.limit("60/minute")
async def get_current_limits(
    request: Request,
    secret_key: str = Header(..., alias="X-Admin-Secret")
):
    """
    Get current ticket limits configuration (admin only)
    """
    try:
        if secret_key != ADMIN_SECRET_KEY:
            logger.warning(f"Invalid admin secret key in /admin/current-limits from {request.client.host}")
            raise HTTPException(status_code=403, detail="Invalid secret key")
        
        return {
            "status": "success",
            "limits": get_ticket_config(),
            "updated_at": db.ticket_limits.find_one({"_id": "global"}, {"updated_at": 1}).get("updated_at").isoformat()
            if db.ticket_limits.find_one({"_id": "global"}) else None
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching ticket limits: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch limits")

@router.post("/admin/reset-limits")
@limiter.limit("5/hour")
async def reset_limits_to_default(
    request: Request,
    secret_key: str = Header(..., alias="X-Admin-Secret")
):
    """
    Reset ticket limits to default values (admin only)
    """
    try:
        if secret_key != ADMIN_SECRET_KEY:
            logger.warning(f"Invalid admin secret key in /admin/reset-limits from {request.client.host}")
            raise HTTPException(status_code=403, detail="Invalid secret key")
        
        db.ticket_limits.update_one(
            {"_id": "global"},
            {
                "$set": {
                    "tiers": DEFAULT_TICKET_CONFIG.copy(),
                    "updated_at": datetime.now(pytz.utc)
                }
            },
            upsert=True
        )
        
        # Reload config
        load_ticket_config()
        
        logger.info(f"✅ Ticket limits reset to defaults by admin")
        
        return {
            "status": "success",
            "message": "Ticket limits reset to default values",
            "limits": get_ticket_config()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resetting ticket limits: {e}")
        raise HTTPException(status_code=500, detail="Failed to reset limits")

@router.get("/")
@limiter.limit("200/minute")
async def ticket_info(request: Request):
    """Get current ticket information and availability"""
    try:
        config = db.ticket_config.find_one({"_id": "global"})
        if not config:
            logger.warning("Ticket config not found, initializing...")
            init_ticket_system()
            config = db.ticket_config.find_one({"_id": "global"})
        
        tickets_enabled = config.get("enabled", False) if config else False
        
        if not tickets_enabled:
            return {
                "status": "closed",
                "message": "Ticket sales are currently closed",
                "enabled": False,
                "tiers": get_tier_stats()
            }
        
        current_tier = get_current_tier()
        stats = get_tier_stats()
        
        return {
            "status": "open" if current_tier not in ["closed", "sold_out"] else current_tier,
            "enabled": True,
            "current_tier": current_tier,
            "tiers": stats,
            "message": "Tickets are available" if current_tier not in ["closed", "sold_out"] else "All tickets sold out"
        }
    except Exception as e:
        logger.error(f"Error in ticket_info: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch ticket information")

@router.post("/toggle")
@limiter.limit("20/hour")
async def toggle_tickets(request: Request, data: TicketToggleRequest):
    """
    Toggle ticket sales on/off (master switch)
    Requires admin secret key
    """
    try:
        if data.secret_key != ADMIN_SECRET_KEY:
            logger.warning(f"Invalid admin secret key attempt from {request.client.host}")
            raise HTTPException(status_code=403, detail="Invalid secret key")
        
        # Update or create global config
        result = db.ticket_config.update_one(
            {"_id": "global"},
            {"$set": {"enabled": data.enabled, "updated_at": datetime.now(pytz.utc)}},
            upsert=True
        )
        
        status = "enabled" if data.enabled else "disabled"
        logger.info(f"✅ Ticket sales {status} by admin")
        
        return {
            "status": "success",
            "message": f"Ticket sales {status}",
            "enabled": data.enabled,
            "updated_at": datetime.now(pytz.utc).isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error toggling tickets: {e}")
        raise HTTPException(status_code=500, detail="Failed to toggle ticket sales")

@router.get("/status")
@limiter.limit("100/minute")
async def ticket_status(request: Request, user_data: dict = Depends(verify_token)):
    """
    Check ticket status for authenticated user
    Requires JWT token
    """
    try:
        email = user_data.get("email")
        if not email:
            logger.warning("Email not found in token")
            raise HTTPException(status_code=400, detail="Email not found in token")
        
        email = email.lower().strip()
        
        # Check if user already has a ticket
        ticket = db.tickets.find_one({"email": email, "status": "PAID"})
        
        if ticket:
            return {
                "status": "has_ticket",
                "message": "User already has a ticket",
                "ticket": {
                    "tier": ticket.get("tier"),
                    "tier_name": ticket.get("tier_name"),
                    "amount": ticket.get("amount"),
                    "payment_id": ticket.get("payment_id"),
                    "created_at": ticket.get("created_at").isoformat() if ticket.get("created_at") else None
                }
            }
        else:
            # Get current ticket availability
            config = db.ticket_config.find_one({"_id": "global"})
            tickets_enabled = config.get("enabled", False) if config else False
            
            if not tickets_enabled:
                return {
                    "status": "no_ticket",
                    "message": "Ticket sales are currently closed",
                    "can_purchase": False
                }
            
            current_tier = get_current_tier()
            available = check_availability(current_tier)
            
            return {
                "status": "no_ticket",
                "message": "No ticket found",
                "can_purchase": available and current_tier not in ["closed", "sold_out"],
                "current_tier": current_tier if current_tier not in ["closed", "sold_out"] else None,
                "price": get_ticket_price(current_tier) if current_tier not in ["closed", "sold_out"] else None
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error checking ticket status: {e}")
        raise HTTPException(status_code=500, detail="Failed to check ticket status")

@router.post("/check")
@limiter.limit("300/minute")
async def check_ticket(request: Request, data: TicketCheckRequest):
    """
    Check ticket status for any user by email
    Secured with secret key for frontend polling
    """
    try:
        if data.secret_key != ADMIN_SECRET_KEY:
            logger.warning(f"Invalid secret key attempt in /check from {request.client.host}")
            raise HTTPException(status_code=403, detail="Invalid secret key")
        
        email = data.email.lower().strip()
        
        if not email:
            raise HTTPException(status_code=400, detail="Email is required")
        
        ticket = db.tickets.find_one({"email": email, "status": "PAID"})
        
        if ticket:
            return {
                "status": "has_ticket",
                "message": "User has a valid ticket",
                "ticket": {
                    "email": ticket.get("email"),
                    "tier": ticket.get("tier"),
                    "tier_name": ticket.get("tier_name"),
                    "amount": ticket.get("amount"),
                    "payment_id": ticket.get("payment_id"),
                    "payment_method": ticket.get("payment_method"),
                    "created_at": ticket.get("created_at").isoformat() if ticket.get("created_at") else None
                }
            }
        else:
            return {
                "status": "no_ticket",
                "message": "No ticket found for this email"
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error checking ticket by email: {e}")
        raise HTTPException(status_code=500, detail="Failed to check ticket")

@router.post("/webhook/razorpay")
async def razorpay_webhook(request: Request):
    """
    Razorpay webhook endpoint for payment verification
    Verifies signature and creates ticket on successful payment
    Production-grade with comprehensive error handling
    """
    try:
        # Get webhook signature
        webhook_signature = request.headers.get('X-Razorpay-Signature')
        if not webhook_signature:
            logger.warning("Webhook called without signature")
            raise HTTPException(status_code=401, detail="No signature provided")
        
        # Get request body
        body = await request.body()
        message = body.decode('utf-8')
        
        # Verify signature
        expected_signature = hmac.new(
            RAZORPAY_WEBHOOK_SECRET.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(expected_signature, webhook_signature):
            logger.error(f"❌ Signature mismatch - Expected: {expected_signature}, Received: {webhook_signature}")
            raise HTTPException(status_code=401, detail="Invalid signature")
        
        logger.info("✅ Razorpay webhook signature verified")
        
        # Parse JSON data
        data = await request.json()
        event = data.get("event")
        
        if not event:
            logger.warning("Webhook received without event type")
            return {"status": "error", "message": "No event type"}
        
        logger.info(f"📥 Received event: {event}")
        
        if event == "payment.captured":
            payment = data.get("payload", {}).get("payment", {}).get("entity", {})
            
            if not payment:
                logger.error("Payment entity not found in webhook data")
                return {"status": "error", "message": "Invalid payload structure"}
            
            # Check for duplicate event
            webhook_headers = request.headers
            event_id = webhook_headers.get("X-Razorpay-Event-ID")
            if event_id:
                existing_event = db.razorpay_events.find_one({"event_id": event_id})
                if existing_event:
                    logger.info(f"ℹ️ Event {event_id} already processed")
                    return {"status": "ok", "message": "Event already processed"}
                else:
                    try:
                        db.razorpay_events.insert_one({
                            "event_id": event_id,
                            "processed_at": datetime.now(pytz.utc)
                        })
                    except Exception as e:
                        logger.warning(f"Duplicate event insert attempted: {e}")
                        return {"status": "ok", "message": "Event already processed"}
            
            # Extract payment details with validation
            email = payment.get("email")
            if not email:
                email = payment.get("notes", {}).get("email")
            
            if not email:
                logger.error("❌ No email found in payment data")
                return {"status": "error", "message": "Email not found in payment data"}
            
            email = email.lower().strip()
            amount = payment.get("amount", 0) / 100  # Convert paise to rupees
            payment_id = payment.get("id")
            status = payment.get("status", "").upper()
            method = payment.get("method")
            bank = payment.get("bank")
            phone = payment.get("contact")
            
            if not phone:
                phone = payment.get("notes", {}).get("phone")
            
            if not payment_id:
                logger.error("❌ No payment ID in webhook")
                return {"status": "error", "message": "Payment ID missing"}
            
            # Check for duplicate payment
            existing = db.tickets.find_one({"payment_id": payment_id})
            if existing:
                logger.info(f"ℹ️ Payment {payment_id} already recorded")
                return {"status": "ok", "message": "Already processed"}
            
            # Check if user already has a ticket
            user_ticket = db.tickets.find_one({"email": email, "status": "PAID"})
            if user_ticket:
                logger.warning(f"⚠️ User {email} already has a ticket")
                return {"status": "error", "message": "User already has a ticket"}
            
            # Determine ticket tier and price
            tier = get_current_tier()
            if tier in ["closed", "sold_out"]:
                logger.warning(f"⚠️ Tickets not available - Tier: {tier}")
                return {"status": "error", "message": f"Tickets {tier}"}
            
            expected_price = get_ticket_price(tier)
            
            # Verify payment amount
            if status == "CAPTURED" and amount < expected_price:
                logger.warning(f"⚠️ Insufficient payment - Expected: ₹{expected_price}, Got: ₹{amount}")
                # Still create ticket but mark for review
                tier_name = TICKET_CONFIG[tier]["name"] + " (REVIEW)"
            else:
                tier_name = TICKET_CONFIG[tier]["name"]
            
            # Create ticket document
            ticket_doc = {
                "email": email,
                "amount": amount,
                "tier": tier,
                "tier_name": tier_name,
                "status": "PAID" if status == "CAPTURED" else status,
                "payment_id": payment_id,
                "payment_method": method,
                "bank": bank,
                "contact": phone,
                "created_at": datetime.now(pytz.utc),
                "secret_token": secretTokenGenerator(),
                "webhook_event_id": event_id
            }
            
            # Insert ticket with error handling
            try:
                db.tickets.insert_one(ticket_doc)
            except Exception as e:
                logger.error(f"❌ Failed to insert ticket: {e}")
                return {"status": "error", "message": "Failed to create ticket"}
            
            # Update tier count with error handling
            try:
                db.tickets_categories.update_one(
                    {"tier": tier},
                    {
                        "$inc": {"count": 1},
                        "$set": {"last_updated": datetime.now(pytz.utc)}
                    },
                    upsert=True
                )
            except Exception as e:
                logger.error(f"❌ Failed to update tier count: {e}")
                # Ticket is created, just log the error
            
            logger.info(f"🎟️ Ticket created - Email: {email} | Tier: {tier} | Amount: ₹{amount}")
            
            return {"status": "ok", "message": "Payment verified and ticket created", "tier": tier}
        
        else:
            logger.info(f"ℹ️ Ignored event: {event}")
            return {"status": "ignored", "message": f"Ignored event: {event}"}
    
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"❌ Error processing webhook: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/admin/stats")
@limiter.limit("60/minute")
async def admin_stats(request: Request, secret_key: str = Header(..., alias="X-Admin-Secret")):
    """
    Get detailed ticket statistics (admin only)
    Requires admin secret key in header
    Production-grade with error handling
    """
    try:
        if secret_key != ADMIN_SECRET_KEY:
            logger.warning(f"Invalid admin secret key attempt from {request.client.host}")
            raise HTTPException(status_code=403, detail="Invalid secret key")
        
        config = db.ticket_config.find_one({"_id": "global"})
        if not config:
            logger.warning("Ticket config not found, initializing...")
            init_ticket_system()
            config = db.ticket_config.find_one({"_id": "global"})
        
        tickets_enabled = config.get("enabled", False) if config else False
        
        stats = get_tier_stats()
        
        # Get total revenue and tickets
        total_revenue = 0
        total_tickets = 0
        for tier_name, tier_data in stats.items():
            total_revenue += tier_data["sold"] * tier_data["price"]
            total_tickets += tier_data["sold"]
        
        # Get recent tickets with error handling
        try:
            recent_tickets = list(db.tickets.find(
                {"status": "PAID"},
                {"email": 1, "tier": 1, "tier_name": 1, "amount": 1, "payment_method": 1, "created_at": 1, "_id": 0}
            ).sort("created_at", -1).limit(10))
            
            for ticket in recent_tickets:
                if ticket.get("created_at"):
                    ticket["created_at"] = ticket["created_at"].isoformat()
        except Exception as e:
            logger.error(f"Error fetching recent tickets: {e}")
            recent_tickets = []
        
        # Get additional stats
        try:
            total_payments = db.tickets.count_documents({"status": "PAID"})
            pending_payments = db.tickets.count_documents({"status": {"$ne": "PAID"}})
        except Exception as e:
            logger.error(f"Error counting tickets: {e}")
            total_payments = total_tickets
            pending_payments = 0
        
        return {
            "status": "success",
            "enabled": tickets_enabled,
            "tiers": stats,
            "summary": {
                "total_tickets_sold": total_tickets,
                "total_payments": total_payments,
                "pending_payments": pending_payments,
                "total_revenue": total_revenue,
                "tickets_remaining": sum(t["remaining"] for t in stats.values())
            },
            "recent_tickets": recent_tickets,
            "timestamp": datetime.now(pytz.utc).isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in admin_stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch statistics")
