# Ticket System API Documentation

## Overview
FastAPI-based ticket system with three pricing tiers, Razorpay webhook integration, master toggle control, and **dynamic configurable ticket limits**.

## Ticket Tiers

| Tier | Default Price | Default Limit | Description |
|------|-------|-------|-------------|
| **lpu** | ₹200 | 200 tickets | LPU Student |
| **external** | ₹300 | 300 tickets | External Student |
| **professional** | ₹500 | 100 tickets | Professional |

**Note:** Limits are fully configurable via admin endpoints and stored in MongoDB. They update in real-time with 5-minute cache for performance.

## Key Features

- **Dynamic Configuration**: Change ticket limits anytime without restarting
- **Rate Limiting**: Production-appropriate limits on all routes
- **CORS Policy**: Enabled for all origins (configurable in production)
- **Comprehensive Logging**: All operations logged for debugging
- **Database Caching**: 5-minute cache with auto-reload
- **Error Handling**: Graceful fallbacks for missing documents
- **Idempotency**: Prevents duplicate webhook processing
- **Security**: Secret key validation, input sanitization

## Authentication
Most endpoints require JWT token in the Authorization header:
```
Authorization: Bearer <your_jwt_token>
```

Admin endpoints require secret key either in request body or header.

---

## API Endpoints

### 1. Get Ticket Information
**Endpoint:** `GET /ticket/`

**Description:** Get current ticket availability and tier information

**Authentication:** None

**Response:**
```json
{
  "status": "open",
  "enabled": true,
  "current_tier": "lpu",
  "tiers": {
    "lpu": {
      "name": "LPU Student",
      "price": 200,
      "limit": 200,
      "sold": 45,
      "available": true
    },
    "external": {
      "name": "External Student",
      "price": 300,
      "limit": 300,
      "sold": 0,
      "available": true
    },
    "professional": {
      "name": "Professional",
      "price": 500,
      "limit": 100,
      "sold": 0,
      "available": true
    }
  },
  "message": "Tickets are available"
}
```

---

### 2. Toggle Ticket Sales (Master Switch)
**Endpoint:** `POST /ticket/toggle`

**Description:** Enable or disable all ticket sales

**Authentication:** Admin Secret Key

**Request Body:**
```json
{
  "secret_key": "AdminSecret123",
  "enabled": true
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Ticket sales enabled",
  "enabled": true
}
```

---

### 3. Check User Ticket Status
**Endpoint:** `GET /ticket/status`

**Description:** Check if the authenticated user has a ticket

**Authentication:** JWT Token (Bearer)

**Response (Has Ticket):**
```json
{
  "status": "has_ticket",
  "message": "User already has a ticket",
  "ticket": {
    "tier": "lpu",
    "amount": 200,
    "payment_id": "pay_xxxxxxxxxxxxx",
    "created_at": "2026-01-15T10:30:00Z"
  }
}
```

**Response (No Ticket):**
```json
{
  "status": "no_ticket",
  "message": "No ticket found",
  "can_purchase": true,
  "current_tier": "lpu",
  "price": 200
}
```

---

### 4. Check Ticket by Email (Frontend Poll)
**Endpoint:** `POST /ticket/check`

**Description:** Check ticket status for any user by email (secured for frontend polling)

**Authentication:** Admin Secret Key

**Request Body:**
```json
{
  "email": "user@example.com",
  "secret_key": "AdminSecret123"
}
```

**Response:**
```json
{
  "status": "has_ticket",
  "message": "User has a valid ticket",
  "ticket": {
    "email": "user@example.com",
    "tier": "lpu",
    "amount": 200,
    "payment_id": "pay_xxxxxxxxxxxxx",
    "payment_method": "upi",
    "created_at": "2026-01-15T10:30:00Z"
  }
}
```

---

### 5. Razorpay Webhook
**Endpoint:** `POST /ticket/webhook/razorpay`

**Description:** Webhook endpoint for Razorpay payment verification

**Authentication:** Razorpay Signature (X-Razorpay-Signature header)

**Request:** Razorpay webhook payload

**Response:**
```json
{
  "status": "ok",
  "message": "Payment verified and ticket created"
}
```

**Features:**
- Verifies HMAC signature
- Prevents duplicate processing
- Creates ticket on successful payment
- Validates payment amount
- Updates tier counts automatically

---

### 7. Update Ticket Limits (Dynamic Configuration)
**Endpoint:** `POST /ticket/admin/update-limits`

**Description:** Update ticket limits for specific tiers (admin only)

**Authentication:** Admin Secret Key (X-Admin-Secret header)

**Query Parameters:**
- `lpu_limit` (integer, optional) - New limit for LPU tier
- `external_limit` (integer, optional) - New limit for External tier
- `professional_limit` (integer, optional) - New limit for Professional tier

**Headers:**
```
X-Admin-Secret: AdminSecret123
```

**Response:**
```json
{
  "status": "success",
  "message": "Ticket limits updated successfully",
  "limits": {
    "lpu": {
      "price": 200,
      "limit": 250,
      "name": "LPU Student"
    },
    "external": {
      "price": 300,
      "limit": 400,
      "name": "External Student"
    },
    "professional": {
      "price": 500,
      "limit": 100,
      "name": "Professional"
    }
  }
}
```

---

### 8. Get Current Limits
**Endpoint:** `GET /ticket/admin/current-limits`

**Description:** Get current ticket limits configuration

**Authentication:** Admin Secret Key (X-Admin-Secret header)

**Headers:**
```
X-Admin-Secret: AdminSecret123
```

**Response:**
```json
{
  "status": "success",
  "limits": {
    "lpu": {
      "price": 200,
      "limit": 250,
      "name": "LPU Student"
    },
    "external": {
      "price": 300,
      "limit": 400,
      "name": "External Student"
    },
    "professional": {
      "price": 500,
      "limit": 100,
      "name": "Professional"
    }
  },
  "updated_at": "2026-01-15T10:30:00Z"
}
```

---

### 9. Reset Limits to Defaults
**Endpoint:** `POST /ticket/admin/reset-limits`

**Description:** Reset all ticket limits to default values

**Authentication:** Admin Secret Key (X-Admin-Secret header)

**Headers:**
```
X-Admin-Secret: AdminSecret123
```

**Response:**
```json
{
  "status": "success",
  "message": "Ticket limits reset to default values",
  "limits": {
    "lpu": {
      "price": 200,
      "limit": 200,
      "name": "LPU Student"
    },
    "external": {
      "price": 300,
      "limit": 300,
      "name": "External Student"
    },
    "professional": {
      "price": 500,
      "limit": 100,
      "name": "Professional"
    }
  }
}
```

---

### 6. Admin Statistics
**Endpoint:** `GET /ticket/admin/stats`

**Description:** Get detailed ticket statistics

**Authentication:** Admin Secret Key (X-Admin-Secret header)

**Headers:**
```
X-Admin-Secret: AdminSecret123
```

**Response:**
```json
{
  "status": "success",
  "enabled": true,
  "tiers": {
    "lpu": {
      "name": "LPU Student",
      "price": 200,
      "limit": 200,
      "sold": 45,
      "available": true
    },
    "external": {
      "name": "External Student",
      "price": 300,
      "limit": 300,
      "sold": 120,
      "available": true
    },
    "professional": {
      "name": "Professional",
      "price": 500,
      "limit": 100,
      "sold": 30,
      "available": true
    }
  },
  "summary": {
    "total_tickets_sold": 195,
    "total_payments": 195,
    "pending_payments": 0,
    "total_revenue": 60000,
    "tickets_remaining": 555
  },
  "recent_tickets": [
    {
      "email": "user@example.com",
      "tier": "lpu",
      "tier_name": "LPU Student",
      "amount": 200,
      "payment_method": "upi",
      "created_at": "2026-01-15T10:30:00Z"
    }
  ],
  "timestamp": "2026-01-15T10:35:00Z"
}
```

---

## Caching & Performance

### Configuration Caching
- **Cache Duration**: 5 minutes
- **Auto-Reload**: Cache automatically refreshes after expiration
- **Force Reload**: All admin endpoints force immediate reload
- **Real-Time Updates**: Database changes via admin API are applied instantly

### How It Works
1. On first request, ticket configuration is loaded from MongoDB
2. Subsequent requests use cached config for performance
3. Admin updates force immediate config reload
4. After 5 minutes, next request auto-refreshes from database

### Adjusting Cache Duration
Edit `CONFIG_CACHE_TTL` in [Routes/Ticket.py](Routes/Ticket.py#L41):
```python
CONFIG_CACHE_TTL = 300  # Cache for 5 minutes (in seconds)
```

---

## Database Schema

### Collection: `tickets`
```javascript
{
  "_id": ObjectId,
  "email": "user@example.com",
  "amount": 200,
  "tier": "lpu",
  "tier_name": "LPU Student",
  "status": "PAID",
  "payment_id": "pay_xxxxxxxxxxxxx",
  "payment_method": "upi",
  "bank": "HDFC",
  "contact": "+919876543210",
  "created_at": ISODate("2026-01-15T10:30:00Z"),
  "secret_token": "randomSecureToken123",
  "webhook_event_id": "evt_xxxxxxxxxxxxx"
}
```

### Collection: `tickets_categories`
```javascript
{
  "_id": ObjectId,
  "tier": "lpu",
  "count": 45,
  "created_at": ISODate("2026-01-15T10:00:00Z"),
  "last_updated": ISODate("2026-01-15T10:30:00Z")
}
```

### Collection: `ticket_config`
```javascript
{
  "_id": "global",
  "enabled": true,
  "updated_at": ISODate("2026-01-15T10:00:00Z"),
  "created_at": ISODate("2026-01-01T00:00:00Z")
}
```

### Collection: `ticket_limits`
```javascript
{
  "_id": "global",
  "tiers": {
    "lpu": {
      "price": 200,
      "limit": 250,
      "name": "LPU Student"
    },
    "external": {
      "price": 300,
      "limit": 400,
      "name": "External Student"
    },
    "professional": {
      "price": 500,
      "limit": 100,
      "name": "Professional"
    }
  },
  "updated_at": ISODate("2026-01-15T10:30:00Z"),
  "created_at": ISODate("2026-01-01T00:00:00Z")
}
```

### Collection: `razorpay_events`
```javascript
{
  "_id": ObjectId,
  "event_id": "evt_xxxxxxxxxxxxx",
  "processed_at": ISODate("2026-01-15T10:30:00Z")
}
```

---

## Frontend Integration Examples

### 1. Check if User Has Ticket (Authenticated)
```javascript
const checkTicketStatus = async (token) => {
    const res = await fetch('/ticket/status', {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    });
    return await res.json();
};

const data = await checkTicketStatus(userToken);
if (data.status === 'has_ticket') {
    console.log('User has ticket:', data.ticket);
} else if (data.can_purchase) {
    redirectToPayment(data.current_tier, data.price);
}
```

### 2. Poll Ticket Status After Payment
```javascript
const pollForTicket = (email, onSuccess, onFail) => {
    let attempts = 0;
    const maxAttempts = 60; // 5 minutes with 5-second interval
    
    const interval = setInterval(async () => {
        attempts++;
        
        const result = await fetch('/ticket/check', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                email: email,
                secret_key: process.env.REACT_APP_ADMIN_SECRET
            })
        }).then(r => r.json());
        
        if (result.status === 'has_ticket') {
            clearInterval(interval);
            onSuccess(result.ticket);
        } else if (attempts >= maxAttempts) {
            clearInterval(interval);
            onFail('Payment verification timeout');
        }
    }, 5000);
};
```

### 3. Get Ticket Information (Public)
```javascript
const getTicketInfo = async () => {
    const res = await fetch('/ticket/');
    const data = await res.json();
    
    console.log('Current tier:', data.current_tier);
    console.log('Available tiers:', data.tiers);
    return data;
};
```

---

## Rate Limiting

Rate limits are applied per IP address using slowapi:

| Endpoint | Limit | Purpose |
|----------|-------|---------|
| `GET /ticket/` | 200/minute | Public info (high traffic) |
| `POST /ticket/toggle` | 20/hour | Admin control |
| `GET /ticket/status` | 100/minute | User checks frequently |
| `POST /ticket/check` | 300/minute | Frontend polling |
| `POST /ticket/webhook/razorpay` | Unlimited | External service |
| `GET /ticket/admin/stats` | 60/minute | Admin dashboard |
| `POST /ticket/admin/update-limits` | 10/hour | Admin config |
| `GET /ticket/admin/current-limits` | 60/minute | Admin config |
| `POST /ticket/admin/reset-limits` | 5/hour | Admin config |

---

## Error Handling

### Common Error Responses

**Invalid Secret Key:**
```json
{
  "detail": "Invalid secret key"
}
```

**Token Expired:**
```json
{
  "detail": "Token has expired"
}
```

**User Already Has Ticket:**
```json
{
  "status": "error",
  "message": "User already has a ticket"
}
```

**Tickets Closed:**
```json
{
  "status": "closed",
  "message": "Ticket sales are currently closed",
  "enabled": false
}
```

**Rate Limit Exceeded:**
```json
{
  "detail": "rate limit exceeded: 200 per 1 minute"
}
```

---

## Testing with cURL

### Get Ticket Info
```bash
curl -X GET http://localhost:8000/ticket/
```

### Enable Ticket Sales
```bash
curl -X POST http://localhost:8000/ticket/toggle \
  -H "Content-Type: application/json" \
  -d '{"secret_key": "AdminSecret123", "enabled": true}'
```

### Update Ticket Limits
```bash
curl -X POST "http://localhost:8000/ticket/admin/update-limits?lpu_limit=300&external_limit=400&professional_limit=150" \
  -H "X-Admin-Secret: AdminSecret123"
```

### Get Current Limits
```bash
curl -X GET http://localhost:8000/ticket/admin/current-limits \
  -H "X-Admin-Secret: AdminSecret123"
```

### Reset Limits to Defaults
```bash
curl -X POST http://localhost:8000/ticket/admin/reset-limits \
  -H "X-Admin-Secret: AdminSecret123"
```

### Get Admin Statistics
```bash
curl -X GET http://localhost:8000/ticket/admin/stats \
  -H "X-Admin-Secret: AdminSecret123"
```

### Check Ticket Status (Authenticated)
```bash
curl -X GET http://localhost:8000/ticket/status \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Check Ticket by Email
```bash
curl -X POST http://localhost:8000/ticket/check \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "secret_key": "AdminSecret123"}'
```

---

## Environment Variables

Required in `.env` file:

```bash
# MongoDB
MONGO_URI=mongodb://localhost:27017
DB_NAME=rcs_ctf_2026

# JWT
JWT_SECRET=your_jwt_secret_here

# Razorpay
RAZORPAY_WEBHOOK_SECRET=your_razorpay_webhook_secret

# Admin
ADMIN_SECRET_KEY=your_admin_secret_key
```

---

## Security Considerations

1. **Admin Secret Key**: Change `ADMIN_SECRET_KEY` in production
2. **Razorpay Webhook Secret**: Use strong secret from Razorpay dashboard
3. **JWT Secret**: Keep `JWT_SECRET` secure and never commit to git
4. **HTTPS**: Always use HTTPS in production for webhook endpoint
5. **Rate Limiting**: Enabled by default to prevent abuse
6. **Input Validation**: All inputs validated using Pydantic models
7. **Database Indexes**: Unique indexes prevent duplicate payments

---

## Troubleshooting

### Webhook Not Receiving Payments
- Verify `RAZORPAY_WEBHOOK_SECRET` matches Razorpay dashboard
- Ensure webhook URL is publicly accessible (use ngrok for testing)
- Check Razorpay webhook logs in dashboard

### Rate Limit Errors
- Implement exponential backoff in frontend
- Check client IP if using load balancer
- Adjust rate limits in route decorators if needed

### Configuration Not Updating
- Check MongoDB connection
- Verify admin secret key is correct
- Cache expires after 5 minutes; use `/admin/current-limits` to verify

---

## Support

For issues or questions, refer to the main README or check server logs.

