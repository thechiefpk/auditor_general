# Fix SSL Certificate Error for localhost:7120

## The Problem
Your C# backend runs on **https://localhost:7120** with a self-signed certificate. Browsers block self-signed certificates by default, causing "ERR_EMPTY_RESPONSE" or "Failed to fetch" errors.

## Solution: Trust the Certificate in Your Browser

### Method 1: Quick Fix - Visit Backend URL Directly

1. **Open a new browser tab**
2. **Navigate to**: `https://localhost:7120/api/auth/login`
3. You'll see a **security warning** (e.g., "Your connection is not private")
4. Click **"Advanced"** → **"Proceed to localhost (unsafe)"**
5. **Return to your Next.js app** and try logging in again

### Method 2: Trust Certificate in Windows (Permanent Fix)

#### For Chrome/Edge:
1. Visit `https://localhost:7120` in browser
2. Click the **padlock icon** → **"Connection is not secure"**
3. Click **"Certificate is not valid"**
4. Go to **"Details"** tab → Click **"Copy to File"**
5. Save certificate as `.cer` file
6. Double-click the `.cer` file
7. Click **"Install Certificate"**
8. Choose **"Local Machine"** → Next
9. Select **"Place all certificates in the following store"**
10. Click **"Browse"** → Select **"Trusted Root Certification Authorities"**
11. Click OK → Next → Finish
12. **Restart browser**

#### For Firefox:
1. Visit `https://localhost:7120`
2. Click **"Advanced"** → **"Accept the Risk and Continue"**
3. Firefox will remember this exception

### Method 3: Run Backend Without SSL (Development Only)

Edit your C# project's `Properties/launchSettings.json`:

```json
{
  "profiles": {
    "YourProjectName": {
      "commandName": "Project",
      "launchBrowser": true,
      "applicationUrl": "http://localhost:7120",  // Changed from https
      "environmentVariables": {
        "ASPNETCORE_ENVIRONMENT": "Development"
      }
    }
  }
}
```

Then update Next.js `.env.local`:
```
NEXT_PUBLIC_API_BASE_URL=http://localhost:7120
```

**Restart both servers** after making changes.

---

## Verify Backend CORS Configuration

Make sure your C# `Program.cs` has CORS enabled:

```csharp
// Add this BEFORE builder.Build()
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowLocalhost", policy =>
    {
        policy.WithOrigins("http://localhost:3000", "https://localhost:3000")
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials();
    });
});

var app = builder.Build();

// Add this AFTER app is built, BEFORE app.MapControllers()
app.UseCors("AllowLocalhost");
```

---

## Current Configuration
- **Backend**: https://localhost:7120 (with SSL)
- **Frontend**: http://localhost:3000
- **Issue**: Browser blocks self-signed SSL certificate

## Quick Test
Run this in browser console to test if certificate is trusted:
```javascript
fetch('https://localhost:7120/api/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: 'Admin', password: 'your-password' })
})
.then(r => r.json())
.then(console.log)
.catch(console.error)
```

If you see certificate errors, follow Method 1 above.
