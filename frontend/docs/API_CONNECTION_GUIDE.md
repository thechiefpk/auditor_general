# API Connection Issues & Solutions

## Common Issues

### 1. SSL Certificate Error (HTTPS Localhost)

**Problem:** Browser blocks `https://localhost:7120` due to self-signed certificate.

**Solutions:**

#### Option A: Trust the SSL Certificate (Recommended for Development)
1. Open Chrome/Edge and navigate to `https://localhost:7120`
2. Click "Advanced" on the security warning
3. Click "Proceed to localhost (unsafe)"
4. This allows the certificate for this session

#### Option B: Change Backend to HTTP (Quick Fix)
Update `.env.local`:
```
NEXT_PUBLIC_API_BASE_URL=http://localhost:7120
```

And update your C# backend to use HTTP instead of HTTPS in development.

#### Option C: Install Certificate (Permanent Solution)
For Windows with ASP.NET Core:
```powershell
dotnet dev-certs https --trust
```

### 2. CORS Issues

If you see CORS errors, add this to your C# backend `Program.cs`:

```csharp
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowLocalhost",
        policy =>
        {
            policy.WithOrigins("http://localhost:3000")
                  .AllowAnyHeader()
                  .AllowAnyMethod()
                  .AllowCredentials();
        });
});

// After var app = builder.Build();
app.UseCors("AllowLocalhost");
```

### 3. Infinite Loader Issue

**Causes:**
- API server not running
- SSL certificate blocking requests
- Network/firewall blocking localhost connections
- CORS policy blocking requests

**Debug Steps:**
1. Check browser console (F12) for errors
2. Verify backend is running: `https://localhost:7120/api/scan`
3. Check Network tab to see if request is being made
4. Look for detailed error messages in toast notifications

### 4. Environment Variables

Make sure `.env.local` exists with:
```
NEXT_PUBLIC_API_BASE_URL=https://localhost:7120
```

Restart Next.js dev server after changing env variables:
```bash
# Stop the server (Ctrl+C)
npm run dev
```

## Testing API Connection

### Test from Browser Console
```javascript
fetch('https://localhost:7120/api/scan', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ path: 'C:\\test' })
})
.then(r => r.json())
.then(console.log)
.catch(console.error);
```

### Test Backend is Running
Open browser to: `https://localhost:7120/swagger` (if Swagger is enabled)

## Current Implementation

The scan page now includes:
- ✅ Detailed console logging for debugging
- ✅ Better error messages
- ✅ Proper try-catch-finally for loader state
- ✅ CORS mode enabled
- ✅ Network error detection

Check the browser console during scan to see detailed logs.
