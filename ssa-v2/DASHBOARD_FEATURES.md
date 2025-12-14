# Dashboard Features Documentation

## Overview
The SecureAudit dashboard provides a comprehensive security compliance scanning platform with rich UI/UX features.

## Features

### 🏠 Dashboard Home
- **Overview Statistics**: Total scans, active scans, violations, and critical issues
- **Quick Actions**: Fast access to scan, reports, and statistics
- **Recent Activity**: View recent scan activity

### 🔍 Security Scanner
- **Path Input**: Scan any directory or file path
- **Real-time Progress**: Visual feedback during scanning
- **Instant Results**: 
  - Total files scanned
  - Total violations found
  - Scan duration
  - Violations by category
  - Detailed violation table with severity indicators

### 📄 Reports
- **Advanced Filtering**:
  - Search by scan ID
  - Filter by category
  - Full-text search across violations
- **Sorting**: Sort by file path, line number, or rule name
- **Pagination**: Customizable page size (10, 25, 50, 100)
- **Rich Violation Display**:
  - File path and line number
  - Rule name and category
  - Severity badges (Critical, High, Medium, Low, Info)
  - Detailed violation messages

### 📈 Statistics
- **Visual Analytics**:
  - Total violations overview
  - Files scanned metrics
  - Scan duration tracking
  - Category distribution
- **Progress Bars**: 
  - Violations by severity with percentages
  - Violations by category with color-coded bars
- **Summary Table**: Detailed metrics including averages

## API Endpoints

All API endpoints are configured in `app/lib/api.ts`:

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration

### Scanning
- `POST /api/scan` - Start a new scan
- `GET /api/report/{id}` - Get scan report
- `GET /api/stats/{id}` - Get scan statistics
- `GET /api/report/{id}/violations` - Get paginated violations

## Navigation

The dashboard uses a collapsible sidebar with:
- 📊 Dashboard (Overview)
- 🔍 New Scan
- 📄 Reports
- 📈 Statistics
- 🚪 Logout

## Technology Stack

- **Framework**: Next.js 14+ with App Router
- **Styling**: Tailwind CSS with dark mode support
- **Notifications**: React Hot Toast
- **Authentication**: JWT with cookie storage
- **API Integration**: Centralized configuration

## Usage

1. **Login/Signup**: Use username/email and password
2. **Start a Scan**: Navigate to "New Scan" and enter a directory path
3. **View Results**: See instant results with violations breakdown
4. **Browse Reports**: Filter and search violations by scan ID
5. **Analyze Statistics**: View detailed analytics and trends

## Color Coding

### Severity Levels
- 🔴 **Critical**: Red
- 🟠 **High**: Orange
- 🟡 **Medium**: Yellow
- 🔵 **Low**: Blue
- ⚪ **Info**: Gray

## Dark Mode
Full dark mode support across all pages with automatic theme detection.
