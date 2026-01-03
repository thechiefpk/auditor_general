# SecureSoft Compliance & Security Auditor - Engineering Design Document

**Date:** 2025-12-21  
**Version:** 1.0  
**Project:** SecureSoft Compliance Auditor (SSA)

---

## 1. Executive Summary

SecureSoft Compliance Auditor is a comprehensive security auditing platform designed to scan local directories and Git repositories for compliance violations (GDPR, HIPAA, Security Best Practices). It features a modern **Next.js** frontend and a robust **ASP.NET Core** backend, utilizing **Hangfire** for background job processing and **SQL Server** for persistence.

---

## 2. System Architecture Overview

The system follows a decoupled Client-Server architecture.

```mermaid
graph TD
    User[User / Browser] -->|HTTPS/JSON| FE[Frontend: Next.js App]
    FE -->|REST API| BE[Backend: ASP.NET Core Web API]
    
    subgraph "Backend Infrastructure"
        BE -->|Dependency Injection| Services[Services Layer]
        Services -->|Job Enqueue| HF[Hangfire Server]
        Services -->|CRUD| DB[(SQL Server)]
        HF -->|Async Execution| ScanEngine[Scan Logic / Validation Engine]
        ScanEngine -->|Updates| DB
        ScanEngine -->|Docker CLI| Privado[Privado Scanner (Docker)]
    end
```

### Key Technologies
*   **Frontend**: Next.js 14+ (App Router), TypeScript, Tailwind CSS, React Context API.
*   **Backend**: .NET 8 (ASP.NET Core Web API), C#.
*   **Database**: Microsoft SQL Server.
*   **Background Jobs**: Hangfire (running in-process with the API).
*   **External Tools**: Docker (for advanced Privado scanning), Git CLI.

---

## 3. User Journey & Workflows

### 3.1. Authentication Flow
1.  **Visitor** lands on `/home` or `/login`.
2.  **Login/Signup**: User submits credentials.
3.  **Backend**: Validates against `Users` table (hashed passwords). Generates a **JWT** (JSON Web Token).
4.  **Frontend**: Stores JWT in HTTP-only cookies (via `js-cookie`) and updates `AuthContext` state.
5.  **Redirect**: User is moved to `/dashboard`.

### 3.2. Scan Workflow
1.  **Initiation**: User navigates to `/dashboard/scan`.
    *   Selects **Local** or **Git** scan.
    *   Enters Path/URL.
    *   Toggles "Advanced Scan" (requires Docker).
2.  **Submission**:
    *   Frontend sends `POST /api/scan/local` or `POST /api/scan/git`.
    *   Backend enqueues a job via `BackgroundJob.Enqueue<ScanJobService>(...)`.
    *   Backend returns a `jobId` immediately.
3.  **Polling (Real-time Feedback)**:
    *   Frontend enters a polling loop (`setInterval` every 1s) calling `GET /api/scan/progress/{jobId}`.
    *   Backend `GetProgress` reads from the `ScanProgress` table.
4.  **Completion**:
    *   Job finishes, updates status to "Completed".
    *   Frontend detects completion, stops polling, and displays a summary or redirects to the report.

### 3.3. Reporting & Statistics
*   **Reports**: Lists historical scans from the `Reports` table.
*   **Statistics**: Aggregates violation data (Category, Severity, Top Files) using SQL `GROUP BY` queries.

---

## 4. Frontend Architecture

The frontend is built with **Next.js (App Router)**, emphasizing server-side rendering where possible and client-side interactivity where needed (`'use client'`).

### 4.1. Directory Structure (`frontend/app/`)
*   **`context/AuthContext.tsx`**: The core of state management.
    *   **Role**: Manages `user` object (token, username) and `isLoading` state.
    *   **Logic**: Checks for cookies on mount. Provides `login`, `signup`, `logout` methods to the entire app via `useAuth()`.
*   **`dashboard/layout.tsx`**:
    *   **Role**: Protected route wrapper.
    *   **Logic**: Checks `!isLoading && !user` to redirect unauthenticated users to `/login`.
    *   **Docker Check**: Automatically polls the backend to see if Docker is running for advanced features.
*   **`lib/api.ts`**:
    *   **Role**: Centralized API configuration.
    *   **Features**: Defines `API_BASE_URL` (configurable via ENV), endpoint constants, and a wrapper `apiRequest` function for standardized error handling.

### 4.2. Key Components
*   **`ScanPage` (`dashboard/scan/page.tsx`)**:
    *   Complex state management for Form inputs (Path, Git URL) and Progress visualization (Progress Bar, Stage Text).
    *   Handles the transition from "Input Mode" -> "Scanning Mode" -> "Results Mode".
*   **`ReportsPage` (`dashboard/reports/page.tsx`)**:
    *   Fetches list of reports.
    *   Provides links to detailed views (`/dashboard/reports/[id]`).

---

## 5. Backend Architecture

The backend is a monolithic **ASP.NET Core Web API** following a layered architecture (Controller -> Service -> Repository).

### 5.1. Directory Structure (`backend/ComplianceSecurityAuditor/`)
*   **`Controllers/`**: Entry points (API Endpoints).
    *   `ScanController`: Handles scan requests, progress checks, and report retrieval.
    *   `AuthController`: Handles Login/Register.
    *   `SystemController`: Manages system-level checks (Docker status).
*   **`Services/`**: Business Logic.
    *   `ScanJobService`: The **Hangfire** job runner. Orchestrates the scanning process (Clone -> Compliance Scan -> Privado Scan -> Save).
    *   `ComplianceService`: Facade for report and statistic retrieval.
    *   `AuthService`: JWT generation logic.
*   **`Data/`**: Data Access Layer (DAL).
    *   `SqlReportRepository`: Direct ADO.NET (`SqlConnection`, `SqlCommand`) for high-performance data operations on Reports/Violations.
    *   `SqlAuthRepository`: User management.
*   **`Library/`**: Core utilities.
    *   `ValidationEngine`: Regex-based scanning logic.
    *   `RuleRegistry`: Definitions of security rules (GDPR, AWS keys, etc.).

### 5.2. Detailed Codeblock Flows

#### A. The Scan Engine (`ScanJobService.cs` + `ValidationEngine.cs`)
1.  **Job Start**: `RunGitScan` or `RunLocalScan` is triggered by Hangfire.
2.  **Progress Tracking**:
    *   Calls `_progressRepo.UpdateAsync(...)` to update the SQL database with the current stage (e.g., "Cloning", "Scanning").
3.  **Git Operations**:
    *   Uses `System.Diagnostics.Process` to run `git clone` commands securely.
    *   Injects Access Tokens into the URL for private repos if provided.
4.  **File Scanning**:
    *   Iterates through files (ignoring `.git`, `node_modules`).
    *   Matches file content against `RuleRegistry` patterns.
5.  **Advanced Scan (Privado)**:
    *   If enabled, runs a Docker container (`privado/scan`) against the target directory.
    *   Parses the JSON output and merges it with local violations.
6.  **Persistence**:
    *   Calls `_repo.SaveReportAsync` to wrap everything in a transaction and save to `Reports` and `Violations` tables.

#### B. Authentication (`Program.cs` + `AuthService.cs`)
*   **Setup**: JWT Authentication is configured in `Program.cs` using `AddJwtBearer`.
*   **Token Generation**: `AuthService` creates tokens signed with a symmetric key (`JWT_SECRET`). Tokens contain claims for `UserId` and `Username`.
*   **Protection**: Controllers use `GetCurrentUserId()` which extracts the `NameIdentifier` claim to ensure users can only access their own data.

### 5.3. Database Schema
*   **`Users`**: `Id` (Guid), `Username`, `PasswordHash`, `Email`.
*   **`Reports`**: `Id`, `UserId` (FK), `Path`, `FilesScanned`, `ViolationsFound`, `CreatedAt`.
*   **`Violations`**: `Id`, `ReportId` (FK), `FilePath`, `LineNumber`, `MatchedText`, `RuleId`, `Category`, `Severity`.
*   **`ScanProgress`**: `JobId` (PK), `UserId`, `Status`, `Stage`, `Percentage`, `UpdatedAt`.

---

## 6. Technical Deliverables & Configuration

### Frontend Config (`frontend/.env.local`)
```env
NEXT_PUBLIC_API_BASE_URL=http://localhost:5059
```

### Backend Config (`backend/.../appsettings.json`)
```json
{
  "SQL_SERVER_CONNECTION": "Server=...;Database=SecureSoft;...",
  "JWT_SECRET": "YourSuperSecretKey...",
  "AllowedHosts": "*"
}
```

### Build & Run
1.  **Backend**: `dotnet run` (Listens on ports 5059/7120).
2.  **Frontend**: `npm run dev` (Runs on port 3000).

---

## 7. Future Considerations
*   **Queue Separation**: Move Hangfire to a separate worker service for scalability.
*   **Real-time Sockets**: Replace HTTP polling with SignalR for scan progress.
*   **Cloud Storage**: Move report storage from SQL to Blob Storage (S3/Azure Blob) for large scale.
