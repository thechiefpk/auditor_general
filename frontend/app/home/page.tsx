'use client';

import Link from 'next/link';
import Image from 'next/image';
import { useAuth } from '../context/AuthContext';
import Header from '../components/Header';
import SecureGlobe from '../components/SecureGlobe';

export default function Home() {
  const { user } = useAuth();

  const CpuChipIcon = () => (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" className="h-8 w-8 text-zinc-100">
      <path d="M16.5 7.5h-9v9h9v-9z" />
      <path fillRule="evenodd" d="M8.25 2.25A.75.75 0 019 3v1.5h2.25V3a.75.75 0 011.5 0v1.5H15V3a.75.75 0 011.5 0v1.5h1.5A2.25 2.25 0 0120.25 6.75v1.5H21a.75.75 0 010 1.5h-.75v2.25H21a.75.75 0 010 1.5h-.75v2.25H21a.75.75 0 010 1.5h-.75v1.5a2.25 2.25 0 01-2.25 2.25h-1.5V21a.75.75 0 01-1.5 0v-.75h-2.25V21a.75.75 0 01-1.5 0v-.75H9V21a.75.75 0 01-1.5 0v-.75h-1.5a2.25 2.25 0 01-2.25-2.25v-1.5H3a.75.75 0 010-1.5h.75v-2.25H3a.75.75 0 010-1.5h.75v-2.25H3a.75.75 0 010-1.5h.75v-1.5A2.25 2.25 0 016 4.5h1.5V3a.75.75 0 01.75-.75zM6 6v12a.75.75 0 00.75.75h10.5A.75.75 0 0018 18V6a.75.75 0 00-.75-.75H6.75A.75.75 0 006 6z" clipRule="evenodd" />
    </svg>
  );
  
  const ChartBarIcon = () => (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" className="h-8 w-8 text-zinc-100">
      <path d="M18.375 2.25c-1.035 0-1.875.84-1.875 1.875v15.75c0 1.035.84 1.875 1.875 1.875h.75c1.035 0 1.875-.84 1.875-1.875V4.125c0-1.036-.84-1.875-1.875-1.875h-.75zM9.75 8.625c0-1.036.84-1.875 1.875-1.875h.75c1.036 0 1.875.84 1.875 1.875v11.25c0 1.035-.84 1.875-1.875 1.875h-.75a1.875 1.875 0 01-1.875-1.875V8.625zM3 13.125c0-1.036.84-1.875 1.875-1.875h.75c1.036 0 1.875.84 1.875 1.875v6.75c0 1.035-.84 1.875-1.875 1.875h-.75A1.875 1.875 0 013 19.875v-6.75z" />
    </svg>
  );

  return (
    <div className="flex min-h-screen flex-col bg-zinc-950">
      <Header />

      <main className="flex-grow">
        {/* Hero Section */}
        <section className="flex flex-col items-center justify-center px-6 pt-24 pb-32 sm:pt-32">
          <div className="mx-auto max-w-4xl text-center">
            
            {/* Secure Globe Interactive Component */}
            <div className="mb-8 flex flex-col items-center justify-center gap-4">
              <div className="relative">
                <SecureGlobe />
              </div>
            </div>

            {/* Hero Title */}
            <h1 className="mb-6 text-5xl font-bold tracking-tight text-white sm:text-6xl lg:text-7xl">
              Secure your codebase with
              <span className="block bg-gradient-to-r from-white to-zinc-400 bg-clip-text text-transparent">
                intelligent compliance scanning
              </span>
            </h1>

            {/* Hero Description */}
            <p className="mx-auto mb-10 max-w-2xl text-lg leading-relaxed text-zinc-400 sm:text-xl">
              SecureSoft automatically detects PII, PHI, and compliance violations across your entire codebase, 
              APIs, and SQL queries—supporting every programming language. Achieve audit-ready security in minutes.
            </p>

            {/* CTA Buttons */}
            <div className="flex flex-col items-center justify-center gap-4 sm:flex-row sm:gap-6">
              {user ? (
                <Link
                  href="/dashboard"
                  className="group inline-flex items-center gap-2 rounded-lg bg-zinc-100 px-8 py-3.5 text-base font-semibold text-black shadow-lg shadow-zinc-500/10 transition-all hover:bg-zinc-200 hover:shadow-xl focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-zinc-500"
                >
                  Go to Dashboard
                  <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={2.5} stroke="currentColor" className="h-5 w-5 transition-transform group-hover:translate-x-1">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
                  </svg>
                </Link>
              ) : (
                <>
                  <Link
                    href="/signup"
                    className="group inline-flex items-center gap-2 rounded-lg bg-zinc-100 px-8 py-3.5 text-base font-semibold text-black shadow-lg shadow-zinc-500/10 transition-all hover:bg-zinc-200 hover:shadow-xl focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-zinc-500"
                  >
                    Start free scan
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={2.5} stroke="currentColor" className="h-5 w-5 transition-transform group-hover:translate-x-1">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
                    </svg>
                  </Link>
                  <Link
                    href="/login"
                    className="group inline-flex items-center gap-2 rounded-lg border border-zinc-700 bg-zinc-800/50 px-8 py-3.5 text-base font-semibold text-white transition-all hover:bg-zinc-800 hover:border-zinc-600"
                  >
                    Sign in
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={2.5} stroke="currentColor" className="h-5 w-5 transition-transform group-hover:translate-x-1">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
                    </svg>
                  </Link>
                </>
              )}
            </div>
          </div>
        </section>

        {/* Features Section */}
        <section className="bg-zinc-950 py-24 sm:py-32 border-t border-zinc-900">
          <div className="mx-auto max-w-7xl px-6">
            
            {/* Section Header */}
            <div className="mb-16 text-center">
              <h2 className="mb-4 text-3xl font-bold text-white sm:text-4xl">
                Comprehensive compliance protection
              </h2>
              <p className="mx-auto max-w-2xl text-lg text-zinc-400">
                Automated security scanning that protects your organization from data breaches and regulatory penalties
              </p>
            </div>

            {/* Feature Cards */}
            <div className="grid grid-cols-1 gap-8 md:grid-cols-3">
              
              {/* Feature 1 */}
              <div className="group rounded-2xl border border-zinc-800 bg-zinc-900/50 p-8 transition-all hover:border-zinc-500/30 hover:shadow-lg hover:shadow-zinc-500/10">
                <div className="mb-4 inline-flex rounded-lg bg-zinc-800/50 p-3 text-zinc-100">
                  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" className="h-8 w-8">
                    <path fillRule="evenodd" d="M12.516 2.17a.75.75 0 00-1.032 0 11.209 11.209 0 01-7.877 3.08.75.75 0 00-.722.515A12.74 12.74 0 002.25 9.75c0 5.942 4.064 10.933 9.563 12.348a.749.749 0 00.374 0c5.499-1.415 9.563-6.406 9.563-12.348 0-1.39-.223-2.73-.635-3.985a.75.75 0 00-.722-.516l-.143.001c-2.996 0-5.717-1.17-7.734-3.08zm3.094 8.016a.75.75 0 10-1.22-.872l-3.236 4.53L9.53 12.22a.75.75 0 00-1.06 1.06l2.25 2.25a.75.75 0 001.14-.094l3.75-5.25z" clipRule="evenodd" />
                  </svg>
                </div>
                <h3 className="mb-3 text-xl font-semibold text-white">
                  PII & PHI Detection
                </h3>
                <p className="mb-4 text-zinc-400">
                  Instantly identify sensitive data exposure in your code, databases, and APIs with industry-leading accuracy.
                </p>
                <ul className="space-y-2 text-sm text-zinc-300">
                  <li className="flex items-center gap-2">
                    <span className="text-zinc-100">✓</span>
                    Real-time PII/PHI scanning
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-zinc-100">✓</span>
                    HIPAA & GDPR compliance checks
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-zinc-100">✓</span>
                    Context-aware vulnerability detection
                  </li>
                </ul>
              </div>

              {/* Feature 2 */}
              <div className="group rounded-2xl border border-zinc-800 bg-zinc-900/50 p-8 transition-all hover:border-zinc-500/30 hover:shadow-lg hover:shadow-zinc-500/10">
                <div className="mb-4 inline-flex rounded-lg bg-zinc-800/50 p-3 text-zinc-100">
                  <CpuChipIcon />
                </div>
                <h3 className="mb-3 text-xl font-semibold text-white">
                  Universal Language Support
                </h3>
                <p className="mb-4 text-zinc-400">
                  Scan any codebase regardless of programming language—Python, Java, JavaScript, SQL, and beyond.
                </p>
                <ul className="space-y-2 text-sm text-zinc-300">
                  <li className="flex items-center gap-2">
                    <span className="text-zinc-100">✓</span>
                    Multi-language code analysis
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-zinc-100">✓</span>
                    API endpoint security testing
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-zinc-100">✓</span>
                    SQL injection & query validation
                  </li>
                </ul>
              </div>

              {/* Feature 3 */}
              <div className="group rounded-2xl border border-zinc-800 bg-zinc-900/50 p-8 transition-all hover:border-zinc-500/30 hover:shadow-lg hover:shadow-zinc-500/10">
                <div className="mb-4 inline-flex rounded-lg bg-zinc-800/50 p-3 text-zinc-100">
                  <ChartBarIcon />
                </div>
                <h3 className="mb-3 text-xl font-semibold text-white">
                  Audit-Ready Reports
                </h3>
                <p className="mb-4 text-zinc-400">
                  Generate comprehensive compliance reports with actionable insights and remediation guidance.
                </p>
                <ul className="space-y-2 text-sm text-zinc-300">
                  <li className="flex items-center gap-2">
                    <span className="text-zinc-100">✓</span>
                    Executive-level dashboards
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-zinc-100">✓</span>
                    Detailed violation breakdowns
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-zinc-100">✓</span>
                    Compliance certification support
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </section>

        {/* Footer */}
        <footer className="border-t border-zinc-900 bg-zinc-950">
          <div className="mx-auto max-w-7xl px-6 py-12">
            <p className="text-center text-sm text-zinc-500">
              &copy; 2025 SecureSoft. All rights reserved.
            </p>
          </div>
        </footer>
      </main>
    </div>
  );
}
