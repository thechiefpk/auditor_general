'use client'; // This component needs to be a client component to use hooks

import Link from 'next/link';
import { useAuth } from '../context/AuthContext'; // Adjust path if needed

export default function Header() {
  const { user, logout } = useAuth();

  return (
    <header className="absolute top-0 left-0 w-full z-10 bg-transparent">
      <nav className="mx-auto flex max-w-7xl items-center justify-between p-6">
        {/* Logo / App Name */}
        <Link href="/home" className="text-2xl font-bold text-white flex items-center gap-2">
          <span className="bg-gradient-to-r from-blue-500 to-indigo-500 bg-clip-text text-transparent">
            Secure
          </span>
          Soft
        </Link>

        {/* Navigation Links */}
        <div className="flex items-center gap-4">
          {user ? (
            // --- User is Logged In ---
            <>
              <Link
                href="/dashboard"
                className="text-sm font-semibold text-slate-300 hover:text-white transition-colors"
              >
                Dashboard
              </Link>
              <button
                onClick={logout}
                className="rounded-lg bg-red-500/10 border border-red-500/20 py-2 px-4 text-sm font-semibold text-red-400 hover:bg-red-500/20 transition-all"
              >
                Logout
              </button>
            </>
          ) : (
            // --- User is Logged Out ---
            <>
              <Link
                href="/login"
                className="text-sm font-semibold text-slate-300 hover:text-white transition-colors"
              >
                Sign in
              </Link>
              <Link
                href="/signup"
                className="rounded-lg bg-gradient-to-r from-blue-600 to-indigo-600 py-2 px-4 text-sm font-semibold text-white shadow-lg shadow-blue-500/25 hover:shadow-blue-500/40 hover:from-blue-500 hover:to-indigo-500 transition-all"
              >
                Get started
              </Link>
            </>
          )}
        </div>
      </nav>
    </header>
  );
}