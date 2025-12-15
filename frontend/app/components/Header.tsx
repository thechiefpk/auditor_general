'use client';

import Link from 'next/link';
import { useAuth } from '../context/AuthContext';
import { useState, useEffect } from 'react';

export default function Header() {
  const { user, logout } = useAuth();
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 20);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return (
    <header 
      className={`fixed top-0 left-0 w-full z-50 transition-all duration-300 ${
        scrolled ? 'bg-zinc-950/80 backdrop-blur-md border-b border-zinc-800 py-3' : 'bg-transparent py-5'
      }`}
    >
      <nav className="mx-auto flex max-w-7xl items-center justify-between px-6">
        {/* Logo */}
        <Link href="/home" prefetch={false} className="group flex items-center gap-2">
          <span className="text-xl font-bold tracking-tight text-white group-hover:text-zinc-300 transition-colors">
            Secure<span className="text-zinc-400">Soft</span>
          </span>
        </Link>

        {/* Navigation & User */}
        <div className="flex items-center gap-6">
          {user ? (
            <>
              <div className="hidden md:flex items-center gap-6">
                <Link
                  href="/dashboard"
                  prefetch={false}
                  className="text-sm font-medium text-zinc-400 hover:text-white transition-colors tracking-wide"
                >
                  Dashboard
                </Link>
                <Link
                  href="/dashboard/scan"
                  prefetch={false}
                  className="text-sm font-medium text-zinc-400 hover:text-white transition-colors tracking-wide"
                >
                  New Scan
                </Link>
              </div>

              <div className="flex items-center gap-4 pl-6 border-l border-zinc-800">
                <div className="flex flex-col items-end">
                  <span className="text-xs text-zinc-500 font-medium uppercase tracking-wider"></span>
                  <span className="text-sm font-semibold text-white tracking-tight">
                    {user.username || 'User'}
                  </span>
                </div>
                
                <div className="h-9 w-9 rounded-full bg-zinc-800 border border-zinc-700 flex items-center justify-center text-white font-bold shadow-inner">
                  {(user.username?.[0] || 'U').toUpperCase()}
                </div>

                <button
                  onClick={logout}
                  className="ml-2 rounded-full p-2 text-zinc-400 hover:bg-zinc-800 hover:text-white transition-all"
                  title="Logout"
                >
                  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
                    <polyline points="16 17 21 12 16 7"></polyline>
                    <line x1="21" y1="12" x2="9" y2="12"></line>
                  </svg>
                </button>
              </div>
            </>
          ) : (
            <>
              <Link
                href="/login"
                prefetch={false}
                className="text-sm font-medium text-zinc-300 hover:text-white transition-colors tracking-wide"
              >
                Sign in
              </Link>
              <Link
                href="/signup"
                prefetch={false}
                className="rounded-full bg-white text-black py-2 px-5 text-sm font-bold shadow-lg shadow-zinc-500/10 hover:bg-zinc-200 hover:shadow-zinc-500/20 transition-all transform hover:-translate-y-0.5"
              >
                Get Started
              </Link>
            </>
          )}
        </div>
      </nav>
    </header>
  );
}
