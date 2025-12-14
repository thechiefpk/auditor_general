'use client';

import { useAuth } from '../context/AuthContext';
import { useRouter, usePathname } from 'next/navigation';
import Link from 'next/link';
import { useEffect, useState } from 'react';

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const { user, logout } = useAuth();
  const router = useRouter();
  const pathname = usePathname();
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);

  useEffect(() => {
    if (!user) {
      router.push('/login');
    }
  }, [user, router]);

  if (!user) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-900">
        <div className="flex flex-col items-center gap-4">
          <div className="h-10 w-10 animate-spin rounded-full border-4 border-blue-500 border-t-transparent"></div>
          <p className="text-slate-400">Loading...</p>
        </div>
      </div>
    );
  }

  const navigation = [
    { name: 'Dashboard', href: '/dashboard', icon: '📊' },
    { name: 'New Scan', href: '/dashboard/scan', icon: '🔍' },
    { name: 'Reports', href: '/dashboard/reports', icon: '📄' },
    { name: 'Statistics', href: '/dashboard/statistics', icon: '📈' },
  ];

  return (
    <div className="flex h-screen bg-slate-950">
      {/* Sidebar */}
      <aside
        className={`${
          isSidebarOpen ? 'w-64' : 'w-20'
        } transition-all duration-300 bg-slate-900 border-r border-slate-800 flex flex-col`}
      >
        {/* Logo */}
        <div className="flex h-16 items-center justify-between px-4 border-b border-slate-800">
          {isSidebarOpen && (
            <h1 className="text-xl font-bold text-white bg-gradient-to-r from-blue-400 to-indigo-400 bg-clip-text text-transparent">
              SecureSoft
            </h1>
          )}
          <button
            onClick={() => setIsSidebarOpen(!isSidebarOpen)}
            className="rounded-lg p-2 text-slate-400 hover:bg-slate-800 hover:text-white transition-colors"
          >
            <span className="text-xl">{isSidebarOpen ? '◀' : '▶'}</span>
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 space-y-1 px-3 py-4">
          {navigation.map((item) => {
            const isActive = pathname === item.href;
            return (
              <Link
                key={item.name}
                href={item.href}
                className={`flex items-center gap-3 rounded-lg px-3 py-3 text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-blue-600 text-white shadow-lg shadow-blue-500/25'
                    : 'text-slate-400 hover:bg-slate-800 hover:text-white'
                }`}
              >
                <span className="text-xl">{item.icon}</span>
                {isSidebarOpen && <span>{item.name}</span>}
              </Link>
            );
          })}
        </nav>

        {/* User Section */}
        <div className="border-t border-slate-800 p-4">
          <button
            onClick={logout}
            className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-red-400 hover:bg-red-500/10 hover:text-red-300 transition-colors w-full ${
              !isSidebarOpen && 'justify-center'
            }`}
          >
            <span className="text-xl">🚪</span>
            {isSidebarOpen && <span>Logout</span>}
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto bg-slate-950">
        {/* Header */}
        <header className="sticky top-0 z-10 bg-slate-900/80 backdrop-blur-md border-b border-slate-800 shadow-sm">
          <div className="flex h-16 items-center justify-between px-6">
            <h2 className="text-lg font-semibold text-white">
              {navigation.find((item) => item.href === pathname)?.name || 'Dashboard'}
            </h2>
            <div className="flex items-center gap-4">
              <span className="text-sm text-slate-400">
                Welcome, {(user as any).username || 'User'}
              </span>
              <div className="h-8 w-8 rounded-full bg-blue-600/20 flex items-center justify-center text-blue-400 font-bold border border-blue-500/30">
                {(user as any).username?.charAt(0).toUpperCase() || 'U'}
              </div>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <div className="p-6">
          {children}
        </div>
      </main>
    </div>
  );
}
