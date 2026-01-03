'use client';

import { useAuth } from '../context/AuthContext';
import { useRouter, usePathname } from 'next/navigation';
import Link from 'next/link';
import { useEffect, useState } from 'react';
import { API_ENDPOINTS } from '@/app/lib/api';
import toast from 'react-hot-toast';

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const { user, logout, isLoading } = useAuth();
  const router = useRouter();
  const pathname = usePathname();
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);

  const [isProfileOpen, setIsProfileOpen] = useState(false);

  useEffect(() => {
    if (!isLoading && !user) {
      router.push('/login');
    }
  }, [user, isLoading, router]);

  // Check and start Docker on mount (Login/Dashboard load)
  useEffect(() => {
    const checkAndStartDocker = async () => {
        if (!user) return;
        try {
            const res = await fetch(API_ENDPOINTS.SYSTEM_DOCKER_STATUS);
            if (!res.ok) return;
            const data = await res.json();
            
            if (!data.isRunning) {
                // Silent start
                const startRes = await fetch(API_ENDPOINTS.SYSTEM_START_DOCKER, { method: 'POST' });
                
                if (startRes.ok) {
                    const interval = setInterval(async () => {
                        try {
                            const pollRes = await fetch(API_ENDPOINTS.SYSTEM_DOCKER_STATUS);
                            const pollData = await pollRes.json();
                            if (pollData.isRunning) {
                                clearInterval(interval);
                            }
                        } catch {}
                    }, 3000);
                }
            }
        } catch (e) {
            console.error("Failed to check docker status", e);
        }
    };

    checkAndStartDocker();
  }, [user]);

  // Close profile dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = () => setIsProfileOpen(false);
    if (isProfileOpen) {
      window.addEventListener('click', handleClickOutside);
    }
    return () => window.removeEventListener('click', handleClickOutside);
  }, [isProfileOpen]);

  if (isLoading || !user) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-zinc-950">
        <div className="flex flex-col items-center gap-4">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-white border-t-transparent"></div>
          <p className="text-zinc-500 text-sm">Loading...</p>
        </div>
      </div>
    );
  }

  const navigation = [
    { name: 'Dashboard', href: '/dashboard', icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
      </svg>
    )},
    { name: 'Compliance Scan', href: '/dashboard/scan', icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
    )},
    { name: 'Automation', href: '/dashboard/automation', icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
    )},
    { name: 'Reports', href: '/dashboard/reports', icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
      </svg>
    )},
    { name: 'Statistics', href: '/dashboard/statistics', icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 12l3-3 3 3 4-4M8 21l4-4 4 4M3 4h18M4 4h16v12a1 1 0 01-1 1H5a1 1 0 01-1-1V4z" />
      </svg>
    )},
    { name: 'Network Audit', href: '/dashboard/network-audit', icon: (
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
        </svg>
    )}
  ];

  return (
    <div className="flex h-screen bg-zinc-950 text-zinc-100 font-sans selection:bg-zinc-700 selection:text-white">
      {/* Sidebar */}
      <aside
        className={`${
          isSidebarOpen ? 'w-52' : 'w-16'
        } transition-all duration-300 bg-black border-r border-zinc-900 flex flex-col shrink-0`}
      >
        {/* Logo and Collapse Button */}
        <div className={`flex h-14 items-center ${isSidebarOpen ? 'justify-between px-4' : 'justify-center'} border-b border-zinc-900`}>
          {isSidebarOpen ? (
            <h1 className="text-lg font-bold tracking-tight text-white">
              SecureSoft
            </h1>
          ) : (
             <span className="font-bold text-white">SS</span>
          )}
          
          {isSidebarOpen && (
            <button
              onClick={() => setIsSidebarOpen(false)}
              className="p-1.5 rounded-md text-zinc-400 hover:bg-zinc-800 hover:text-white transition-colors"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
            </button>
          )}
        </div>
        
        {!isSidebarOpen && (
             <button
              onClick={() => setIsSidebarOpen(true)}
              className="mx-auto mt-2 p-1.5 rounded-md text-zinc-400 hover:bg-zinc-800 hover:text-white transition-colors"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
              </svg>
            </button>
        )}

        {/* Navigation */}
        <nav className="flex-1 space-y-1 p-2">
          {navigation.map((item) => {
            const isActive = pathname === item.href;
            return (
              <Link
                key={item.name}
                href={item.href}
                className={`flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-all group ${
                  isActive
                    ? 'bg-zinc-800 text-white shadow-md shadow-zinc-900/20 ring-1 ring-zinc-700'
                    : 'text-zinc-500 hover:text-zinc-300 hover:bg-zinc-900'
                }`}
              >
                <span className={`${isActive ? 'text-white' : 'text-zinc-500 group-hover:text-zinc-300'}`}>
                  {item.icon}
                </span>
                {isSidebarOpen && <span>{item.name}</span>}
              </Link>
            );
          })}
        </nav>

        {/* Bottom Section */}
        <div className="border-t border-zinc-900 p-2">
          {/* Removed collapse button as it moved to top */}
          
          <button
            onClick={logout}
            className={`flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium text-zinc-500 hover:bg-zinc-900 hover:text-white transition-colors w-full mt-1 ${
              !isSidebarOpen && 'justify-center'
            }`}
          >
             <span className="w-5 h-5 flex items-center justify-center">
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" /></svg>
             </span>
            {isSidebarOpen && <span>Logout</span>}
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto bg-zinc-950">
        {/* Header */}
        <header className="sticky top-0 z-10 bg-zinc-950/80 backdrop-blur-md border-b border-zinc-900">
          <div className="flex h-14 items-center justify-between px-6">
            <h2 className="text-sm font-medium text-zinc-200">
               {navigation.find((item) => item.href === pathname)?.name || 'Dashboard'}
            </h2>
            <div className="relative">
              <button 
                onClick={(e) => {
                  e.stopPropagation();
                  setIsProfileOpen(!isProfileOpen);
                }}
                className="flex items-center gap-3 hover:bg-zinc-900/50 p-1.5 rounded-full pr-3 transition-colors outline-none"
              >
                <span className="text-xs text-zinc-500 hidden sm:inline-block">
                  Hi ,  <span className="text-zinc-300 font-medium">{ user?.username || 'User'}</span>
                </span>
                <div className="h-7 w-7 rounded-full bg-zinc-800 flex items-center justify-center text-xs text-zinc-300 font-bold border border-zinc-700">
                  {user?.username?.charAt(0).toUpperCase() || 'U'}
                </div>
              </button>

              {/* Profile Dropdown */}
              {isProfileOpen && (
                <div className="absolute right-0 top-full mt-2 w-48 rounded-md bg-zinc-900 border border-zinc-800 shadow-lg py-1 z-50">
                  <div className="px-4 py-2 border-b border-zinc-800">
                    <p className="text-sm font-medium text-white truncate">{user?.username || 'User'}</p>
                    <p className="text-xs text-zinc-500 truncate">user@securesoft.com</p>
                  </div>
                  
                  <Link 
                    href="/dashboard/profile" 
                    className="block px-4 py-2 text-sm text-zinc-400 hover:bg-zinc-800 hover:text-white transition-colors"
                    onClick={() => setIsProfileOpen(false)}
                  >
                    Manage Profile
                  </Link>
                  
                  <button
                    onClick={() => {
                      setIsProfileOpen(false);
                      logout();
                    }}
                    className="block w-full text-left px-4 py-2 text-sm text-red-400 hover:bg-zinc-800 hover:text-red-300 transition-colors"
                  >
                    Logout
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        {/* Page Content */}
        <div className="p-6 max-w-7xl mx-auto">
          {children}
        </div>
      </main>
    </div>
  );
}
