'use client';

import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import SecureGlobe from '../components/SecureGlobe';
import toast from 'react-hot-toast';

export default function LoginPage() {
  const [emailOrUsername, setEmailOrUsername] = useState('');
  const [password, setPassword] = useState('');
  const [errors, setErrors] = useState<{ user?: string; password?: string }>({});
  const [submitting, setSubmitting] = useState(false);
  const { login, user } = useAuth();
  const router = useRouter();

  // 1. If user is already logged in, redirect to dashboard
  useEffect(() => {
    if (user) {
      router.push('/dashboard');
    }
  }, [user, router]);

  // 2. Handle form submission
  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const newErrors: { user?: string; password?: string } = {};
    const isEmail = emailOrUsername.includes('@');
    if (!emailOrUsername.trim()) {
      newErrors.user = 'Enter username or email';
    } else if (isEmail) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(emailOrUsername.trim())) {
        newErrors.user = 'Enter a valid email address';
      }
    } else if (emailOrUsername.trim().length < 3) {
      newErrors.user = 'Username must be at least 3 characters';
    }
    if (!password) {
      newErrors.password = 'Enter your password';
    }
    setErrors(newErrors);
    if (Object.keys(newErrors).length > 0) {
      return;
    }
    setSubmitting(true);
    const result = await login(emailOrUsername.trim(), password);
    if (!result.ok) {
      toast.error(result.message || 'Login failed');
    }
    setSubmitting(false);
  };

  return (
    <div className="flex min-h-screen bg-zinc-950 text-white overflow-hidden relative">
      {/* Brand Name Top Left */}
      <div className="absolute top-8 left-8 z-20">
          <span className="text-xl font-bold tracking-tight text-white group-hover:text-zinc-300 transition-colors">
            Secure<span className="text-zinc-400">Soft</span>
          </span>
      </div>

      {/* Left Side - Globe & Content */}
      <div className="hidden lg:flex flex-1 flex-col items-center justify-center relative z-10 translate-x-[50px]">
        <div className="w-[300px] h-[300px] relative mb-5 translate-x-[20px]">
            <div className="absolute inset-0 flex items-center justify-center">
                <SecureGlobe />
            </div>
        </div>
        
        <div className="text-center max-w-md px-6 translate-x-[20px]">
            <h2 className="font-bold tracking-tight text-white mb-3">Enterprise Compliance Audit</h2>
            <p className="text-zinc-400 text-sm leading-relaxed">
                Comprehensive compliance monitoring and automated security assessments for your entire infrastructure.
            </p>
        </div>
      </div>

      {/* Right Side - Login Form */}
      <div className="flex-1 flex items-center justify-center lg:justify-end p-8 lg:pr-24 relative z-20">
        <div className="w-full max-w-sm">
            <div className="mb-8">
                <h1 className="text-2xl font-semibold tracking-tight text-white">Welcome back</h1>
                <p className="text-sm text-zinc-400 mt-2">Please enter your details to sign in.</p>
            </div>

            <form onSubmit={handleSubmit} className="space-y-4">
            {/* Email or Username Input */}
            <div>
                <label htmlFor="emailOrUsername" className="sr-only">Email or Username</label>
                <input
                type="text"
                id="emailOrUsername"
                value={emailOrUsername}
                onChange={(e) => setEmailOrUsername(e.target.value)}
                className="block w-full rounded-md border border-zinc-800 bg-zinc-900/50 p-2.5 text-sm text-white placeholder-zinc-500 shadow-sm focus:border-zinc-600 focus:ring-1 focus:ring-zinc-600 focus:outline-none transition-all"
                placeholder="Username or email"
                />
                {errors.user && <p className="mt-1 text-xs text-red-400">{errors.user}</p>}
            </div>

            {/* Password Input */}
            <div>
                <label htmlFor="password" className="sr-only">Password</label>
                <input
                type="password"
                id="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="block w-full rounded-md border border-zinc-800 bg-zinc-900/50 p-2.5 text-sm text-white placeholder-zinc-500 shadow-sm focus:border-zinc-600 focus:ring-1 focus:ring-zinc-600 focus:outline-none transition-all"
                placeholder="Password"
                />
                {errors.password && <p className="mt-1 text-xs text-red-400">{errors.password}</p>}
            </div>

            {/* Submit Button */}
            <button
                type="submit"
                disabled={submitting}
                className={`w-full rounded-md py-2.5 px-4 text-center text-sm font-medium shadow-lg transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-zinc-500 focus:ring-offset-2 focus:ring-offset-zinc-950 mt-2 ${submitting ? 'bg-zinc-300 text-zinc-700 cursor-not-allowed' : 'bg-white text-black hover:bg-zinc-200'}`}
            >
                {submitting ? 'Signing in…' : 'Sign in'}
            </button>
            </form>

            {/* Sign-up Link */}
            <p className="mt-6 text-center text-xs text-zinc-500">
            Don&apos;t have an account?{' '}
            <Link href="/signup" prefetch={false} className="font-medium text-zinc-300 hover:text-white transition-colors">
                Create account
            </Link>
            </p>
        </div>
      </div>
    </div>
  );
}
