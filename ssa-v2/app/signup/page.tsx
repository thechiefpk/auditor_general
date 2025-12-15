'use client';

import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import SecureGlobe from '../components/SecureGlobe';

export default function SignupPage() {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const { signup, user } = useAuth();
  const router = useRouter();

  // 1. If user is already logged in, redirect
  useEffect(() => {
    if (user) {
      router.push('/dashboard');
    }
  }, [user, router]);

  // 2. Handle form submission
  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    try {
      // We assume the signup function will auto-login
      await signup(username, email, password);
      // The signup function in context will redirect on success
    } catch (error) {
      console.error('Signup failed', error);
      // You can add state here to show an error message
    }
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
          <h2 className="font-bold tracking-tight text-white mb-3">Enterprise Security Audit</h2>
          <p className="text-zinc-400 text-sm leading-relaxed">
            Comprehensive compliance monitoring and automated security assessments for your entire infrastructure.
          </p>
        </div>
      </div>

      {/* Right Side - Signup Form */}
      <div className="flex-1 flex items-center justify-center lg:justify-end p-8 lg:pr-24 relative z-20">
        <div className="w-full max-w-sm">
          <div className="mb-8">
            <h1 className="text-2xl font-semibold tracking-tight text-white">Create account</h1>
            <p className="text-sm text-zinc-400 mt-2">Join us! It&apos;s quick and easy.</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Username Input */}
            <div>
              <label htmlFor="username" className="sr-only">Username</label>
              <input
                type="text"
                id="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                className="block w-full rounded-md border border-zinc-800 bg-zinc-900/50 p-2.5 text-sm text-white placeholder-zinc-500 shadow-sm focus:border-zinc-600 focus:ring-1 focus:ring-zinc-600 focus:outline-none transition-all"
                placeholder="Username"
              />
            </div>

            {/* Email Input */}
            <div>
              <label htmlFor="email" className="sr-only">Email Address</label>
              <input
                type="email"
                id="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="block w-full rounded-md border border-zinc-800 bg-zinc-900/50 p-2.5 text-sm text-white placeholder-zinc-500 shadow-sm focus:border-zinc-600 focus:ring-1 focus:ring-zinc-600 focus:outline-none transition-all"
                placeholder="Email address"
              />
            </div>

            {/* Password Input */}
            <div>
              <label htmlFor="password" className="sr-only">Password</label>
              <input
                type="password"
                id="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="block w-full rounded-md border border-zinc-800 bg-zinc-900/50 p-2.5 text-sm text-white placeholder-zinc-500 shadow-sm focus:border-zinc-600 focus:ring-1 focus:ring-zinc-600 focus:outline-none transition-all"
                placeholder="Password"
              />
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              className="w-full rounded-md bg-white py-2.5 px-4 text-center text-sm font-medium text-black shadow-lg shadow-zinc-900/20 hover:bg-zinc-200 transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-zinc-500 focus:ring-offset-2 focus:ring-offset-zinc-950 mt-2"
            >
              Create Account
            </button>
          </form>

          {/* Login Link */}
          <p className="mt-6 text-center text-xs text-zinc-500">
            Already have an account?{' '}
            <Link href="/login" className="font-medium text-zinc-300 hover:text-white transition-colors">
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
