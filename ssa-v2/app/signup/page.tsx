'use client';

import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

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
    <div className="flex min-h-screen items-center justify-center bg-slate-900">
      <div className="w-full max-w-md rounded-xl bg-slate-900 border border-slate-800 p-8 shadow-2xl shadow-blue-900/20">
        <h1 className="mb-6 text-center text-3xl font-bold text-white">
          Create an Account
        </h1>
        <p className="mb-6 text-center text-slate-400">
          Join us! It&apos;s quick and easy.
        </p>

        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Username Input */}
          <div>
            <label
              htmlFor="username"
              className="mb-2 block text-sm font-medium text-slate-300"
            >
              Username
            </label>
            <input
              type="text"
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              className="block w-full rounded-lg border border-slate-700 bg-slate-800 p-3 text-white placeholder-slate-500 shadow-sm focus:border-blue-500 focus:ring-blue-500 focus:outline-none transition-colors"
              placeholder="username"
            />
          </div>

          {/* Email Input */}
          <div>
            <label
              htmlFor="email"
              className="mb-2 block text-sm font-medium text-slate-300"
            >
              Email Address
            </label>
            <input
              type="email"
              id="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="block w-full rounded-lg border border-slate-700 bg-slate-800 p-3 text-white placeholder-slate-500 shadow-sm focus:border-blue-500 focus:ring-blue-500 focus:outline-none transition-colors"
              placeholder="you@example.com"
            />
          </div>

          {/* Password Input */}
          <div>
            <label
              htmlFor="password"
              className="mb-2 block text-sm font-medium text-slate-300"
            >
              Password
            </label>
            <input
              type="password"
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="block w-full rounded-lg border border-slate-700 bg-slate-800 p-3 text-white placeholder-slate-500 shadow-sm focus:border-blue-500 focus:ring-blue-500 focus:outline-none transition-colors"
              placeholder="••••••••"
            />
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            className="w-full rounded-lg bg-blue-600 py-3 px-4 text-center text-base font-semibold text-white shadow-lg shadow-blue-500/25 transition duration-200 ease-in hover:bg-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-slate-900"
          >
            Create Account
          </button>
        </form>

        {/* Login Link */}
        <p className="mt-6 text-center text-sm text-slate-400">
          Already have an account?{' '}
          <Link
            href="/login"
            className="font-medium text-blue-400 hover:text-blue-300 transition-colors"
          >
            Login
          </Link>
        </p>
      </div>
    </div>
  );
}