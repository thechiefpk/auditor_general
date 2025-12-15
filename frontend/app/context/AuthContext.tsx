'use client';

import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { useRouter } from 'next/navigation';
import Cookies from 'js-cookie';
import toast from 'react-hot-toast';
import { API_ENDPOINTS, createAuthHeaders } from '../lib/api';

// 1. Define the shape of a user
interface User {
  token: string;
  username?: string;
}

// 2. Define the shape of the context value
interface AuthContextType {
  user: User | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  signup: (username: string, email: string, password: string) => Promise<void>; // <-- ADDED
}

// 3. Create the Context
const AuthContext = createContext<AuthContextType | null>(null);

// 4. Create the Provider Component
interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(null);
  const router = useRouter();

  useEffect(() => {
    const token = Cookies.get('authToken');
    const username = Cookies.get('authUsername');
    if (token) {
      setUser({ token, username }); 
    }
  }, []);

  // 5. Login Function
  const login = async (username: string, password: string) => {
    try {
      const res = await fetch(API_ENDPOINTS.LOGIN, {
        method: 'POST',
        headers: createAuthHeaders(),
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (res.ok) {
        const token = data.token; 
        Cookies.set('authToken', token, { expires: 1 });
        Cookies.set('authUsername', username, { expires: 1 });
        setUser({ token, username });
        toast.success('Login successful!');
        router.push('/dashboard');
      } else {
        toast.error(data.message || 'Login failed');
        console.error(data.message);
      }
    } catch (error) {
      toast.error('An error occurred during login');
      console.error('An error occurred during login', error);
    }
  };

  // 6. Signup Function (NEW)
  const signup = async (username: string, email: string, password: string) => {
    try {
      const res = await fetch(API_ENDPOINTS.REGISTER, {
        method: 'POST',
        headers: createAuthHeaders(),
        body: JSON.stringify({ username, email, password }),
      });
      
      const data = await res.json();

      if (res.ok) {
        // Auto-login on successful signup
        const token = data.token;
        Cookies.set('authToken', token, { expires: 1 });
        Cookies.set('authUsername', username, { expires: 1 });
        setUser({ token, username });
        toast.success('Account created successfully!');
        router.push('/dashboard');
      } else {
        toast.error(data.message || 'Signup failed');
      }
    } catch (error) {
      toast.error('An error occurred during signup');
      console.error(error);
    }
  };

  const logout = () => {
    Cookies.remove('authToken');
    Cookies.remove('authUsername');
    setUser(null);
    router.push('/login');
    toast.success('Logged out');
  };

  // 8. Provide the context value
  return (
    <AuthContext.Provider value={{ user, login, logout, signup }}> {/* <-- ADDED signup */}
      {children}
    </AuthContext.Provider>
  );
}

// 9. Create the custom hook
export function useAuth() {
  const context = useContext(AuthContext);
  if (context === null) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}