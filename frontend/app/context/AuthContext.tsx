'use client';

import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { useRouter } from 'next/navigation';
import Cookies from 'js-cookie';
import toast from 'react-hot-toast';
import { API_ENDPOINTS, createAuthHeaders, apiRequest } from '../lib/api';

// 1. Define the shape of a user
interface User {
  token: string;
  username?: string;
}

// 2. Define the shape of the context value
interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  login: (username: string, password: string) => Promise<{ ok: boolean; message?: string }>;
  logout: () => void;
  signup: (username: string, email: string, password: string) => Promise<{ ok: boolean; message?: string }>;
}

// 3. Create the Context
const AuthContext = createContext<AuthContextType | null>(null);

// 4. Create the Provider Component
interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const router = useRouter();

  useEffect(() => {
    const token = Cookies.get('authToken');
    const username = Cookies.get('authUsername');
    if (token) {
      setUser({ token, username }); 
    }
    setIsLoading(false);
  }, []);

  // 5. Login Function
  const login = async (username: string, password: string) => {
    console.log('AuthContext.login called with:', username);
    try {
      const { data, error, status } = await apiRequest(API_ENDPOINTS.LOGIN, {
        method: 'POST',
        headers: createAuthHeaders(),
        body: JSON.stringify({ username, password }),
      });
      if (!error && data) {
        const token = (data as any).token;
        Cookies.set('authToken', token, { expires: 1 });
        Cookies.set('authUsername', username, { expires: 1 });
        setUser({ token, username });
        toast.success('Login successful!');
        router.push('/dashboard');
        return { ok: true };
      } else {
        const msg = error || 'Login failed';
        // toast.error(msg); // Removed to avoid double toast in UI components
        return { ok: false, message: msg };
      }
    } catch (error) {
      const msg = 'An error occurred during login';
      // toast.error(msg); // Removed to avoid double toast in UI components
      return { ok: false, message: msg };
    }
  };

  // 6. Signup Function
  const signup = async (username: string, email: string, password: string) => {
    try {
      const { data, error, status } = await apiRequest(API_ENDPOINTS.REGISTER, {
        method: 'POST',
        headers: createAuthHeaders(),
        body: JSON.stringify({ username, email, password }),
      });
      if (!error && data) {
        const token = (data as any).token;
        Cookies.set('authToken', token, { expires: 1 });
        Cookies.set('authUsername', username, { expires: 1 });
        setUser({ token, username });
        toast.success('Account created successfully!');
        router.push('/dashboard');
        return { ok: true };
      } else {
        const msg = error || 'Signup failed';
        // toast.error(msg); // Removed to avoid double toast in UI components
        return { ok: false, message: msg };
      }
    } catch (error) {
      const msg = 'An error occurred during signup';
      // toast.error(msg); // Removed to avoid double toast in UI components
      return { ok: false, message: msg };
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
    <AuthContext.Provider value={{ user, isLoading, login, logout, signup }}> {/* <-- ADDED signup */}
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
