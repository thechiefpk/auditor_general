'use client';

import { useState, useEffect } from 'react';
import { useAuth } from '@/app/context/AuthContext';
import { API_ENDPOINTS, createAuthHeaders, apiRequest } from '@/app/lib/api';
import toast from 'react-hot-toast';

interface UserProfile {
  id: string;
  username: string;
  email: string;
  createdAt: string;
}

export default function ProfilePage() {
  const { user } = useAuth();
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    newPassword: '',
    confirmPassword: ''
  });

  useEffect(() => {
    fetchProfile();
  }, [user]);

  const fetchProfile = async () => {
    if (!user?.token) return;
    setLoading(true);
    try {
      const result = await apiRequest<UserProfile>(
        API_ENDPOINTS.PROFILE,
        {
          method: 'GET',
          headers: createAuthHeaders(user.token),
        }
      );

      if (result.data) {
        setProfile(result.data);
        setFormData(prev => ({
          ...prev,
          username: result.data!.username,
          email: result.data!.email
        }));
      } else {
        toast.error(result.error || 'Failed to load profile');
      }
    } catch (error) {
      toast.error('An error occurred loading profile');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!user?.token) return;

    if (formData.newPassword && formData.newPassword !== formData.confirmPassword) {
        toast.error('Passwords do not match');
        return;
    }

    setSaving(true);
    try {
      const body: any = {
          username: formData.username,
          email: formData.email
      };
      if (formData.newPassword) {
          body.newPassword = formData.newPassword;
      }

      const result = await apiRequest(
        API_ENDPOINTS.PROFILE,
        {
          method: 'PUT',
          headers: createAuthHeaders(user.token),
          body: JSON.stringify(body)
        }
      );

      if (result.error) {
        toast.error(result.error);
      } else {
        toast.success('Profile updated successfully');
        setFormData(prev => ({ ...prev, newPassword: '', confirmPassword: '' }));
        fetchProfile(); // Reload to confirm
      }
    } catch (error) {
      toast.error('An error occurred updating profile');
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin h-8 w-8 border-4 border-zinc-500 border-t-transparent rounded-full"></div>
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto space-y-6 animate-in fade-in duration-500">
      <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg">
        <h1 className="text-2xl font-bold text-white mb-2">Manage Profile</h1>
        <p className="text-zinc-400">Update your account information</p>
      </div>

      <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg">
        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="space-y-2">
            <label className="text-sm font-medium text-zinc-300">User ID</label>
            <input
              type="text"
              value={profile?.id || ''}
              disabled
              className="w-full bg-zinc-800/50 border border-zinc-700 rounded-lg px-4 py-2 text-zinc-500 cursor-not-allowed"
            />
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium text-zinc-300">Username</label>
            <input
              type="text"
              value={formData.username}
              disabled
              className="w-full bg-zinc-800/50 border border-zinc-700 rounded-lg px-4 py-2 text-zinc-500 cursor-not-allowed"
            />
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium text-zinc-300">Email Address</label>
            <input
              type="email"
              value={formData.email}
              onChange={(e) => setFormData({ ...formData, email: e.target.value })}
              className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-emerald-500/50 focus:border-emerald-500 transition-all"
              required
            />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <label className="text-sm font-medium text-zinc-300">New Password (Optional)</label>
                <input
                  type="password"
                  value={formData.newPassword}
                  onChange={(e) => setFormData({ ...formData, newPassword: e.target.value })}
                  placeholder="Leave blank to keep current"
                  className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-emerald-500/50 focus:border-emerald-500 transition-all"
                />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium text-zinc-300">Confirm Password</label>
                <input
                  type="password"
                  value={formData.confirmPassword}
                  onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
                  placeholder="Confirm new password"
                  className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-emerald-500/50 focus:border-emerald-500 transition-all"
                />
              </div>
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium text-zinc-300">Account Created</label>
            <input
              type="text"
              value={profile?.createdAt ? new Date(profile.createdAt).toLocaleString() : ''}
              disabled
              className="w-full bg-zinc-800/50 border border-zinc-700 rounded-lg px-4 py-2 text-zinc-500 cursor-not-allowed"
            />
          </div>

          <div className="pt-4 flex justify-end">
            <button
              type="submit"
              disabled={saving}
              className="bg-emerald-600 hover:bg-emerald-500 text-white font-medium py-2 px-6 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            >
              {saving ? (
                <>
                  <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full"></div>
                  Saving...
                </>
              ) : (
                'Save Changes'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
