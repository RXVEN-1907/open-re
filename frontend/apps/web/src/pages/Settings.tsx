import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import { api } from '../lib/api';
import { cn } from '../lib/utils';
import {
  User,
  Mail,
  Lock,
  Key,
  Trash2,
  Plus,
  Copy,
  Check,
  Loader2,
  AlertCircle,
  Monitor,
  Sun,
  Moon,
  Bell,
  Shield,
} from 'lucide-react';

interface User {
  id: string;
  email: string;
  username: string;
  full_name: string | null;
  roles: string[];
  permissions: string[];
  is_active: boolean;
  created_at: string;
  last_login: string | null;
}

interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  expires_at: string | null;
  last_used: string | null;
  created_at: string;
}

export default function Settings() {
  const { user, logout, refreshUser } = useAuth();
  const { theme, setTheme, resolvedTheme } = useTheme();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'profile' | 'security' | 'api-keys' | 'appearance' | 'danger'>('profile');
  const [showCreateKeyModal, setShowCreateKeyModal] = useState(false);
  const [newKeyName, setNewKeyName] = useState('');
  const [newKeyScopes, setNewKeyScopes] = useState('');
  const [createdKey, setCreatedKey] = useState<string | null>(null);

  const { data: apiKeys } = useQuery({
    queryKey: ['api-keys'],
    queryFn: async () => {
      const response = await api.get('/api/auth/api-keys');
      return response.data as ApiKey[];
    },
  });

  const updateProfileMutation = useMutation({
    mutationFn: async (data: { full_name?: string; email?: string }) => {
      const response = await api.put('/api/users/me', data);
      return response.data;
    },
    onSuccess: () => {
      refreshUser();
    },
  });

  const changePasswordMutation = useMutation({
    mutationFn: async (data: { current_password: string; new_password: string }) => {
      await api.put('/api/auth/password', data);
    },
  });

  const createKeyMutation = useMutation({
    mutationFn: async (data: { name: string; scopes: string[] }) => {
      const response = await api.post('/api/auth/api-keys', data);
      return response.data;
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['api-keys'] });
      setCreatedKey(data.api_key);
      setShowCreateKeyModal(false);
      setNewKeyName('');
      setNewKeyScopes('');
    },
  });

  const revokeKeyMutation = useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/api/auth/api-keys/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['api-keys'] });
    },
  });

  const tabs = [
    { id: 'profile', label: 'Profile', icon: User },
    { id: 'security', label: 'Security', icon: Shield },
    { id: 'api-keys', label: 'API Keys', icon: Key },
    { id: 'appearance', label: 'Appearance', icon: Monitor },
    { id: 'danger', label: 'Danger Zone', icon: AlertCircle },
  ];

  return (
    <div className="space-y-6 animate-fade-in max-w-4xl">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold">Settings</h1>
        <p className="text-muted-foreground">Manage your account and preferences</p>
      </div>

      {/* Tabs */}
      <div className="rounded-lg border border-border bg-card">
        <div className="border-b border-border">
          <nav className="flex gap-1 px-1" aria-label="Settings tabs">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as typeof activeTab)}
                className={cn(
                  'flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors',
                  activeTab === tab.id
                    ? 'border-primary text-primary'
                    : 'border-transparent text-muted-foreground hover:text-foreground'
                )}
              >
                <tab.icon className="h-4 w-4" />
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        <div className="p-6">
          {/* Profile Tab */}
          {activeTab === 'profile' && (
            <div className="space-y-6">
              <div className="flex items-center gap-4">
                <div className="flex h-20 w-20 items-center justify-center rounded-full bg-primary/10 text-primary text-2xl font-bold">
                  {user?.username?.charAt(0).toUpperCase()}
                </div>
                <div>
                  <h2 className="text-xl font-bold">{user?.username}</h2>
                  <p className="text-muted-foreground">{user?.email}</p>
                  <p className="text-sm text-muted-foreground">Member since {new Date(user?.created_at || '').toLocaleDateString()}</p>
                </div>
              </div>

              <div className="rounded-lg border border-border p-4">
                <h3 className="text-lg font-semibold mb-4">Profile Information</h3>
                <form onSubmit={(e) => { e.preventDefault(); updateProfileMutation.mutate({ full_name: (e.target as HTMLFormElement).full_name?.value }); }} className="space-y-4">
                  <div>
                    <label htmlFor="username" className="block text-sm font-medium mb-1">Username</label>
                    <input
                      id="username"
                      type="text"
                      value={user?.username}
                      className="w-full px-4 py-2 rounded-lg border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring"
                      disabled
                    />
                    <p className="text-xs text-muted-foreground mt-1">Username cannot be changed</p>
                  </div>
                  <div>
                    <label htmlFor="email" className="block text-sm font-medium mb-1">Email</label>
                    <input
                      id="email"
                      type="email"
                      value={user?.email}
                      className="w-full px-4 py-2 rounded-lg border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring"
                      disabled
                    />
                    <p className="text-xs text-muted-foreground mt-1">Email cannot be changed</p>
                  </div>
                  <div>
                    <label htmlFor="full_name" className="block text-sm font-medium mb-1">Full Name</label>
                    <input
                      id="full_name"
                      name="full_name"
                      type="text"
                      value={user?.full_name || ''}
                      className="w-full px-4 py-2 rounded-lg border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring"
                      placeholder="John Doe"
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={updateProfileMutation.isPending}
                    className="px-4 py-2 rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50 transition-colors"
                  >
                    {updateProfileMutation.isPending ? 'Saving...' : 'Save Changes'}
                  </button>
                </form>
              </div>

              <div className="rounded-lg border border-border p-4">
                <h3 className="text-lg font-semibold mb-4">Roles & Permissions</h3>
                <div className="flex flex-wrap gap-2">
                  {user?.roles.map((role) => (
                    <span key={role} className="px-2 py-1 rounded-full text-xs bg-primary/10 text-primary">
                      {role}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Security Tab */}
          {activeTab === 'security' && (
            <div className="space-y-6">
              <div className="rounded-lg border border-border p-4">
                <h3 className="text-lg font-semibold mb-4">Change Password</h3>
                <form onSubmit={(e) => { e.preventDefault(); changePasswordMutation.mutate({ current_password: (e.target as HTMLFormElement).current_password?.value, new_password: (e.target as HTMLFormElement).new_password?.value }); }} className="space-y-4 max-w-md">
                  <div>
                    <label htmlFor="current_password" className="block text-sm font-medium mb-1">Current Password</label>
                    <input
                      id="current_password"
                      name="current_password"
                      type="password"
                      className="w-full px-4 py-2 rounded-lg border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring"
                      required
                    />
                  </div>
                  <div>
                    <label htmlFor="new_password" className="block text-sm font-medium mb-1">New Password</label>
                    <input
                      id="new_password"
                      name="new_password"
                      type="password"
                      className="w-full px-4 py-2 rounded-lg border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring"
                      required
                      minLength={8}
                    />
                  </div>
                  <div>
                    <label htmlFor="confirm_password" className="block text-sm font-medium mb-1">Confirm New Password</label>
                    <input
                      id="confirm_password"
                      type="password"
                      className="w-full px-4 py-2 rounded-lg border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring"
                      required
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={changePasswordMutation.isPending}
                    className="px-4 py-2 rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50 transition-colors"
                  >
                    {changePasswordMutation.isPending ? 'Changing...' : 'Change Password'}
                  </button>
                </form>
              </div>

              <div className="rounded-lg border border-border p-4">
                <h3 className="text-lg font-semibold mb-4">Active Sessions</h3>
                <p className="text-muted-foreground mb-4">Session management coming soon</p>
              </div>

              <div className="rounded-lg border border-border p-4">
                <h3 className="text-lg font-semibold mb-4">Two-Factor Authentication</h3>
                <p className="text-muted-foreground mb-4">2FA support coming soon</p>
              </div>
            </div>
          )}

          {/* API Keys Tab */}
          {activeTab === 'api-keys' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold">API Keys</h3>
                <button
                  onClick={() => setShowCreateKeyModal(true)}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
                >
                  <Plus className="h-4 w-4" />
                  Create API Key
                </button>
              </div>

              {apiKeys && apiKeys.length > 0 ? (
                <div className="space-y-3">
                  {apiKeys.map((key) => (
                    <div key={key.id} className="rounded-lg border border-border p-4 flex items-center justify-between">
                      <div className="flex items-center gap-4">
                        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
                          <Key className="h-5 w-5" />
                        </div>
                        <div>
                          <p className="font-medium">{key.name}</p>
                          <p className="text-sm text-muted-foreground font-mono">{key.prefix}••••••••</p>
                          <p className="text-xs text-muted-foreground">
                            Created {new Date(key.created_at).toLocaleDateString()}
                            {key.last_used && ` • Last used ${new Date(key.last_used).toLocaleDateString()}`}
                            {key.expires_at && ` • Expires ${new Date(key.expires_at).toLocaleDateString()}`}
                          </p>
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {key.scopes.map((scope) => (
                            <span key={scope} className="px-2 py-0.5 rounded text-xs bg-muted text-muted-foreground">
                              {scope}
                            </span>
                          ))}
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => navigator.clipboard.writeText(`${key.prefix}••••••••`)}
                          className="p-2 rounded-lg text-muted-foreground hover:bg-accent transition-colors"
                          title="Copy prefix"
                        >
                          <Copy className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => {
                            if (confirm('Are you sure you want to revoke this API key?')) {
                              revokeKeyMutation.mutate(key.id);
                            }
                          }}
                          disabled={revokeKeyMutation.isPending}
                          className="p-2 rounded-lg text-muted-foreground hover:bg-accent hover:text-destructive transition-colors"
                          title="Revoke"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-12">
                  <Key className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <h3 className="text-lg font-medium mb-2">No API keys</h3>
                  <p className="text-muted-foreground mb-4">Create an API key to access the API programmatically</p>
                  <button
                    onClick={() => setShowCreateKeyModal(true)}
                    className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
                  >
                    <Plus className="h-4 w-4" />
                    Create API Key
                  </button>
                </div>
              )}

              {/* Created Key Modal */}
              {createdKey && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
                  <div className="w-full max-w-md bg-card rounded-lg border border-border p-6 shadow-xl animate-slide-in">
                    <div className="flex items-center gap-2 text-green-500 mb-4">
                      <Check className="h-5 w-5" />
                      <h3 className="text-lg font-semibold">API Key Created</h3>
                    </div>
                    <p className="text-muted-foreground mb-4">Save this key now - it won't be shown again!</p>
                    <div className="relative mb-4">
                      <code className="block px-4 py-2 rounded-lg bg-muted font-mono text-sm break-all">{createdKey}</code>
                      <button
                        onClick={() => { navigator.clipboard.writeText(createdKey); setCreatedKey(null); }}
                        className="absolute right-2 top-1/2 -translate-y-1/2 p-2 rounded-lg text-muted-foreground hover:bg-accent"
                      >
                        <Copy className="h-4 w-4" />
                      </button>
                    </div>
                    <button
                      onClick={() => setCreatedKey(null)}
                      className="w-full px-4 py-2 rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
                    >
                      I've saved it
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Appearance Tab */}
          {activeTab === 'appearance' && (
            <div className="space-y-6">
              <div className="rounded-lg border border-border p-4">
                <h3 className="text-lg font-semibold mb-4">Theme</h3>
                <div className="grid gap-4 md:grid-cols-3">
                  {['light', 'dark', 'system'].map((t) => (
                    <button
                      key={t}
                      onClick={() => setTheme(t as 'light' | 'dark' | 'system')}
                      className={cn(
                        'relative p-4 rounded-lg border-2 transition-colors flex flex-col items-center gap-2',
                        theme === t
                          ? 'border-primary bg-primary/5'
                          : 'border-border hover:border-primary/50'
                      )}
                    >
                      <div className={cn(
                        'w-12 h-12 rounded-lg flex items-center justify-center',
                        t === 'light' ? 'bg-white border' :
                        t === 'dark' ? 'bg-gray-900' :
                        'bg-gradient-to-br from-white to-gray-900 border'
                      )}>
                        {t === 'light' && <Sun className="h-6 w-6 text-yellow-500" />}
                        {t === 'dark' && <Moon className="h-6 w-6 text-blue-500" />}
                        {t === 'system' && <Monitor className="h-6 w-6 text-gray-500" />}
                      </div>
                      <span className="font-medium capitalize">{t}</span>
                      {theme === t && (
                        <div className="absolute top-2 right-2 w-5 h-5 rounded-full bg-primary flex items-center justify-center">
                          <Check className="h-3 w-3 text-primary-foreground" />
                        </div>
                      )}
                    </button>
                  ))}
                </div>
                <p className="text-sm text-muted-foreground mt-4">
                  System theme follows your OS preference. Changes apply immediately.
                </p>
              </div>

              <div className="rounded-lg border border-border p-4">
                <h3 className="text-lg font-semibold mb-4">Editor Preferences</h3>
                <p className="text-muted-foreground">Code editor settings coming soon</p>
              </div>
            </div>
          )}

          {/* Danger Zone Tab */}
          {activeTab === 'danger' && (
            <div className="space-y-6 border-t border-destructive/20 pt-6">
              <div className="rounded-lg border border-destructive/20 bg-destructive/5 p-4">
                <div className="flex items-center gap-3">
                  <AlertCircle className="h-6 w-6 text-destructive" />
                  <div>
                    <h3 className="font-semibold text-destructive">Danger Zone</h3>
                    <p className="text-sm text-muted-foreground">Irreversible actions</p>
                  </div>
                </div>
              </div>

              <div className="rounded-lg border border-border p-4">
                <h3 className="text-lg font-semibold mb-4">Delete Account</h3>
                <p className="text-muted-foreground mb-4">
                  Permanently delete your account and all associated data. This action cannot be undone.
                </p>
                <button className="px-4 py-2 rounded-lg bg-destructive text-destructive-foreground hover:bg-destructive/90 transition-colors">
                  Delete Account
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Create API Key Modal */}
      {showCreateKeyModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="w-full max-w-md bg-card rounded-lg border border-border p-6 shadow-xl animate-slide-in">
            <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
              <Plus className="h-5 w-5" />
              Create API Key
            </h2>
            <form onSubmit={(e) => { e.preventDefault(); createKeyMutation.mutate({ name: newKeyName, scopes: newKeyScopes.split(',').map(s => s.trim()).filter(Boolean) }); }} className="space-y-4">
              <div>
                <label htmlFor="key_name" className="block text-sm font-medium mb-1">Name *</label>
                <input
                  id="key_name"
                  type="text"
                  value={newKeyName}
                  onChange={(e) => setNewKeyName(e.target.value)}
                  className="w-full px-4 py-2 rounded-lg border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring"
                  placeholder="My API Key"
                  required
                  autoFocus
                />
              </div>
              <div>
                <label htmlFor="key_scopes" className="block text-sm font-medium mb-1">Scopes (comma-separated)</label>
                <input
                  id="key_scopes"
                  type="text"
                  value={newKeyScopes}
                  onChange={(e) => setNewKeyScopes(e.target.value)}
                  className="w-full px-4 py-2 rounded-lg border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring"
                  placeholder="read:projects, write:files, admin"
                />
                <p className="text-xs text-muted-foreground mt-1">Available: read:projects, write:projects, read:files, write:files, read:analysis, write:analysis, admin</p>
              </div>
              <div className="flex justify-end gap-2 pt-4">
                <button
                  type="button"
                  onClick={() => setShowCreateKeyModal(false)}
                  disabled={createKeyMutation.isPending}
                  className="px-4 py-2 rounded-lg border border-border hover:bg-accent transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createKeyMutation.isPending || !newKeyName.trim()}
                  className="px-4 py-2 rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50 transition-colors"
                >
                  {createKeyMutation.isPending ? 'Creating...' : 'Create Key'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}