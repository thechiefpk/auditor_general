// API Configuration
export const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || 'https://localhost:7120';

export const API_ENDPOINTS = {
  // Auth endpoints
  LOGIN: `${API_BASE_URL}/api/auth/login`,
  REGISTER: `${API_BASE_URL}/api/auth/register`,
  PROFILE: `${API_BASE_URL}/api/auth/profile`,
  
  // Scan endpoints
  SCAN: `${API_BASE_URL}/api/scan`,
  SCAN_GIT: `${API_BASE_URL}/api/scan/git`,
  MY_REPORTS: `${API_BASE_URL}/api/myreports`,
  REPORT: (id: string) => `${API_BASE_URL}/api/report/${id}`,
  STATS: (id: string) => `${API_BASE_URL}/api/stats/${id}`,
  VIOLATIONS: (id: string) => `${API_BASE_URL}/api/report/${id}/violations`,
};

// Helper function to create headers with auth token
export const createAuthHeaders = (token?: string) => {
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
  };
  
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  
  return headers;
};

// Helper function for API calls with better error handling
export const apiRequest = async <T = any>(
  url: string,
  options: RequestInit = {}
): Promise<{ data?: T; error?: string; status: number }> => {
  try {
    const response = await fetch(url, {
      ...options,
      // Add mode: 'cors' to handle cross-origin requests
      mode: 'cors',
      // Add credentials to support authenticated requests
      credentials: 'omit',
    });

    // Check if response has content before parsing JSON
    const contentType = response.headers.get('content-type');
    let data: any = null;
    
    if (contentType && contentType.includes('application/json')) {
        try {
            data = await response.json();
        } catch (e) {
            console.warn('Failed to parse JSON response:', e);
            data = {}; 
        }
    } else {
        // Handle non-JSON responses (like 404 HTML or empty 204)
        const text = await response.text();
        try {
            data = text ? JSON.parse(text) : {};
        } catch {
            data = { message: text };
        }
    }

    if (!response.ok) {
      return {
        error: data.error || data.message || `Request failed with status ${response.status}`,
        status: response.status,
      };
    }

    return {
      data,
      status: response.status,
    };
  } catch (error) {
    console.error('API Request Error:', error);
    
    if (error instanceof TypeError && error.message.includes('fetch')) {
      return {
        error: 'Cannot connect to API server. Check if backend is running on https://localhost:7120 and certificate is trusted.',
        status: 0,
      };
    }

    return {
      error: error instanceof Error ? error.message : 'An unknown error occurred',
      status: 0,
    };
  }
};
