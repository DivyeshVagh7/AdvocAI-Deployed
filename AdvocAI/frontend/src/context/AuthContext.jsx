import React, { createContext, useState, useEffect, useContext } from 'react';
import axios from '../api/axios';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const loadUser = async () => {
      const accessToken = localStorage.getItem('access_token');
      if (accessToken) {
        try {
          // Validate token and fetch user profile
          const response = await axios.get('/api/auth/profile/', {
            headers: {
              Authorization: `Bearer ${accessToken}`
            }
          });
          setUser(response.data);
          setIsAuthenticated(true);
        } catch (error) {
          console.error('Failed to load user profile:', error);
          localStorage.removeItem('access_token');
          localStorage.removeItem('refresh_token');
          setUser(null);
          setIsAuthenticated(false);
        }
      }
      setLoading(false);
    };

    loadUser();
  }, []);

  const login = async (email, password, socialUserData = null, socialTokens = null) => {
    setLoading(true);
    try {
      let tokens;
      let userData;
      let redirect;

      if (socialUserData && socialTokens) {
        // For social logins (e.g., Google)
        tokens = socialTokens;
        userData = socialUserData;
        redirect = 'home'; // Assuming social login always redirects to home
      } else {
        // For traditional email/password login
        const response = await axios.post('/api/auth/login/', { email, password });
        tokens = response.data.tokens;
        userData = response.data.user;
        redirect = response.data.redirect;
      }
      
      const { access, refresh } = tokens;

      localStorage.setItem('access_token', access);
      localStorage.setItem('refresh_token', refresh);
      setUser(userData);
      setIsAuthenticated(true);
      toast.success('Login successful!');

      if (userData?.role === 'lawyer' && userData?.lawyer_verification_status !== 'approved') {
        navigate('/lawyer-dashboard');
      } else if (redirect) {
        navigate(`/${redirect === 'home' ? '' : redirect}`);
      } else {
        navigate('/');
      }
      return true;
    } catch (error) {
      console.error('Login failed:', error);
      toast.error(error.response?.data?.error || 'Login failed.');
      return false;
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    setLoading(true);
    try {
      const refreshToken = localStorage.getItem('refresh_token');
      if (refreshToken) {
        await axios.post('/api/auth/logout/', { refresh: refreshToken });
      }
    } catch (error) {
      console.error('Logout failed:', error);
      // Even if logout API fails, clear local storage
    } finally {
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      setUser(null);
      setIsAuthenticated(false);
      toast.success('Logged out successfully!');
      navigate('/login');
      setLoading(false);
    }
  };

  return (
    <AuthContext.Provider value={{ user, isAuthenticated, loading, login, logout, setUser, setIsAuthenticated }}>
      {children}
    </AuthContext.Provider>
  );
};

// eslint-disable-next-line react-refresh/only-export-components
export const useAuth = () => useContext(AuthContext);
