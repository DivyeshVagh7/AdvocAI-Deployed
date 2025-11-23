import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import axios from '../api/axios';
import toast from 'react-hot-toast';
import { useAuth } from '../context/AuthContext';
import { Button } from "@/Components/ui/Button";
import { Input } from "@/Components/ui/Input";
import { Label } from "@/Components/ui/Label";
import { GoogleLogin } from '@react-oauth/google'; // Import GoogleLogin

const Login = () => {
  const navigate = useNavigate();
  const { login } = useAuth();
  const [formData, setFormData] = useState({
    email: '',
    password: ''
  });
  const [loading, setLoading] = useState(false);

  const handleInputChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    await login(formData.email, formData.password);
    setLoading(false);
  };

  const handleGoogleSuccess = async (credentialResponse) => {
    setLoading(true);
    try {
      const token = credentialResponse.credential;
      const response = await axios.post('api/auth/google/', { token });
      
      // Use the login function from AuthContext to update the state
      await login(null, null, response.data.user, response.data.tokens);
      
    } catch (error) {
      console.error('Google login error:', error);
      toast.error(error.response?.data?.error || 'Google login failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleError = () => {
    console.log('Google Login Failed');
    toast.error('Google login failed. Please try again.');
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background relative overflow-hidden">
      <button
        type="button"
        onClick={() => navigate(-1)}
        className="absolute top-4 left-4 z-20 inline-flex items-center gap-2 px-4 py-2 rounded-full bg-card/50 hover:bg-card/70 text-muted-foreground border border-border/50 shadow-lg backdrop-blur-md transition-all duration-200"
      >
        <span className="text-xl leading-none">←</span>
        <span className="text-sm font-medium tracking-wide uppercase opacity-90">Go back</span>
      </button>
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-primary/10 via-transparent to-transparent"></div>
      <div className="w-full max-w-md p-8 space-y-6 bg-card/90 backdrop-blur-xl rounded-2xl shadow-2xl border border-border/50 relative z-10 animate-fade-in">
        <div className="text-center">
          <div className="inline-block mb-4 px-4 py-2 bg-primary/20 rounded-full border border-primary/30">
            <span className="text-primary text-sm font-semibold">Welcome Back</span>
          </div>
          <h1 className="text-4xl font-extrabold text-foreground mb-2 bg-gradient-to-r from-foreground to-primary bg-clip-text text-transparent">
            Login
          </h1>
          <p className="text-muted-foreground">Enter your email below to login to your account</p>
        </div>

        {/* Google Login Button */}
        <GoogleLogin
          onSuccess={handleGoogleSuccess}
          onError={handleGoogleError}
          useOneTap
          render={({ onClick }) => (
            <Button 
              variant="outline" 
              className="w-full border-2 border-border/50 hover:border-primary/50 hover:bg-primary/10 text-muted-foreground hover:text-foreground transition-all duration-300" 
              onClick={onClick} 
              disabled={loading}
            >
              <svg className="w-5 h-5 mr-2" viewBox="0 0 24 24">
                <path fill="currentColor" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                <path fill="currentColor" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                <path fill="currentColor" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                <path fill="currentColor" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
              </svg>
              Login with Google
            </Button>
          )}
        />

        <div className="relative">
          <div className="absolute inset-0 flex items-center">
            <span className="w-full border-t border-border/50" />
          </div>
          <div className="relative flex justify-center text-xs uppercase">
            <span className="bg-card/90 px-4 text-muted-foreground">
              Or continue with
            </span>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-5">
          <div className="space-y-2">
            <Label htmlFor="email" className="text-foreground font-medium">Email</Label>
            <Input
              id="email"
              name="email"
              type="email"
              placeholder="m@example.com"
              required
              value={formData.email}
              onChange={handleInputChange}
              disabled={loading}
              className="bg-input border-border/50 text-foreground placeholder-muted-foreground focus:border-primary focus:ring-primary/20 transition-all duration-300"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="password" className="text-foreground font-medium">Password</Label>
            <Input
              id="password"
              name="password"
              type="password"
              required
              value={formData.password}
              onChange={handleInputChange}
              disabled={loading}
              className="bg-input border-border/50 text-foreground placeholder-muted-foreground focus:border-primary focus:ring-primary/20 transition-all duration-300"
            />
          </div>
          <Button 
            type="submit" 
            className="w-full bg-gradient-to-r from-primary to-secondary hover:from-primary/90 hover:to-secondary/90 text-foreground shadow-lg shadow-primary/50 hover:shadow-xl hover:shadow-primary/60 transition-all duration-300" 
            disabled={loading}
          >
            {loading ? 'Logging in...' : 'Login'}
          </Button>
          <div className="text-right text-sm">
            <Link to="/forgot-password" className="font-medium text-primary hover:text-primary/80 hover:underline transition-colors duration-200">
              Forgot password?
            </Link>
          </div>
        </form>

        <div className="text-center text-sm text-muted-foreground">
          Don't have an account?{" "}
          <Link to="/signup" className="font-medium text-primary hover:text-primary/80 hover:underline transition-colors duration-200">
            Sign up
          </Link>
        </div>
      </div>
    </div>
  );
};

export default Login;