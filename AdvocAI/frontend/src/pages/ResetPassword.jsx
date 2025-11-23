import React, { useState, useEffect } from "react";
import { useNavigate, Link, useLocation } from "react-router-dom";
import axios from '../api/axios';
import toast from 'react-hot-toast';
import { Button } from "@/Components/ui/Button";
import { Input } from "@/Components/ui/Input";
import { Label } from "@/Components/ui/Label";

const ResetPassword = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmNewPassword, setConfirmNewPassword] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    // Pre-fill email if passed from ForgotPassword page
    if (location.state && location.state.email) {
      setEmail(location.state.email);
    }
  }, [location.state]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    if (newPassword !== confirmNewPassword) {
      toast.error("New passwords do not match.");
      setLoading(false);
      return;
    }
    try {
      const response = await axios.post('/api/auth/reset-password/', {
        email,
        otp_code: otpCode,
        new_password: newPassword,
        new_password2: confirmNewPassword, // Backend expects new_password2 for validation
      });
      toast.success(response.data.message);
      navigate('/login');
    } catch (error) {
      console.error('Reset password failed:', error);
      toast.error(error.response?.data?.error || 'Failed to reset password.');
    } finally {
      setLoading(false);
    }
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
            <span className="text-primary text-sm font-semibold">Reset Password</span>
          </div>
          <h1 className="text-4xl font-extrabold text-foreground mb-2 bg-gradient-to-r from-foreground to-primary bg-clip-text text-transparent">
            Set New Password
          </h1>
          <p className="text-muted-foreground">Enter the OTP sent to your email and your new password.</p>
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
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={loading}
              className="bg-input border-border/50 text-foreground placeholder-muted-foreground focus:border-primary focus:ring-primary/20 transition-all duration-300"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="otpCode" className="text-foreground font-medium">OTP Code</Label>
            <Input
              id="otpCode"
              name="otpCode"
              type="text"
              placeholder="Enter OTP"
              required
              value={otpCode}
              onChange={(e) => setOtpCode(e.target.value)}
              disabled={loading}
              className="bg-input border-border/50 text-foreground placeholder-muted-foreground focus:border-primary focus:ring-primary/20 transition-all duration-300"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="newPassword" className="text-foreground font-medium">New Password</Label>
            <Input
              id="newPassword"
              name="newPassword"
              type="password"
              placeholder="Enter new password"
              required
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              disabled={loading}
              className="bg-input border-border/50 text-foreground placeholder-muted-foreground focus:border-primary focus:ring-primary/20 transition-all duration-300"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="confirmNewPassword" className="text-foreground font-medium">Confirm New Password</Label>
            <Input
              id="confirmNewPassword"
              name="confirmNewPassword"
              type="password"
              placeholder="Confirm new password"
              required
              value={confirmNewPassword}
              onChange={(e) => setConfirmNewPassword(e.target.value)}
              disabled={loading}
              className="bg-input border-border/50 text-foreground placeholder-muted-foreground focus:border-primary focus:ring-primary/20 transition-all duration-300"
            />
          </div>
          <Button 
            type="submit" 
            className="w-full bg-gradient-to-r from-primary to-secondary hover:from-primary/90 hover:to-secondary/90 text-foreground shadow-lg shadow-primary/50 hover:shadow-xl hover:shadow-primary/60 transition-all duration-300" 
            disabled={loading}
          >
            {loading ? 'Resetting Password...' : 'Reset Password'}
          </Button>
        </form>

        <div className="text-center text-sm text-muted-foreground">
          Remember your password?{" "}
          <Link to="/login" className="font-medium text-primary hover:text-primary/80 hover:underline transition-colors duration-200">
            Login
          </Link>
        </div>
      </div>
    </div>
  );
};

export default ResetPassword;