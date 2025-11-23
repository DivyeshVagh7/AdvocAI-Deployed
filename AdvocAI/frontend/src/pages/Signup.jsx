import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import axios from '../api/axios';
import toast from 'react-hot-toast';
import { Button } from "@/Components/ui/Button";
import { Input } from "@/Components/ui/Input";
import { Label } from "@/Components/ui/Label";

const Signup = () => {
  const navigate = useNavigate();
  const [accountType, setAccountType] = useState('client');
  const [formData, setFormData] = useState({
    name: '',
    username: '',
    email: '',
    password: '',
    password2: '',
    phone: '',
    license_number: '',
    bar_council_id: '',
    education: '',
    experience_years: '',
    law_firm: '',
    specializations: '',
    consultation_fee: '',
    bio: '',
    verification_documents: ''
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

    if (formData.password !== formData.password2) {
      toast.error("Passwords do not match.");
      setLoading(false);
      return;
    }

    try {
      const payload = {
        ...formData,
        role: accountType,
      };

      if (accountType === 'lawyer') {
        payload.experience_years = formData.experience_years ? Number(formData.experience_years) : 0;
        payload.specializations = formData.specializations
          ? formData.specializations.split(',').map(item => item.trim()).filter(Boolean)
          : [];
        payload.verification_documents = formData.verification_documents
          ? formData.verification_documents.split(',').map(item => item.trim()).filter(Boolean)
          : [];
      } else {
        [
          'license_number',
          'bar_council_id',
          'education',
          'experience_years',
          'law_firm',
          'specializations',
          'consultation_fee',
          'bio',
          'verification_documents',
        ].forEach((field) => delete payload[field]);
      }

      const response = await axios.post('api/auth/signup/', payload);
      toast.success(response.data.message);
      if (response.data.requires_verification) {
        navigate('/verify-otp', { state: { email: response.data.email } });
      } else {
        navigate('/login');
      }
    } catch (error) {
      console.error('Signup error:', error);
      console.error('Signup error details:', error.response?.data);
      toast.error(error.response?.data?.error || 'Signup failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleSignup = async () => {
    setLoading(true);
    toast.error('Google OAuth integration is required for this feature. The current dummy token is invalid.');
    setLoading(false);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background relative overflow-hidden py-8">
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
            <span className="text-primary text-sm font-semibold">Get Started</span>
          </div>
          <h1 className="text-4xl font-extrabold text-foreground mb-2 bg-gradient-to-r from-foreground to-primary bg-clip-text text-transparent">
            Create an account
          </h1>
          <p className="text-muted-foreground">Enter your information to create an account</p>
        </div>

        <div className="grid grid-cols-2 gap-2">
          <Button
            type="button"
            variant={accountType === 'client' ? 'default' : 'outline'}
            className="w-full"
            onClick={() => setAccountType('client')}
            disabled={loading}
          >
            I'm a client
          </Button>
          <Button
            type="button"
            variant={accountType === 'lawyer' ? 'default' : 'outline'}
            className="w-full"
            onClick={() => setAccountType('lawyer')}
            disabled={loading}
          >
            I'm a lawyer
          </Button>
        </div>

        <Button 
          variant="outline" 
          className="w-full border-2 border-border/50 hover:border-primary/50 hover:bg-primary/10 text-muted-foreground hover:text-foreground transition-all duration-300" 
          onClick={handleGoogleSignup} 
          disabled={loading}
        >
          <svg className="w-5 h-5 mr-2" viewBox="0 0 24 24">
            <path fill="currentColor" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
            <path fill="currentColor" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
            <path fill="currentColor" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
            <path fill="currentColor" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
          </svg>
          Sign up with Google
        </Button>

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
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="name" className="text-foreground font-medium">Name</Label>
              <Input 
                id="name" 
                name="name" 
                placeholder="John Doe" 
                required 
                value={formData.name} 
                onChange={handleInputChange} 
                disabled={loading}
                className="bg-input border-border/50 text-foreground placeholder-muted-foreground focus:border-primary focus:ring-primary/20 transition-all duration-300"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="username" className="text-foreground font-medium">Username</Label>
              <Input 
                id="username" 
                name="username" 
                placeholder="johndoe" 
                required 
                value={formData.username} 
                onChange={handleInputChange} 
                disabled={loading}
                className="bg-input border-border/50 text-foreground placeholder-muted-foreground focus:border-primary focus:ring-primary/20 transition-all duration-300"
              />
            </div>
          </div>
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
          <div className="space-y-2">
            <Label htmlFor="password2" className="text-foreground font-medium">Confirm Password</Label>
            <Input 
              id="password2" 
              name="password2" 
              type="password" 
              required 
              value={formData.password2} 
              onChange={handleInputChange} 
              disabled={loading}
              className="bg-input border-border/50 text-foreground placeholder-muted-foreground focus:border-primary focus:ring-primary/20 transition-all duration-300"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="phone" className="text-foreground font-medium">Phone (optional)</Label>
            <Input
              id="phone"
              name="phone"
              placeholder="+91-XXXXXXXXXX"
              value={formData.phone}
              onChange={handleInputChange}
              disabled={loading}
              className="bg-input border-border/50 text-foreground placeholder-muted-foreground focus:border-primary focus:ring-primary/20 transition-all duration-300"
            />
          </div>

          {accountType === 'lawyer' && (
            <div className="space-y-6 border border-border/60 rounded-xl p-4 bg-card/40">
              <div>
                <h2 className="text-lg font-semibold text-foreground">Professional Information</h2>
                <p className="text-xs text-muted-foreground">
                  Provide accurate information so our team can verify your credentials.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="license_number" className="text-foreground font-medium">License Number *</Label>
                  <Input
                    id="license_number"
                    name="license_number"
                    placeholder="State Bar License Number"
                    required={accountType === 'lawyer'}
                    value={formData.license_number}
                    onChange={handleInputChange}
                    disabled={loading}
                    className="bg-input border-border/50 text-foreground placeholder-muted-foreground focus:border-primary focus:ring-primary/20 transition-all duration-300"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="bar_council_id" className="text-foreground font-medium">Bar Council ID *</Label>
                  <Input
                    id="bar_council_id"
                    name="bar_council_id"
                    placeholder="Bar Council Registration ID"
                    required={accountType === 'lawyer'}
                    value={formData.bar_council_id}
                    onChange={handleInputChange}
                    disabled={loading}
                    className="bg-input border-border/50 text-foreground placeholder-muted-foreground focus:border-primary focus:ring-primary/20 transition-all duration-300"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="education" className="text-foreground font-medium">Education</Label>
                  <Input
                    id="education"
                    name="education"
                    placeholder="LLB, LLM..."
                    value={formData.education}
                    onChange={handleInputChange}
                    disabled={loading}
                    className="bg-input border-border/50 text-foreground placeholder-muted-foreground focus:border-primary focus:ring-primary/20 transition-all duration-300"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="experience_years" className="text-foreground font-medium">Years of Experience</Label>
                  <Input
                    id="experience_years"
                    name="experience_years"
                    type="number"
                    min="0"
                    placeholder="e.g. 5"
                    value={formData.experience_years}
                    onChange={handleInputChange}
                    disabled={loading}
                    className="bg-input border-border/50 text-foreground placeholder-muted-foreground focus:border-primary focus:ring-primary/20 transition-all duration-300"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="law_firm" className="text-foreground font-medium">Law Firm / Practice</Label>
                  <Input
                    id="law_firm"
                    name="law_firm"
                    placeholder="Firm name or Independent"
                    value={formData.law_firm}
                    onChange={handleInputChange}
                    disabled={loading}
                    className="bg-input border-border/50 text-foreground placeholder-muted-foreground focus:border-primary focus:ring-primary/20 transition-all duration-300"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="consultation_fee" className="text-foreground font-medium">Consultation Fee</Label>
                  <Input
                    id="consultation_fee"
                    name="consultation_fee"
                    placeholder="e.g. ₹1500/hour"
                    value={formData.consultation_fee}
                    onChange={handleInputChange}
                    disabled={loading}
                    className="bg-input border-border/50 text-foreground placeholder-muted-foreground focus:border-primary focus:ring-primary/20 transition-all duration-300"
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="specializations" className="text-foreground font-medium">Specializations</Label>
                <Input
                  id="specializations"
                  name="specializations"
                  placeholder="Separate with commas e.g. Corporate Law, Family Law"
                  value={formData.specializations}
                  onChange={handleInputChange}
                  disabled={loading}
                  className="bg-input border-border/50 text-foreground placeholder-muted-foreground focus:border-primary focus:ring-primary/20 transition-all duration-300"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="bio" className="text-foreground font-medium">Professional Bio</Label>
                <textarea
                  id="bio"
                  name="bio"
                  rows="4"
                  placeholder="Describe your experience, notable cases, or approach to clients."
                  value={formData.bio}
                  onChange={handleInputChange}
                  disabled={loading}
                  className="w-full rounded-md border border-border/50 bg-input text-foreground placeholder-muted-foreground focus:border-primary focus:ring-primary/20 transition-all duration-300 p-3"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="verification_documents" className="text-foreground font-medium">Verification Documents</Label>
                <Input
                  id="verification_documents"
                  name="verification_documents"
                  placeholder="Links to certifications or proofs (comma separated URLs)"
                  value={formData.verification_documents}
                  onChange={handleInputChange}
                  disabled={loading}
                  className="bg-input border-border/50 text-foreground placeholder-muted-foreground focus:border-primary focus:ring-primary/20 transition-all duration-300"
                />
              </div>
            </div>
          )}

          <Button 
            type="submit" 
            className="w-full bg-gradient-to-r from-primary to-secondary hover:from-primary/90 hover:to-secondary/90 text-foreground shadow-lg shadow-primary/50 hover:shadow-xl hover:shadow-primary/60 transition-all duration-300" 
            disabled={loading}
          >
            {loading ? 'Creating account...' : 'Create account'}
          </Button>
        </form>

        <div className="text-center text-sm text-muted-foreground">
          Already have an account?{" "}
          <Link to="/login" className="font-medium text-primary hover:text-primary/80 hover:underline transition-colors duration-200">
            Login
          </Link>
        </div>
      </div>
    </div>
  );
};

export default Signup;