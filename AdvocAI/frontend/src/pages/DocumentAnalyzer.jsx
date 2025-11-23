import React, { useState, useEffect, useRef } from 'react';
import {
  Upload,
  Bot,
  MessageCircle,
  Send,
  FileText,
  Loader2,
  History,
  X,
  Sparkles,
  User,
  Copy,
  Check,
} from 'lucide-react';

import { uploadDocument as uploadDocumentApi, getUserSessions as getUserSessionsApi, getChatHistory as getChatHistoryApi, sendChatMessage as sendChatMessageApi, } from '../utils/api';

const DocumentAnalyzer = () => {
  const fileInputRef = useRef(null);
  const [uploadedFile, setUploadedFile] = useState(null);
  const [summary, setSummary] = useState('');
  const [sessionId, setSessionId] = useState(null);
  const [chatMessage, setChatMessage] = useState('');
  const [chatHistory, setChatHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState('');
  const [sessions, setSessions] = useState([]);
  const [loadingSessions, setLoadingSessions] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [dragActive, setDragActive] = useState(false);
  const [isSummaryCopied, setIsSummaryCopied] = useState(false); // New state for copy status


  const resetForNewDocument = () => {
    setUploadedFile(null);
    setSummary('');
    setSessionId(null);
    setChatHistory([]);
    setError('');

  };

  const handleCopySummary = () => {
    navigator.clipboard.writeText(summary);
    setIsSummaryCopied(true);
    setTimeout(() => setIsSummaryCopied(false), 2000); // Reset after 2 seconds
  };

  const handleFileUpload = async (event) => {
    const file = event.target.files?.[0] ?? null;
    if (!file) return;

    setUploadedFile(file);
    setError('');
    setUploading(true);
    setSummary('');

    try {
      const response = await uploadDocumentApi(file);

      // Accept multiple possible shapes from backend
      const receivedSummary = response?.summary ?? response?.data?.summary ?? '';
      const receivedSessionId = response?.session_id ?? response?.sessionId ?? null;

      // If backend didn't provide a session id, create a client-side one so chat works
      const finalSessionId = receivedSessionId ?? `local-${Date.now()}`;
      setSessionId(finalSessionId);

      if (receivedSummary) {
        setSummary(receivedSummary);
        setChatHistory([
          {
            id: Date.now(),
            sender: 'AdvocAI',
            message:
              "Hi! I've analyzed your document. Feel free to ask me any questions about the terms, risks, or anything else you'd like to understand better.",
            timestamp: new Date().toLocaleTimeString(),
          },
        ]);
      } else {
        // If there's no summary but upload succeeded, show a friendly placeholder
        setSummary(response?.summary_preview ?? response?.summaryPreview ?? 'No summary available');
        setChatHistory([
          {
            id: Date.now(),
            sender: 'AdvocAI',
            message: "Document uploaded successfully. Ask a question to start the analysis.",
            timestamp: new Date().toLocaleTimeString(),
          },
        ]);
      }
    } catch (err) {
      console.error(err);
      // better extraction of error text
      const message = err?.response?.data?.error || err?.message || 'Failed to upload document';
      setError(message);
      setUploadedFile(null);
    } finally {
      setUploading(false);
    }
  };

  const handleDragOver = (event) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = 'copy';
    setDragActive(true);
  };

  const handleDragLeave = (event) => {
    event.preventDefault();
    setDragActive(false);
  };

  const handleDrop = (event) => {
    event.preventDefault();
    setDragActive(false);
    const files = event.dataTransfer.files;
    if (files && files.length > 0) {
      const file = files[0];
      if (fileInputRef.current) {
        const dataTransfer = new DataTransfer();
        dataTransfer.items.add(file);
        fileInputRef.current.files = dataTransfer.files;
        // reuse same handler shape
        handleFileUpload({ target: { files: dataTransfer.files } });
      }
    }
  };

  const handleSendMessage = async () => {
    if (!chatMessage.trim() || !sessionId) return;

    const userMessage = chatMessage.trim();
    setChatMessage('');
    setLoading(true);

    const newUserMessage = {
      id: Date.now(),
      sender: 'User',
      message: userMessage,
      timestamp: new Date().toLocaleTimeString(),
    };

    setChatHistory((prev) => [...prev, newUserMessage]);

    try {
      const response = await sendChatMessageApi(sessionId, userMessage);
      const aiText = response?.response ?? response?.message ?? response?.text ?? response?.data?.text ?? '';

      if (aiText) {
        const aiMessage = {
          id: Date.now() + 1,
          sender: 'AdvocAI',
          message: aiText,
          timestamp: new Date().toLocaleTimeString(),
        };
        setChatHistory((prev) => [...prev, aiMessage]);
      }
    } catch (err) {
      console.error(err);
      const message = err?.response?.data?.error || err?.message || 'Failed to send message';
      setError(message);
      // remove the optimistic user message
      setChatHistory((prev) => prev.filter((m) => m.id !== newUserMessage.id));
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (event) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      handleSendMessage();
    }
  };

  useEffect(() => {
    fetchSessions();
  }, []);

  const fetchSessions = async () => {
    setLoadingSessions(true);
    try {
      const response = await getUserSessionsApi();
      const list = Array.isArray(response) ? response : response?.sessions ?? response?.data?.sessions ?? [];
      setSessions(list);
    } catch (err) {
      console.error('Failed to fetch sessions:', err);
    } finally {
      setLoadingSessions(false);
    }
  };

  const openSession = async (session) => {
    if (!session) return;
    setSessionId(session.id ?? session._id ?? `session-${Date.now()}`);
    setSidebarOpen(false);
    setLoading(true);
    try {
      const data = await getChatHistoryApi(session.id ?? session._id ?? session.sessionId);
      const sessionInfo = data?.session ?? data ?? {};
      const messagesRaw = data?.messages ?? data?.messages_list ?? [];

      const messages = (messagesRaw || []).map((m, idx) => ({
        id: m.id ?? m._id ?? idx + 1,
        sender: (m.sender || m.role || '').toLowerCase() === 'user' ? 'User' : 'AdvocAI',
        message: m.text || m.message || '',
        timestamp: m.timestamp ? new Date(m.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString(),
      }));

      setChatHistory(messages);
      const sessionSummary = sessionInfo.summary ?? session.summary ?? session.summary_preview ?? '';
      if (sessionSummary) setSummary(sessionSummary);
    } catch (err) {
      console.error(err);
      const message = err?.response?.data?.error || err?.message || 'Failed to load session';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return '';
    const date = new Date(dateString);
    if (Number.isNaN(date.getTime())) return dateString;

    const now = new Date();
    const diffMs = now - date;
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

    if (diffDays === 0) return 'Today';
    if (diffDays === 1) return 'Yesterday';
    if (diffDays < 7) return `${diffDays} days ago`;

    return date.toLocaleDateString();
  };

  return (
    <div className="flex h-[89vh] bg-background">
      {/* Animated background effects */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 -left-48 w-96 h-96 bg-primary/10 rounded-full blur-3xl animate-pulse" />
        <div
          className="absolute bottom-1/4 -right-48 w-96 h-96 bg-secondary/10 rounded-full blur-3xl animate-pulse"
          style={{ animationDelay: '1s' }}
        />
      </div>

      {/* Sidebar */}
      <div className={`${sidebarOpen ? 'w-80' : 'w-0'} transition-all duration-300 h-full relative z-10`}>
        <div className={`${sidebarOpen ? 'opacity-100' : 'opacity-0'} transition-opacity duration-300 bg-card/60 backdrop-blur-xl border-r border-border/50 flex flex-col h-full`}>
          {sidebarOpen && (
            <>
              <div className="p-6 border-b border-border/50 flex-shrink-0">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-gradient-to-br from-primary to-secondary rounded-lg">
                      <History className="w-5 h-5 text-foreground" />
                    </div>
                    <h2 className="text-lg font-semibold text-foreground">History</h2>
                  </div>
                  <button onClick={() => setSidebarOpen(false)} className="p-1.5 hover:bg-muted rounded-lg transition-colors">
                    <X className="w-5 h-5 text-muted-foreground" />
                  </button>
                </div>
                <p className="text-sm text-muted-foreground">Previous sessions</p>
              </div>

              <div className="h-[70vh] overflow-y-auto p-4 custom-scrollbar">
                {loadingSessions ? (
                  <div className="flex items-center justify-center py-12">
                    <Loader2 className="w-6 h-6 animate-spin text-primary" />
                  </div>
                ) : sessions.length > 0 ? (
                  <div className="space-y-2">
                    {sessions.map((session) => (
                      <button
                        key={session.id ?? session._id}
                        onClick={() => openSession(session)}
                        className={`w-full text-left p-4 rounded-xl border transition-all duration-200 ${
                          sessionId === (session.id ?? session._id)
                            ? 'bg-gradient-to-br from-primary/20 to-secondary/20 border-primary/50 shadow-lg shadow-primary/20'
                            : 'bg-card/40 border-border/50 hover:bg-card/60 hover:border-border'
                        }`}
                      >
                        <div className="flex items-start gap-3">
                          <FileText className="w-4 h-4 text-primary mt-0.5 flex-shrink-0" />
                          <div className="flex-1 min-w-0">
                            <p className="text-sm text-foreground font-medium line-clamp-2 mb-2">{session.summary_preview || session.title || 'Document Analysis'}</p>
                            <div className="flex items-center justify-between text-xs">
                              <span className="text-muted-foreground">{formatDate(session.created_at || session.createdAt || session.date)}</span>
                              {Number(session.message_count || session.messages_count || 0) > 0 && (
                                <span className="bg-primary/20 text-primary px-2 py-0.5 rounded-full">{session.message_count || session.messages_count}</span>
                              )}
                            </div>
                          </div>
                        </div>
                      </button>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-12">
                    <div className="p-4 bg-card/40 rounded-full w-16 h-16 mx-auto mb-4 flex items-center justify-center">
                      <History className="w-8 h-8 text-muted-foreground" />
                    </div>
                    <p className="text-muted-foreground text-sm mb-1">No previous sessions</p>
                    <p className="text-muted-foreground text-xs">Upload a document to start</p>
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>

      {/* Sidebar toggle button */}
      {!sidebarOpen && (
        <button
          onClick={() => setSidebarOpen(true)}
          className="fixed left-0 top-1/2 -translate-y-1/2 p-3 bg-gradient-to-r from-primary to-secondary text-foreground rounded-r-xl shadow-lg shadow-primary/20 hover:shadow-primary/40 transition-all duration-200 z-20"
        >
          <History className="w-5 h-5" />
        </button>
      )}

      {/* Main content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        <div className="max-w-7xl mx-auto p-6 lg:p-12 flex-1 flex flex-col w-full h-full">
          {/* Upload / Summary header */}
          {!summary ? (
            <div className="mb-8">
              <div
                className={`relative overflow-hidden rounded-2xl border-2 border-dashed transition-all duration-300 ${
                  dragActive ? 'border-primary bg-primary/10 scale-[1.02]' : uploadedFile ? 'border-accent/50 bg-card/40' : 'border-border/20 hover:border-border hover:bg-card/30'
                }`}
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                onClick={() => !uploading && fileInputRef.current && fileInputRef.current.click()}
              >
                <input
                  id="file-upload"
                  ref={fileInputRef}
                  type="file"
                  accept=".pdf,.docx,.txt"
                  onChange={handleFileUpload}
                  className="hidden"
                  disabled={uploading}
                />

                <div className="px-6 pts-8 sm:p-10 lg:p-12 text-center cursor-pointer">
                  {uploading ? (
                    <div className="space-y-4">
                      <div className="relative w-16 h-16 mx-auto">
                        <Loader2 className="w-16 h-16 text-primary animate-spin" />
                        <Sparkles className="w-6 h-6 text-secondary absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2" />
                      </div>
                      <div>
                        <p className="text-lg font-medium text-foreground mb-1">Analyzing your document...</p>
                        <p className="text-sm text-muted-foreground">This may take a moment</p>
                      </div>
                    </div>
                  ) : uploadedFile ? (
                    <div className="space-y-4">
                      <div className="p-4 bg-accent/20 rounded-full w-20 h-20 mx-auto flex items-center justify-center border border-accent/30">
                        <FileText className="w-10 h-10 text-accent" />
                      </div>
                      <div>
                        <p className="text-lg font-medium text-foreground mb-1">{uploadedFile.name}</p>
                        <p className="text-sm text-accent">✓ Ready for analysis</p>
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      <div className="relative w-20 h-20 mx-auto">
                        <div className="absolute inset-0 bg-gradient-to-br from-primary to-secondary rounded-2xl opacity-20 blur-xl" />
                        <div className="relative p-4 bg-gradient-to-br from-primary/20 to-secondary/20 rounded-2xl border border-primary/30">
                          <Upload className="w-12 h-12 text-primary" />
                        </div>
                      </div>
                      <div>
                        <p className="text-lg font-medium text-foreground mb-2">Drop your document here</p>
                        <p className="text-sm text-muted-foreground mb-4">or click to browse your files</p>
                        <div className="flex items-center justify-center gap-2 text-xs text-muted-foreground">
                          <span>Supports:</span>
                          <span className="px-2 py-1 bg-card/50 rounded">PDF</span>
                          <span className="px-2 py-1 bg-card/50 rounded">DOCX</span>
                          <span className="px-2 py-1 bg-card/50 rounded">TXT</span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                {error && (
                  <div className="mt-4 p-4 bg-destructive/10 border border-destructive/30 rounded-xl">
                    <p className="text-destructive text-sm">{error}</p>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="mb-8 flex items-center justify-between">
              <div className="text-left">
                <h2 className="text-xl font-semibold text-foreground">Summary & Q&A</h2>
                <p className="text-sm text-muted-foreground">Your analysis is ready. Ask follow-up questions or start a new summary.</p>
              </div>
              <button
                onClick={resetForNewDocument}
                className="px-4 py-2 bg-gradient-to-r from-primary to-secondary text-foreground rounded-xl font-medium hover:shadow-lg hover:shadow-primary/30 transition-all duration-200"
              >
                Summarize New Document
              </button>

            </div>
          )}

          {/* Analysis & Chat Grid */}
          {summary && (
            <div className="grid lg:grid-cols-5 gap-6 h-[60vh]">
              {/* Analysis Results */}
             

              {/* Chat Interface */}
              <div className="lg:col-span-3 flex flex-col h-[60vh]">
                <div className="bg-card/40 backdrop-blur-xl rounded-2xl border border-border/50 overflow-hidden flex flex-col h-full">
                  <div className="p-6 border-b border-border/50 bg-gradient-to-r from-primary/5 to-secondary/5 flex-shrink-0">
                    <div className="flex items-center gap-3 mb-2">
                      <div className="p-2 bg-gradient-to-br from-primary to-secondary rounded-lg">
                        <MessageCircle className="w-5 h-5 text-foreground" />
                      </div>
                      <h3 className="text-lg font-semibold text-foreground">Ask Questions</h3>
                    </div>
                    <p className="text-sm text-muted-foreground">Chat with AI about your document</p>
                  </div>

                  {/* Messages */}
                  <div className="flex-1 overflow-y-auto p-6 pt-8 space-y-4 custom-scrollbar">
                    {chatHistory.map((message) => (
                      <div key={message.id} className={`flex items-start gap-3 ${message.sender === 'User' ? 'justify-end' : 'justify-start'} animate-fade-in`}>
                        {message.sender !== 'User' && (
                          <div className="w-8 h-8 rounded-full bg-card flex items-center justify-center flex-shrink-0">
                            <Bot className="w-5 h-5 text-muted-foreground" />
                          </div>
                        )}
                        <div className={`max-w-[80%]`}>
                          <div className={`rounded-2xl px-4 py-3 ${
                            message.sender === 'User' ? 'bg-gradient-to-br from-primary to-secondary text-foreground shadow-lg shadow-primary/20' : 'bg-card/50 text-foreground border border-border/50'
                          }`}>
                            <p className="text-sm leading-relaxed whitespace-pre-wrap">{message.message}</p>
                          </div>
                        </div>
                        {message.sender === 'User' && (
                          <div className="w-8 h-8 rounded-full bg-primary flex items-center justify-center flex-shrink-0">
                            <User className="w-5 h-5 text-foreground" />
                          </div>
                        )}
                      </div>
                    ))}
                    {loading && (
                      <div className="flex justify-start">
                        <div className="bg-card/50 border border-border/50 px-4 py-3 rounded-2xl flex items-center gap-2">
                          <Loader2 className="w-4 h-4 animate-spin text-primary" />
                          <span className="text-sm text-muted-foreground">Thinking...</span>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Input */}
                  <div className="p-6 border-t border-border/50 bg-card/30 flex-shrink-0">
                    <div className="flex gap-3">
                      <input
                        type="text"
                        value={chatMessage}
                        onChange={(e) => setChatMessage(e.target.value)}
                        onKeyDown={handleKeyDown}
                        placeholder="Ask anything about your document..."
                        disabled={!sessionId || loading}
                        className="flex-1 px-4 py-3 bg-card/50 border border-border/50 rounded-xl text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent transition-all"
                      />
                      <button
                        onClick={handleSendMessage}
                        disabled={!sessionId || !chatMessage.trim() || loading}
                        className="px-6 py-3 bg-gradient-to-r from-primary to-secondary text-foreground rounded-xl font-medium hover:shadow-lg hover:shadow-primary/30 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 flex items-center gap-2"
                      >
                        {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <><Send className="w-5 h-5" /><span>Send</span></>}
                      </button>
                    </div>
                  </div>
                </div>
              </div>

               <div className="lg:col-span-2 flex flex-col min-h-0">
                <div className="bg-card/40 backdrop-blur-xl rounded-2xl border border-border/50 overflow-hidden flex flex-col">
                  <div className="p-6 border-b border-border/50 bg-gradient-to-r from-primary/5 to-secondary/5 flex-shrink-0">
                    <div className="flex items-center justify-between mb-2"> {/* Added justify-between here */}
                      <div className="flex items-center gap-3">
                        <div className="p-2 bg-gradient-to-br from-primary to-secondary rounded-lg">
                          <Bot className="w-5 h-5 text-foreground" />
                        </div>
                        <h3 className="text-lg font-semibold text-foreground">Analysis</h3>
                      </div>
                      <button
                        onClick={handleCopySummary}
                        className="px-3 py-1.5 bg-gradient-to-r from-primary to-secondary text-foreground rounded-lg font-medium hover:shadow-lg hover:shadow-primary/30 transition-all duration-200 flex items-center gap-2 text-sm"
                      >
                        {isSummaryCopied ? (
                          <>
                            <Check className="w-4 h-4" />
                            <span>Copied!</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-4 h-4" />
                            <span>Copy Analysis</span>
                          </>
                        )}
                      </button>
                    </div>
                    <p className="text-sm text-muted-foreground">AI-generated insights</p>
                  </div>
                  <div className="p-6 flex-1 overflow-y-auto custom-scrollbar">
                    <p className="text-muted-foreground leading-relaxed whitespace-pre-wrap mb-4">{summary}</p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default DocumentAnalyzer;
