import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from '../api/axios';
import toast from 'react-hot-toast';
import { useAuth } from '../context/AuthContext';
import { Card, CardContent, CardHeader, CardTitle } from "@/Components/ui/Card";
import { Button } from "@/Components/ui/Button";
import { MessageSquare, ArrowRight } from 'lucide-react';

const ChatList = () => {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [conversations, setConversations] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadConversations();
    // Refresh every 5 seconds
    const interval = setInterval(loadConversations, 5000);
    return () => clearInterval(interval);
  }, []);

  const loadConversations = async () => {
    try {
      console.log('Loading conversations for user:', user?.id);
      const response = await axios.get('api/auth/chat/conversations/');
      console.log('Conversations response:', response.data);
      setConversations(response.data || []);
    } catch (err) {
      console.error('Failed to load conversations:', err);
      console.error('Error details:', err.response?.data);
      toast.error(err.response?.data?.error || 'Failed to load conversations.');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="container mx-auto py-10 animate-fade-in">
        <div className="text-center text-gray-400">Loading conversations...</div>
      </div>
    );
  }

  return (
    <div className="container mx-auto py-10 animate-fade-in">
      <div className="text-center mb-10">
        <div className="inline-flex items-center gap-2 mb-3 px-3 py-1 bg-blue-500/10 rounded-full border border-blue-500/20">
          <span className="text-blue-400 text-xs font-medium">Messages</span>
        </div>
        <h1 className="text-4xl md:text-5xl font-bold text-white mb-3">
          Your Conversations
        </h1>
        <p className="text-gray-400 max-w-2xl mx-auto">
          Chat with lawyers and clients
        </p>
      </div>

      {conversations.length === 0 ? (
        <Card className="bg-gray-800/40 backdrop-blur-sm border border-gray-700/50">
          <CardContent className="p-10 text-center">
            <MessageSquare className="w-16 h-16 text-gray-500 mx-auto mb-4" />
            <p className="text-gray-400">No conversations yet.</p>
            <p className="text-gray-500 text-sm mt-2">
              Connect with a lawyer to start chatting.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {conversations.map((conv) => {
            const otherUser = conv.client?.id === user?.id ? conv.lawyer : conv.client;
            const lastMessage = conv.last_message;
            const unreadCount = conv.unread_count || 0;

            return (
              <Card
                key={conv.id}
                className="bg-gray-800/40 backdrop-blur-sm border border-gray-700/50 hover:border-gray-600 transition-all duration-200 cursor-pointer"
                onClick={() => navigate(`/chat/${conv.id}`)}
              >
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3">
                        <div className="w-12 h-12 bg-blue-600/20 border border-blue-500/30 rounded-full flex items-center justify-center">
                          <span className="text-blue-400 font-semibold">
                            {otherUser?.name?.split(' ').map(n => n[0]).join('') || 
                             otherUser?.username?.slice(0, 2).toUpperCase() || 'U'}
                          </span>
                        </div>
                        <div className="flex-1">
                          <h3 className="text-white font-semibold">
                            {otherUser?.name || otherUser?.username || 'Unknown User'}
                          </h3>
                          {lastMessage && (
                            <p className="text-gray-400 text-sm truncate">
                              {lastMessage.message_type === 'document' 
                                ? `📄 ${lastMessage.document_title || 'Document'}`
                                : lastMessage.message}
                            </p>
                          )}
                          {!lastMessage && (
                            <p className="text-gray-500 text-sm">No messages yet</p>
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      {unreadCount > 0 && (
                        <span className="bg-blue-600 text-white text-xs font-bold rounded-full w-6 h-6 flex items-center justify-center">
                          {unreadCount}
                        </span>
                      )}
                      <ArrowRight className="w-5 h-5 text-gray-400" />
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
};

export default ChatList;

