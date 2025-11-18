import { useState, useCallback, useEffect } from 'react';
import { useNavigate } from 'react-router';
import { useAuth } from '@getmocha/users-service/react';
import { 
  Mail, 
  Plus, 
  FolderOpen, 
  Calendar, 
  Copy, 
  Trash2, 
  Download,
  LogOut,
  User,
  Settings,
  BarChart3,
  Play,
  Edit3
} from 'lucide-react';
import { useSequences } from '@/react-app/hooks/useApi';
import { Sequence } from '@/shared/types';
import PlaySequenceModal from '@/react-app/components/PlaySequenceModal';
import ExportModal from '@/react-app/components/ExportModal';
import AccountSettingsModal from '@/react-app/components/AccountSettingsModal';

export default function DashboardPage() {
  const navigate = useNavigate();
  const { user, logout, isPending } = useAuth();
  const { sequences, loading, createSequence, duplicateSequence, deleteSequence, refetch } = useSequences();

  // Fetch saved templates
  const fetchSavedTemplates = useCallback(async () => {
    if (!user) return;
    try {
      const response = await fetch('/api/user-templates');
      if (response.ok) {
        const templates = await response.json();
        setSavedTemplates(templates);
      }
    } catch (error) {
      console.error('Failed to fetch saved templates:', error);
    } finally {
      setLoadingTemplates(false);
    }
  }, [user]);

  // Load templates on component mount
  useEffect(() => {
    fetchSavedTemplates();
  }, [fetchSavedTemplates]);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newSequenceName, setNewSequenceName] = useState('');
  const [newSequenceDescription, setNewSequenceDescription] = useState('');
  const [showPlayModal, setShowPlayModal] = useState(false);
  const [showExportModal, setShowExportModal] = useState(false);
  const [selectedSequence, setSelectedSequence] = useState<Sequence | null>(null);
  const [savedTemplates, setSavedTemplates] = useState<any[]>([]);
  const [loadingTemplates, setLoadingTemplates] = useState(true);
  const [activeTab, setActiveTab] = useState<'sequences' | 'templates'>('sequences');
  const [showAccountSettings, setShowAccountSettings] = useState(false);
  const [showRenameModal, setShowRenameModal] = useState(false);
  const [renameSequence, setRenameSequence] = useState<Sequence | null>(null);
  const [renameSequenceName, setRenameSequenceName] = useState('');
  const [renameSequenceDesc, setRenameSequenceDesc] = useState('');

  const handleLogout = useCallback(async () => {
    try {
      await logout();
      navigate('/');
    } catch (error) {
      console.error('Logout failed:', error);
    }
  }, [logout, navigate]);

  const handleCreateSequence = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newSequenceName.trim()) {
      try {
        const newSequence = await createSequence(newSequenceName.trim(), newSequenceDescription.trim() || undefined);
        setNewSequenceName('');
        setNewSequenceDescription('');
        setShowCreateModal(false);
        navigate(`/?sequence=${newSequence.id}`);
      } catch (error) {
        console.error('Failed to create sequence:', error);
        alert('Failed to create sequence. Please try again.');
      }
    }
  };

  const handleDuplicateSequence = async (sequence: Sequence) => {
    try {
      const duplicatedSequence = await duplicateSequence(sequence.id);
      navigate(`/?sequence=${duplicatedSequence.id}`);
    } catch (error) {
      console.error('Failed to duplicate sequence:', error);
      alert('Failed to duplicate sequence. Please try again.');
    }
  };

  const handleDeleteSequence = async (sequenceId: string) => {
    if (confirm('Are you sure you want to delete this sequence? This action cannot be undone.')) {
      try {
        await deleteSequence(sequenceId);
      } catch (error) {
        console.error('Failed to delete sequence:', error);
        alert('Failed to delete sequence. Please try again.');
      }
    }
  };

  const handleRenameSequence = (sequence: Sequence) => {
    setRenameSequence(sequence);
    setRenameSequenceName(sequence.name);
    setRenameSequenceDesc(sequence.description || '');
    setShowRenameModal(true);
  };

  const handleUpdateSequence = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!renameSequence || !renameSequenceName.trim()) return;

    try {
      const response = await fetch(`/api/sequences/${renameSequence.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: renameSequenceName.trim(),
          description: renameSequenceDesc.trim() || undefined,
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to update sequence');
      }

      // Refresh sequences list
      await refetch();
      setShowRenameModal(false);
      setRenameSequence(null);
      setRenameSequenceName('');
      setRenameSequenceDesc('');
    } catch (error) {
      console.error('Failed to update sequence:', error);
      alert('Failed to update sequence. Please try again.');
    }
  };

  const handlePlaySequence = (sequence: Sequence) => {
    setSelectedSequence(sequence);
    setShowPlayModal(true);
  };

  const handleExportSequence = (sequence: Sequence) => {
    setSelectedSequence(sequence);
    setShowExportModal(true);
  };

  const handleDeleteTemplate = async (templateId: string) => {
    if (confirm('Are you sure you want to delete this template? This action cannot be undone.')) {
      try {
        const response = await fetch(`/api/user-templates/${templateId}`, {
          method: 'DELETE',
        });
        if (response.ok) {
          setSavedTemplates(prev => prev.filter(t => t.id !== templateId));
        }
      } catch (error) {
        console.error('Failed to delete template:', error);
        alert('Failed to delete template. Please try again.');
      }
    }
  };

  const handleLoadSavedTemplate = async (template: any) => {
    try {
      // Create a new sequence
      const newSequence = await createSequence(`${template.name} (From Template)`, template.description);
      
      // Note: We would need to implement the logic to recreate blocks and connections
      // For now, just navigate to the new sequence
      navigate(`/?sequence=${newSequence.id}`);
    } catch (error) {
      console.error('Failed to load saved template:', error);
      alert('Failed to load template. Please try again.');
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  };

  if (isPending) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="animate-spin mb-4">
            <Mail className="w-12 h-12 text-blue-600" />
          </div>
          <p className="text-gray-600">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  if (!user) {
    navigate('/');
    return null;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-white to-blue-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200 px-6 py-4">
        <div className="flex items-center justify-between max-w-7xl mx-auto">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-gradient-to-br from-blue-600 to-purple-600 rounded-xl flex items-center justify-center">
                <Mail className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-gray-900">
                  Email Architect Suite
                </h1>
                <p className="text-sm text-gray-600">
                  Dashboard
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <button
              onClick={() => setShowAccountSettings(true)}
              className="flex items-center gap-3 text-sm text-gray-600 hover:text-gray-900 hover:bg-gray-100 px-2 py-1 rounded transition-colors"
              title="Account Settings"
            >
              <User className="w-4 h-4" />
              <span>{user.email}</span>
            </button>
            
            <button
              onClick={() => navigate('/')}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
            >
              Flow Builder
            </button>
            
            <button
              onClick={handleLogout}
              className="p-2 text-gray-600 hover:text-gray-900 transition-colors"
              title="Logout"
            >
              <LogOut className="w-5 h-5" />
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto p-6">
        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <div className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center">
                <FolderOpen className="w-6 h-6 text-blue-600" />
              </div>
              <div>
                <p className="text-2xl font-bold text-gray-900">{sequences.length}</p>
                <p className="text-sm text-gray-600">Email Sequences</p>
              </div>
            </div>
          </div>
          
          <div className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center">
                <BarChart3 className="w-6 h-6 text-green-600" />
              </div>
              <div>
                <p className="text-2xl font-bold text-gray-900">
                  {sequences.reduce((acc, seq) => acc + (seq.created_at ? 1 : 0), 0)}
                </p>
                <p className="text-sm text-gray-600">Active Campaigns</p>
              </div>
            </div>
          </div>
          
          <div className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center">
                <Settings className="w-6 h-6 text-purple-600" />
              </div>
              <div>
                <p className="text-2xl font-bold text-gray-900">Premium</p>
                <p className="text-sm text-gray-600">Account Status</p>
              </div>
            </div>
          </div>
        </div>

        {/* Main Content Section */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-100">
          {/* Tabs */}
          <div className="border-b border-gray-100">
            <div className="flex">
              <button
                onClick={() => setActiveTab('sequences')}
                className={`flex-1 px-6 py-4 font-medium border-b-2 transition-colors ${
                  activeTab === 'sequences'
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}
              >
                <FolderOpen className="w-4 h-4 inline-block mr-2" />
                Your Sequences ({sequences.length})
              </button>
              <button
                onClick={() => setActiveTab('templates')}
                className={`flex-1 px-6 py-4 font-medium border-b-2 transition-colors ${
                  activeTab === 'templates'
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}
              >
                <Settings className="w-4 h-4 inline-block mr-2" />
                Saved Templates ({savedTemplates.length})
              </button>
            </div>
          </div>

          {activeTab === 'sequences' && (
            <div>
              <div className="p-6 border-b border-gray-100">
                <div className="flex items-center justify-between">
                  <h2 className="text-xl font-bold text-gray-900">Your Email Sequences</h2>
                  <button
                    onClick={() => setShowCreateModal(true)}
                    className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                  >
                    <Plus className="w-4 h-4" />
                    Create New Sequence
                  </button>
                </div>
              </div>

          {loading ? (
            <div className="p-12 text-center">
              <div className="animate-spin mb-4 mx-auto">
                <Mail className="w-8 h-8 text-blue-600" />
              </div>
              <p className="text-gray-600">Loading sequences...</p>
            </div>
          ) : sequences.length === 0 ? (
            <div className="p-12 text-center">
              <div className="w-16 h-16 bg-gray-100 rounded-xl flex items-center justify-center mx-auto mb-4">
                <FolderOpen className="w-8 h-8 text-gray-400" />
              </div>
              <h3 className="text-lg font-medium text-gray-900 mb-2">No sequences yet</h3>
              <p className="text-gray-600 mb-6">Create your first email sequence to get started</p>
              <button
                onClick={() => setShowCreateModal(true)}
                className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
              >
                Create First Sequence
              </button>
            </div>
          ) : (
            <div className="divide-y divide-gray-100">
              {sequences.map((sequence) => (
                <div key={sequence.id} className="p-6 hover:bg-gray-50 transition-colors">
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <h3 className="font-medium text-gray-900 mb-1">{sequence.name}</h3>
                      {sequence.description && (
                        <p className="text-sm text-gray-600 mb-2">{sequence.description}</p>
                      )}
                      <div className="flex items-center gap-4 text-xs text-gray-500">
                        <div className="flex items-center gap-1">
                          <Calendar className="w-3 h-3" />
                          Created {formatDate(sequence.created_at)}
                        </div>
                        <div className="flex items-center gap-1">
                          <Calendar className="w-3 h-3" />
                          Updated {formatDate(sequence.updated_at)}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => navigate(`/?sequence=${sequence.id}`)}
                        className="flex items-center gap-2 px-3 py-2 text-blue-600 hover:bg-blue-50 rounded-lg transition-colors text-sm font-medium"
                        title="Edit sequence"
                      >
                        <Edit3 className="w-4 h-4" />
                        Edit
                      </button>
                      <button
                        onClick={() => handleRenameSequence(sequence)}
                        className="flex items-center gap-2 px-3 py-2 text-green-600 hover:bg-green-50 rounded-lg transition-colors text-sm font-medium"
                        title="Rename sequence"
                      >
                        <Edit3 className="w-4 h-4" />
                        Rename
                      </button>
                      <button
                        onClick={() => handleExportSequence(sequence)}
                        className="flex items-center gap-2 px-3 py-2 text-purple-600 hover:bg-purple-50 rounded-lg transition-colors text-sm font-medium"
                        title="Export sequence in multiple formats"
                      >
                        <Download className="w-4 h-4" />
                        Export
                      </button>
                      <button
                        onClick={() => handlePlaySequence(sequence)}
                        className="flex items-center gap-2 px-3 py-2 text-green-600 hover:bg-green-50 rounded-lg transition-colors text-sm font-medium"
                        title="Send sequence via autoresponder"
                      >
                        <Play className="w-4 h-4" />
                        Play Sequence
                      </button>
                      <div className="w-px h-6 bg-gray-200"></div>
                      <button
                        onClick={() => handleDuplicateSequence(sequence)}
                        className="p-2 text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
                        title="Duplicate sequence"
                      >
                        <Copy className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => handleDeleteSequence(sequence.id)}
                        className="p-2 text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                        title="Delete sequence"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === 'templates' && (
        <div>
          <div className="p-6 border-b border-gray-100">
            <div className="flex items-center justify-between">
              <h2 className="text-xl font-bold text-gray-900">Your Saved Templates</h2>
              <p className="text-sm text-gray-500">Templates you've saved from your sequences</p>
            </div>
          </div>

          {loadingTemplates ? (
            <div className="p-12 text-center">
              <div className="animate-spin mb-4 mx-auto">
                <Settings className="w-8 h-8 text-blue-600" />
              </div>
              <p className="text-gray-600">Loading templates...</p>
            </div>
          ) : savedTemplates.length === 0 ? (
            <div className="p-12 text-center">
              <div className="w-16 h-16 bg-gray-100 rounded-xl flex items-center justify-center mx-auto mb-4">
                <Settings className="w-8 h-8 text-gray-400" />
              </div>
              <h3 className="text-lg font-medium text-gray-900 mb-2">No saved templates yet</h3>
              <p className="text-gray-600 mb-6">Create sequences and save them as templates for future use</p>
              <button
                onClick={() => setActiveTab('sequences')}
                className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
              >
                View Your Sequences
              </button>
            </div>
          ) : (
            <div className="divide-y divide-gray-100">
              {savedTemplates.map((template) => (
                <div key={template.id} className="p-6 hover:bg-gray-50 transition-colors">
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <h3 className="font-medium text-gray-900 mb-1">{template.name}</h3>
                      {template.description && (
                        <p className="text-sm text-gray-600 mb-2">{template.description}</p>
                      )}
                      <div className="flex items-center gap-4 text-xs text-gray-500">
                        <div className="flex items-center gap-1">
                          <Calendar className="w-3 h-3" />
                          Saved {formatDate(template.created_at)}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleLoadSavedTemplate(template)}
                        className="flex items-center gap-2 px-3 py-2 text-blue-600 hover:bg-blue-50 rounded-lg transition-colors text-sm font-medium"
                        title="Use this template"
                      >
                        <Plus className="w-4 h-4" />
                        Use Template
                      </button>
                      <button
                        onClick={() => handleDeleteTemplate(template.id)}
                        className="p-2 text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                        title="Delete template"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  </div>

      {/* Create Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl max-w-md w-full p-6">
            <h2 className="text-xl font-bold text-gray-900 mb-4">
              Create New Sequence
            </h2>
            
            <form onSubmit={handleCreateSequence} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Sequence Name *
                </label>
                <input
                  type="text"
                  value={newSequenceName}
                  onChange={(e) => setNewSequenceName(e.target.value)}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="e.g., Welcome Series, Product Launch"
                  required
                  autoFocus
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Description (optional)
                </label>
                <textarea
                  value={newSequenceDescription}
                  onChange={(e) => setNewSequenceDescription(e.target.value)}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="Briefly describe this email sequence..."
                  rows={3}
                />
              </div>

              <div className="flex justify-end gap-3 pt-4">
                <button
                  type="button"
                  onClick={() => {
                    setShowCreateModal(false);
                    setNewSequenceName('');
                    setNewSequenceDescription('');
                  }}
                  className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                >
                  Create Sequence
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Play Sequence Modal */}
      {showPlayModal && selectedSequence && (
        <PlaySequenceModal
          sequence={selectedSequence}
          onClose={() => {
            setShowPlayModal(false);
            setSelectedSequence(null);
          }}
        />
      )}

      {/* Export Modal */}
      {showExportModal && selectedSequence && (
        <ExportModal
          sequence={selectedSequence}
          onClose={() => {
            setShowExportModal(false);
            setSelectedSequence(null);
          }}
        />
      )}

      {/* Rename Sequence Modal */}
      {showRenameModal && renameSequence && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl max-w-md w-full p-6">
            <h2 className="text-xl font-bold text-gray-900 mb-4">
              Rename Sequence
            </h2>
            
            <form onSubmit={handleUpdateSequence} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Sequence Name *
                </label>
                <input
                  type="text"
                  value={renameSequenceName}
                  onChange={(e) => setRenameSequenceName(e.target.value)}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="e.g., Welcome Series, Product Launch"
                  required
                  autoFocus
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Description (optional)
                </label>
                <textarea
                  value={renameSequenceDesc}
                  onChange={(e) => setRenameSequenceDesc(e.target.value)}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="Briefly describe this email sequence..."
                  rows={3}
                />
              </div>

              <div className="flex justify-end gap-3 pt-4">
                <button
                  type="button"
                  onClick={() => {
                    setShowRenameModal(false);
                    setRenameSequence(null);
                    setRenameSequenceName('');
                    setRenameSequenceDesc('');
                  }}
                  className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                >
                  Update Sequence
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Account Settings Modal */}
      <AccountSettingsModal
        isOpen={showAccountSettings}
        onClose={() => setShowAccountSettings(false)}
        onLogout={handleLogout}
      />
    </div>
  );
}
