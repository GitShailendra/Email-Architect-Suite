import { useState, useEffect, useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router';
import { useAuth } from '@getmocha/users-service/react';
import { Plus, Home, User, LogOut, Download, Loader2, Clock, GitBranch, Coins } from 'lucide-react';

import FlowBuilder from '@/react-app/components/FlowBuilder';
import BlockSidebar from '@/react-app/components/BlockSidebar';
import EmailBlockModal from '@/react-app/components/EmailBlockModal';
import AIContentModal from '@/react-app/components/AIContentModal';
import ExportModal from '@/react-app/components/ExportModal';
import ConnectionModal from '@/react-app/components/ConnectionModal';
import TimelineView from '@/react-app/components/TimelineView';
import SequenceSelector from '@/react-app/components/SequenceSelector';
import AutoSaveIndicator from '@/react-app/components/AutoSaveIndicator';
import TemplateModal from '@/react-app/components/TemplateModal';
import AccountSettingsModal from '@/react-app/components/AccountSettingsModal';
import EmailAuthForm from '@/react-app/components/EmailAuthForm';

import { useSequences, useSequenceData } from '@/react-app/hooks/useApi';
import { EmailBlock, EmailBlockTypeT, BLOCK_TYPE_CONFIG } from '@/shared/types';
import { EMAIL_TEMPLATES } from '@/react-app/data/emailTemplates';

export default function HomePage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { user, redirectToLogin, logout, isPending } = useAuth();
  
  const [selectedSequenceId, setSelectedSequenceId] = useState<string | null>(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [editingBlock, setEditingBlock] = useState<EmailBlock | null>(null);
  const [showExportModal, setShowExportModal] = useState(false);
  const [showAIModal, setShowAIModal] = useState(false);
  const [aiBlockType, setAIBlockType] = useState<EmailBlockTypeT | null>(null);
  const [showConnectionModal, setShowConnectionModal] = useState(false);
  const [connectionData, setConnectionData] = useState<{
    sourceId: string;
    targetId: string;
    sourceName: string;
    targetName: string;
    currentCondition: string;
    currentCustomLabel?: string;
  } | null>(null);
  const [viewMode, setViewMode] = useState<'flow' | 'timeline'>('flow');
  const [isSaving, setIsSaving] = useState(false);
  const [lastSaved, setLastSaved] = useState<Date | null>(null);
  const [showTemplateModal, setShowTemplateModal] = useState(false);
  const [showAccountSettings, setShowAccountSettings] = useState(false);
  const [creditsBalance, setCreditsBalance] = useState<number | null>(null);

  const { sequences, loading: sequencesLoading, createSequence, duplicateSequence } = useSequences();
  const {
    blocks,
    connections,
    createBlock,
    updateBlock,
    duplicateBlock,
    deleteBlock,
    createConnection,
    deleteConnection,
  } = useSequenceData(selectedSequenceId);

  // Auto-save timer - saves every 5 minutes
  useEffect(() => {
    if (!selectedSequenceId || !blocks || !connections) return;

    const autoSaveTimer = setInterval(() => {
      // Auto-save logic here - the data is already being saved through the API hooks
      setLastSaved(new Date());
    }, 300000); // Auto-save every 5 minutes

    return () => clearInterval(autoSaveTimer);
  }, [selectedSequenceId, blocks, connections]);

  // Get sequence from URL parameter
  useEffect(() => {
    const sequenceId = searchParams.get('sequence');
    if (sequenceId) {
      setSelectedSequenceId(sequenceId);
    }
  }, [searchParams]);

  // Fetch user credits
  useEffect(() => {
    if (!user) return;
    
    const fetchCredits = async () => {
      try {
        const response = await fetch('/api/users/me/credits');
        if (response.ok) {
          const data = await response.json();
          setCreditsBalance(data.credits_balance);
        }
      } catch (error) {
        console.error('Failed to fetch credits:', error);
      }
    };
    
    fetchCredits();
    // Refresh credits every 30 seconds
    const interval = setInterval(fetchCredits, 30000);
    return () => clearInterval(interval);
  }, [user]);

  const selectedSequence = sequences.find(s => s.id === selectedSequenceId) || null;

  const handleAddBlock = useCallback(async (type: EmailBlockTypeT, useAI: boolean = false) => {
    if (!selectedSequenceId) return;

    if (useAI) {
      setAIBlockType(type);
      setShowAIModal(true);
      return;
    }

    try {
      const config = BLOCK_TYPE_CONFIG[type];
      // Calculate position for new block
      const existingBlocks = blocks || [];
      let position_x = 300;
      let position_y = existingBlocks.length * 120 + 100;

      // If there are existing blocks, position the new one to the right
      if (existingBlocks.length > 0) {
        const lastBlock = existingBlocks[existingBlocks.length - 1];
        position_x = lastBlock.position_x + 350;
        position_y = lastBlock.position_y;
      }

      await createBlock(type, config.defaultName, position_x, position_y);
    } catch (error) {
      console.error('Failed to create block:', error);
      alert('Failed to create email block. Please try again.');
    }
  }, [selectedSequenceId, blocks, createBlock]);

  const handleUpdateBlock = useCallback(async (blockId: string, updates: Partial<EmailBlock>) => {
    try {
      setIsSaving(true);
      await updateBlock(blockId, updates);
    } catch (error) {
      console.error('Failed to update block:', error);
      alert('Failed to update email block. Please try again.');
    } finally {
      setIsSaving(false);
    }
  }, [updateBlock]);

  const handleDeleteBlock = useCallback(async (blockId: string) => {
    if (confirm('Are you sure you want to delete this email block?')) {
      try {
        await deleteBlock(blockId);
      } catch (error) {
        console.error('Failed to delete block:', error);
        alert('Failed to delete email block. Please try again.');
      }
    }
  }, [deleteBlock]);

  const handleDuplicateBlock = useCallback(async (block: EmailBlock) => {
    try {
      // Call the backend API to duplicate the block with all its latest content
      await duplicateBlock(block.id);
    } catch (error) {
      console.error('Failed to duplicate block:', error);
      alert('Failed to duplicate email block. Please try again.');
    }
  }, [duplicateBlock]);

  const handleCreateConnection = useCallback(async (sourceId: string, targetId: string) => {
    if (!selectedSequenceId) return;

    // Show connection modal for advanced logic
    const sourceBlock = (blocks || []).find((b: any) => b.id === sourceId);
    const targetBlock = (blocks || []).find((b: any) => b.id === targetId);
    
    if (sourceBlock && targetBlock) {
      setConnectionData({
        sourceId,
        targetId,
        sourceName: sourceBlock.name,
        targetName: targetBlock.name,
        currentCondition: 'default',
        currentCustomLabel: undefined
      });
      setShowConnectionModal(true);
    }
  }, [selectedSequenceId, blocks]);

  const handleDeleteConnection = useCallback(async (connectionId: string) => {
    try {
      await deleteConnection(connectionId);
    } catch (error) {
      console.error('Failed to delete connection:', error);
      alert('Failed to delete connection. Please try again.');
    }
  }, [deleteConnection]);

  const handleLogout = useCallback(async () => {
    try {
      await logout();
      navigate('/');
    } catch (error) {
      console.error('Logout failed:', error);
    }
  }, [logout, navigate]);

  const handleAIGenerate = useCallback(async (content: any) => {
    if (!selectedSequenceId || !aiBlockType) return;

    try {
      // Calculate position for new block
      const existingBlocks = blocks || [];
      let position_x = 300;
      let position_y = existingBlocks.length * 120 + 100;

      if (existingBlocks.length > 0) {
        const lastBlock = existingBlocks[existingBlocks.length - 1];
        position_x = lastBlock.position_x + 350;
        position_y = lastBlock.position_y;
      }

      const newBlock = await createBlock(aiBlockType, content.name, position_x, position_y);
      // Update the block with AI-generated content
      await updateBlock(newBlock.id, content);
      setShowAIModal(false);
      setAIBlockType(null);
    } catch (error) {
      console.error('Failed to create AI block:', error);
      alert('Failed to create email block. Please try again.');
    }
  }, [selectedSequenceId, aiBlockType, blocks, createBlock, updateBlock]);

  const handleSaveConnection = useCallback(async (conditionType: string, customLabel?: string) => {
    if (!connectionData || !selectedSequenceId) return;

    try {
      await createConnection(connectionData.sourceId, connectionData.targetId, conditionType, customLabel);
      setShowConnectionModal(false);
      setConnectionData(null);
    } catch (error) {
      console.error('Failed to create connection:', error);
      alert('Failed to create connection. Please try again.');
    }
  }, [connectionData, selectedSequenceId, createConnection]);

  const handleManualSave = useCallback(() => {
    // Manual save - the data is already being saved, just update the timestamp
    setLastSaved(new Date());
  }, []);

  const handleSaveTemplate = useCallback(() => {
    if (selectedSequence) {
      setShowTemplateModal(true);
    }
  }, [selectedSequence]);

  const handleCloneSequence = useCallback(async () => {
    if (!selectedSequenceId) return;
    
    try {
      const cloned = await duplicateSequence(selectedSequenceId);
      setSelectedSequenceId(cloned.id);
      // Update URL
      window.history.pushState({}, '', `/?sequence=${cloned.id}`);
    } catch (error) {
      console.error('Failed to clone sequence:', error);
      alert('Failed to clone sequence. Please try again.');
    }
  }, [selectedSequenceId, duplicateSequence]);

  const handleLoadTemplate = useCallback(async (templateId: string) => {
    try {
      const template = EMAIL_TEMPLATES.find(t => t.id === templateId);
      if (!template) {
        alert('Template not found');
        return;
      }

      // If no sequence is selected, create a new one
      if (!selectedSequenceId) {
        const newSequence = await createSequence(`${template.name}`, template.description);
        setSelectedSequenceId(newSequence.id);
        // Update URL
        window.history.pushState({}, '', `/?sequence=${newSequence.id}`);
      }
      
      // Calculate starting positions to avoid overlap with existing blocks
      const existingBlocks = blocks || [];
      let maxX = 0;
      let maxY = 0;
      
      if (existingBlocks.length > 0) {
        maxX = Math.max(...existingBlocks.map(b => b.position_x)) + 400;
        maxY = Math.max(...existingBlocks.map(b => b.position_y));
      }
      
      // Create blocks from template
      const createdBlocks = [];
      for (const blockTemplate of template.blocks) {
        const block = await createBlock(
          blockTemplate.type,
          blockTemplate.name,
          blockTemplate.position_x + maxX,
          blockTemplate.position_y + (existingBlocks.length > 0 ? maxY + 50 : 0)
        );
        
        // Update block with template content
        await updateBlock(block.id, {
          subject_line: blockTemplate.subject_line,
          preview_text: blockTemplate.preview_text,
          body_copy: blockTemplate.body_copy,
          cta_text: blockTemplate.cta_text,
          cta_url: blockTemplate.cta_url,
          send_delay_hours: blockTemplate.send_delay_hours,
        });
        
        createdBlocks.push(block);
      }

      // Create connections from template
      for (const connectionTemplate of template.connections) {
        const sourceBlock = createdBlocks[connectionTemplate.source_index];
        const targetBlock = createdBlocks[connectionTemplate.target_index];
        
        if (sourceBlock && targetBlock) {
          await createConnection(sourceBlock.id, targetBlock.id, connectionTemplate.condition_type);
        }
      }

    } catch (error) {
      console.error('Failed to load template:', error);
      alert('Failed to load template. Please try again.');
    }
  }, [selectedSequenceId, blocks, createSequence, createBlock, updateBlock, createConnection]);

  // Show loading spinner during auth check
  if (isPending) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="animate-spin mb-4">
            <Loader2 className="w-12 h-12 text-blue-600" />
          </div>
          <p className="text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  // Show login screen if not authenticated
if (!user) {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-white to-blue-50 flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl shadow-2xl max-w-md w-full p-8">
        <div className="text-center mb-8">
          <div className="w-16 h-16 bg-gradient-to-br from-blue-600 to-purple-600 rounded-2xl flex items-center justify-center mx-auto mb-4">
            <Plus className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-gray-900 mb-2">
            Email Architect Suite
          </h1>
          <p className="text-gray-600">
            Build powerful email sequences with visual flow builder and AI content generation
          </p>
        </div>

        <EmailAuthForm onSuccess={() => window.location.reload()} />

        <div className="relative my-6">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-gray-300"></div>
          </div>
          <div className="relative flex justify-center text-sm">
            <span className="px-2 bg-white text-gray-500">Or continue with</span>
          </div>
        </div>

        <button
          onClick={redirectToLogin}
          className="w-full bg-white border-2 border-gray-300 text-gray-700 py-3 px-4 rounded-lg hover:bg-gray-50 transition-all duration-200 font-medium flex items-center justify-center gap-2"
        >
          <svg className="w-5 h-5" viewBox="0 0 24 24">
            <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
            <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
            <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
            <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
          </svg>
          Sign in with Google
        </button>

        <div className="mt-8 pt-6 border-t border-gray-100">
          <div className="text-sm text-gray-500 space-y-2">
            <p>✨ AI-powered email content generation</p>
            <p>🎯 Visual drag-and-drop flow builder</p>
            <p>📊 Export to major email platforms</p>
            <p>🔄 Advanced branching logic</p>
          </div>
        </div>
      </div>
    </div>
  );
}


  return (
    <div className="h-screen flex flex-col bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200 px-6 py-4 flex-shrink-0">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-gradient-to-br from-blue-600 to-purple-600 rounded-lg flex items-center justify-center">
                <Plus className="w-5 h-5 text-white" />
              </div>
              <h1 className="text-xl font-bold text-gray-900">
                Email Architect Suite
              </h1>
            </div>

            <SequenceSelector
              sequences={sequences}
              selectedSequence={selectedSequence}
              onSelectSequence={(sequence: any) => setSelectedSequenceId(sequence.id)}
              onCreateSequence={async (name: string, description?: string) => {
                try {
                  const newSequence = await createSequence(name, description);
                  setSelectedSequenceId(newSequence.id);
                  // Update URL to reflect new sequence
                  window.history.pushState({}, '', `/?sequence=${newSequence.id}`);
                  return newSequence;
                } catch (error) {
                  console.error('Failed to create sequence:', error);
                  throw error; // Re-throw so SequenceSelector can handle the error
                }
              }}
              loading={sequencesLoading}
            />
          </div>

          <div className="flex items-center gap-4">
            {/* Credits Display */}
            {creditsBalance !== null && (
              <div className="flex items-center gap-2 px-3 py-2 bg-gradient-to-r from-yellow-50 to-orange-50 border border-yellow-200 rounded-lg">
                <Coins className="w-4 h-4 text-yellow-600" />
                <span className="text-sm font-semibold text-gray-900">
                  {creditsBalance.toLocaleString()}
                </span>
                <span className="text-xs text-gray-600">AI Credits</span>
              </div>
            )}

            {/* Auto-save indicator and manual save button */}
            {selectedSequence && (
              <AutoSaveIndicator
                lastSaved={lastSaved}
                isSaving={isSaving}
                onManualSave={handleManualSave}
              />
            )}

            {/* View Mode Toggle and Export */}
            <div className="flex items-center gap-2">
              <div className="flex bg-gray-100 rounded-lg p-1">
                <button
                  onClick={() => setViewMode('flow')}
                  className={`px-3 py-1 text-sm rounded transition-colors ${
                    viewMode === 'flow'
                      ? 'bg-white text-gray-900 shadow-sm'
                      : 'text-gray-600 hover:text-gray-900'
                  }`}
                >
                  <GitBranch className="w-4 h-4 inline-block mr-1" />
                  Flow
                </button>
                <button
                  onClick={() => setViewMode('timeline')}
                  className={`px-3 py-1 text-sm rounded transition-colors ${
                    viewMode === 'timeline'
                      ? 'bg-white text-gray-900 shadow-sm'
                      : 'text-gray-600 hover:text-gray-900'
                  }`}
                >
                  <Clock className="w-4 h-4 inline-block mr-1" />
                  Timeline
                </button>
              </div>
              
              <button
                onClick={() => setShowExportModal(true)}
                disabled={!selectedSequence}
                className="flex items-center gap-2 px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                title="Export your full sequence in multiple formats"
              >
                <Download className="w-4 h-4" />
                <span className="hidden sm:inline">Export Sequence</span>
              </button>
            </div>

            {/* User menu */}
            <div className="flex items-center gap-3">
              <button
                onClick={() => setShowAccountSettings(true)}
                className="flex items-center gap-2 text-sm text-gray-600 hover:text-gray-900 hover:bg-gray-100 px-2 py-1 rounded transition-colors"
                title="Account Settings"
              >
                <User className="w-4 h-4" />
                <span>{user.email}</span>
              </button>
              
              <button
                onClick={() => navigate('/dashboard')}
                className="p-2 rounded-lg hover:bg-gray-100 transition-colors"
                title="Dashboard"
              >
                <Home className="w-5 h-5 text-gray-600" />
              </button>
              
              <button
                onClick={handleLogout}
                className="p-2 rounded-lg hover:bg-gray-100 transition-colors"
                title="Logout"
              >
                <LogOut className="w-5 h-5 text-gray-600" />
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Sidebar */}
        <BlockSidebar
          onAddBlock={handleAddBlock}
          isCollapsed={sidebarCollapsed}
          onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
          selectedSequence={selectedSequence}
          onExport={() => setShowExportModal(true)}
          onSaveTemplate={handleSaveTemplate}
          onCloneSequence={handleCloneSequence}
          onSwitchToTimeline={() => setViewMode('timeline')}
          onLoadTemplate={handleLoadTemplate}
        />

        {/* Flow Builder */}
        <div className="flex-1 relative">
          {sequencesLoading ? (
            <div className="flex items-center justify-center h-full">
              <div className="text-center">
                <Loader2 className="w-12 h-12 text-blue-600 animate-spin mb-4" />
                <p className="text-gray-600">Loading sequence...</p>
              </div>
            </div>
          ) : !selectedSequenceId ? (
            <div className="flex items-center justify-center h-full">
              <div className="text-center p-8 max-w-md">
                <div className="text-6xl mb-4">🎯</div>
                <h3 className="text-xl font-bold text-gray-900 mb-2">
                  Select a Sequence
                </h3>
                <p className="text-gray-600 mb-6">
                  Choose an existing sequence from the dropdown above, or create a new one to start building your email flow.
                </p>
                <button
                  onClick={() => navigate('/dashboard')}
                  className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                >
                  Go to Dashboard
                </button>
              </div>
            </div>
          ) : viewMode === 'flow' ? (
            <FlowBuilder
              blocks={blocks || []}
              connections={connections || []}
              onUpdateBlock={handleUpdateBlock}
              onEditBlock={setEditingBlock}
              onDeleteBlock={handleDeleteBlock}
              onDuplicateBlock={handleDuplicateBlock}
              onCreateConnection={handleCreateConnection}
              onDeleteConnection={handleDeleteConnection}
            />
          ) : (
            <TimelineView
              blocks={blocks || []}
              connections={connections || []}
              onEditBlock={setEditingBlock}
              onDeleteBlock={handleDeleteBlock}
            />
          )}
        </div>
      </div>

      {/* Edit Block Modal */}
      {editingBlock && (
        <EmailBlockModal
          block={editingBlock}
          onClose={() => setEditingBlock(null)}
          onSave={handleUpdateBlock}
        />
      )}

      {/* AI Content Modal */}
      {showAIModal && aiBlockType && (
        <AIContentModal
          blockType={aiBlockType}
          onClose={() => {
            setShowAIModal(false);
            setAIBlockType(null);
          }}
          onGenerate={handleAIGenerate}
        />
      )}

      {/* Connection Modal */}
      {showConnectionModal && connectionData && (
        <ConnectionModal
          sourceBlockName={connectionData.sourceName}
          targetBlockName={connectionData.targetName}
          currentCondition={connectionData.currentCondition}
          currentCustomLabel={connectionData.currentCustomLabel}
          onClose={() => {
            setShowConnectionModal(false);
            setConnectionData(null);
          }}
          onSave={handleSaveConnection}
        />
      )}

      {/* Export Modal */}
      {showExportModal && selectedSequence && (
        <ExportModal
          sequence={selectedSequence}
          onClose={() => setShowExportModal(false)}
        />
      )}

      {/* Template Modal */}
      {showTemplateModal && selectedSequence && (
        <TemplateModal
          sequence={selectedSequence}
          onClose={() => setShowTemplateModal(false)}
        />
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
