import { useState } from 'react';
import { X, Play, Settings, CheckCircle, Clock, AlertCircle, Pause, Square } from 'lucide-react';
import { Sequence } from '@/shared/types';

interface PlaySequenceModalProps {
  sequence: Sequence;
  onClose: () => void;
}

const AUTORESPONDER_PLATFORMS = [
  {
    id: 'mailchimp',
    name: 'Mailchimp',
    logo: '🐵',
    description: 'Connect to your Mailchimp account to send this sequence',
    requiresAuth: true,
  },
  {
    id: 'aweber',
    name: 'AWeber',
    logo: '📧',
    description: 'Send this sequence through AWeber autoresponder',
    requiresAuth: true,
  },
  {
    id: 'getresponse',
    name: 'GetResponse',
    logo: '🚀',
    description: 'Deploy this sequence to GetResponse automation',
    requiresAuth: true,
  },
  {
    id: 'activecampaign',
    name: 'ActiveCampaign',
    logo: '⚡',
    description: 'Connect to ActiveCampaign for advanced automation',
    requiresAuth: true,
  },
  {
    id: 'webhook',
    name: 'Custom Webhook',
    logo: '🔗',
    description: 'Send to any platform via custom API webhook',
    requiresAuth: false,
  },
];

interface SequenceStatus {
  blockId: string;
  blockName: string;
  status: 'pending' | 'sent' | 'failed';
  sentAt?: Date;
  recipients?: number;
}

export default function PlaySequenceModal({ sequence, onClose }: PlaySequenceModalProps) {
  const [selectedPlatform, setSelectedPlatform] = useState<string>('');
  const [step, setStep] = useState<'select' | 'authenticate' | 'configure' | 'running'>('select');
  const [apiKey, setApiKey] = useState('');
  const [selectedList, setSelectedList] = useState('');
  const [, setIsRunning] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  
  // Mock status data for demonstration
  const [sequenceStatus] = useState<SequenceStatus[]>([
    { blockId: '1', blockName: 'Welcome Email', status: 'sent', sentAt: new Date(), recipients: 125 },
    { blockId: '2', blockName: 'Follow-up Email', status: 'pending' },
    { blockId: '3', blockName: 'Special Offer', status: 'pending' },
  ]);

  const selectedPlatformData = AUTORESPONDER_PLATFORMS.find(p => p.id === selectedPlatform);

  const handleConnect = () => {
    if (!selectedPlatformData) return;
    
    if (selectedPlatformData.requiresAuth) {
      setStep('authenticate');
    } else {
      setStep('configure');
    }
  };

  const handleAuthenticate = () => {
    // Simulate authentication
    if (apiKey) {
      setStep('configure');
    }
  };

  const handleStartSequence = () => {
    setStep('running');
    setIsRunning(true);
  };

  const handlePauseSequence = () => {
    setIsPaused(!isPaused);
  };

  const handleStopSequence = () => {
    setIsRunning(false);
    setIsPaused(false);
    onClose();
  };

  const getStatusIcon = (status: SequenceStatus['status']) => {
    switch (status) {
      case 'sent':
        return <CheckCircle className="w-5 h-5 text-green-500" />;
      case 'pending':
        return <Clock className="w-5 h-5 text-gray-400" />;
      case 'failed':
        return <AlertCircle className="w-5 h-5 text-red-500" />;
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-2xl max-w-2xl w-full max-h-[90vh] overflow-hidden shadow-2xl">
        {/* Header */}
        <div className="bg-gradient-to-r from-purple-50 to-blue-50 border-b border-gray-200 p-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 bg-gradient-to-br from-purple-600 to-blue-600 rounded-xl flex items-center justify-center">
                <Play className="w-6 h-6 text-white" />
              </div>
              <div>
                <h2 className="text-xl font-bold text-gray-900">
                  Play Email Sequence
                </h2>
                <p className="text-sm text-gray-600 mt-1">
                  Connect and send "{sequence.name}" via autoresponder
                </p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-white/50 rounded-lg transition-colors"
            >
              <X className="w-6 h-6 text-gray-600" />
            </button>
          </div>
        </div>

        <div className="p-6 max-h-[70vh] overflow-y-auto">
          {step === 'select' && (
            <div className="space-y-6">
              <div className="bg-blue-50 border border-blue-200 rounded-xl p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Settings className="w-5 h-5 text-blue-600" />
                  <h3 className="font-medium text-blue-900">Choose Autoresponder</h3>
                </div>
                <p className="text-sm text-blue-700">
                  Select your email service provider to connect and send this sequence to your subscribers.
                </p>
              </div>

              <div className="space-y-4">
                <h3 className="font-medium text-gray-900">Available Platforms</h3>
                <div className="grid grid-cols-1 gap-4">
                  {AUTORESPONDER_PLATFORMS.map((platform) => (
                    <div
                      key={platform.id}
                      className={`p-4 border-2 rounded-xl cursor-pointer transition-all ${
                        selectedPlatform === platform.id
                          ? 'border-purple-500 bg-purple-50'
                          : 'border-gray-200 hover:border-gray-300'
                      }`}
                      onClick={() => setSelectedPlatform(platform.id)}
                    >
                      <div className="flex items-start gap-3">
                        <span className="text-2xl">{platform.logo}</span>
                        <div className="flex-1">
                          <h4 className="font-medium text-gray-900">{platform.name}</h4>
                          <p className="text-sm text-gray-600 mt-1">{platform.description}</p>
                          {platform.requiresAuth && (
                            <span className="inline-block mt-2 px-2 py-1 bg-orange-100 text-orange-700 text-xs rounded">
                              Requires API Key
                            </span>
                          )}
                        </div>
                        {selectedPlatform === platform.id && (
                          <div className="w-2 h-2 bg-purple-500 rounded-full mt-2"></div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {step === 'authenticate' && selectedPlatformData && (
            <div className="space-y-6">
              <div className="text-center">
                <span className="text-4xl mb-4 block">{selectedPlatformData.logo}</span>
                <h3 className="text-xl font-bold text-gray-900 mb-2">
                  Connect to {selectedPlatformData.name}
                </h3>
                <p className="text-gray-600">
                  Enter your API key to authenticate with {selectedPlatformData.name}
                </p>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    API Key
                  </label>
                  <input
                    type="password"
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                    placeholder="Enter your API key..."
                  />
                  <p className="text-sm text-gray-500 mt-1">
                    Find your API key in your {selectedPlatformData.name} account settings
                  </p>
                </div>
              </div>
            </div>
          )}

          {step === 'configure' && selectedPlatformData && (
            <div className="space-y-6">
              <div className="text-center">
                <span className="text-4xl mb-4 block">{selectedPlatformData.logo}</span>
                <h3 className="text-xl font-bold text-gray-900 mb-2">
                  Configure Sequence
                </h3>
                <p className="text-gray-600">
                  Choose the list or campaign to send this sequence to
                </p>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Select List/Campaign
                  </label>
                  <select
                    value={selectedList}
                    onChange={(e) => setSelectedList(e.target.value)}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                  >
                    <option value="">Choose a list...</option>
                    <option value="newsletter">Newsletter Subscribers</option>
                    <option value="prospects">Lead Prospects</option>
                    <option value="customers">Existing Customers</option>
                  </select>
                </div>

                <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                  <div className="flex items-start gap-2">
                    <AlertCircle className="w-5 h-5 text-yellow-600 flex-shrink-0 mt-0.5" />
                    <div>
                      <h4 className="font-medium text-yellow-800">Important</h4>
                      <p className="text-sm text-yellow-700 mt-1">
                        This will send emails to all subscribers in the selected list. Make sure you have permission to email these contacts.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {step === 'running' && (
            <div className="space-y-6">
              <div className="text-center">
                <div className={`w-16 h-16 mx-auto mb-4 rounded-full flex items-center justify-center ${
                  isPaused ? 'bg-yellow-100' : 'bg-green-100'
                }`}>
                  {isPaused ? (
                    <Pause className="w-8 h-8 text-yellow-600" />
                  ) : (
                    <Play className="w-8 h-8 text-green-600" />
                  )}
                </div>
                <h3 className="text-xl font-bold text-gray-900 mb-2">
                  {isPaused ? 'Sequence Paused' : 'Sequence Running'}
                </h3>
                <p className="text-gray-600">
                  {isPaused ? 'The sequence is paused. Resume to continue sending.' : 'Your email sequence is actively sending to subscribers.'}
                </p>
              </div>

              <div className="space-y-4">
                <h4 className="font-medium text-gray-900">Email Status</h4>
                {sequenceStatus.map((status) => (
                  <div key={status.blockId} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                    <div className="flex items-center gap-3">
                      {getStatusIcon(status.status)}
                      <div>
                        <h5 className="font-medium text-gray-900">{status.blockName}</h5>
                        {status.sentAt && (
                          <p className="text-sm text-gray-500">
                            Sent at {status.sentAt.toLocaleTimeString()}
                          </p>
                        )}
                      </div>
                    </div>
                    <div className="text-right">
                      {status.recipients && (
                        <p className="text-sm font-medium text-gray-900">{status.recipients} sent</p>
                      )}
                      <p className="text-xs text-gray-500 capitalize">{status.status}</p>
                    </div>
                  </div>
                ))}
              </div>

              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <h4 className="font-medium text-blue-900 mb-2">Summary Stats</h4>
                <div className="grid grid-cols-3 gap-4 text-sm">
                  <div>
                    <p className="text-blue-700 font-medium">125</p>
                    <p className="text-blue-600">Emails Sent</p>
                  </div>
                  <div>
                    <p className="text-blue-700 font-medium">Newsletter Subscribers</p>
                    <p className="text-blue-600">List Name</p>
                  </div>
                  <div>
                    <p className="text-blue-700 font-medium">{selectedPlatformData?.name}</p>
                    <p className="text-blue-600">Platform</p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="border-t border-gray-200 p-6 flex justify-between">
          <button
            onClick={onClose}
            className="px-6 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors"
          >
            {step === 'running' ? 'Close' : 'Cancel'}
          </button>
          
          {step === 'select' && (
            <button
              onClick={handleConnect}
              disabled={!selectedPlatform}
              className="px-8 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Connect Platform
            </button>
          )}

          {step === 'authenticate' && (
            <button
              onClick={handleAuthenticate}
              disabled={!apiKey}
              className="px-8 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Authenticate
            </button>
          )}

          {step === 'configure' && (
            <button
              onClick={handleStartSequence}
              disabled={!selectedList}
              className="px-8 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            >
              <Play className="w-4 h-4" />
              Start Sequence
            </button>
          )}

          {step === 'running' && (
            <div className="flex gap-2">
              <button
                onClick={handlePauseSequence}
                className="px-6 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 transition-colors flex items-center gap-2"
              >
                {isPaused ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
                {isPaused ? 'Resume' : 'Pause'}
              </button>
              <button
                onClick={handleStopSequence}
                className="px-6 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors flex items-center gap-2"
              >
                <Square className="w-4 h-4" />
                Stop
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
