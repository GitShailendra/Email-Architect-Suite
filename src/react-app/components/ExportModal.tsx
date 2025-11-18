import { useState } from 'react';
import { X, Download, FileText, Code, Database, Clipboard, Check, ExternalLink } from 'lucide-react';
import { Sequence } from '@/shared/types';

interface ExportModalProps {
  sequence: Sequence;
  onClose: () => void;
}

const EXPORT_FORMATS = [
  {
    id: 'csv',
    name: 'CSV File',
    description: 'Spreadsheet format with all email data',
    icon: FileText,
    color: 'text-green-600',
    bgColor: 'bg-green-50',
    borderColor: 'border-green-200',
  },
  {
    id: 'html',
    name: 'HTML Export',
    description: 'Ready-to-import HTML for email platforms',
    icon: Code,
    color: 'text-blue-600',
    bgColor: 'bg-blue-50',
    borderColor: 'border-blue-200',
  },
  {
    id: 'txt',
    name: 'Plain Text',
    description: 'Simple text format for easy reading',
    icon: FileText,
    color: 'text-gray-600',
    bgColor: 'bg-gray-50',
    borderColor: 'border-gray-200',
  },
  {
    id: 'json',
    name: 'JSON Data',
    description: 'Structured data format for developers',
    icon: Database,
    color: 'text-purple-600',
    bgColor: 'bg-purple-50',
    borderColor: 'border-purple-200',
  },
];

const ESP_PLATFORMS = [
  {
    id: 'mailchimp',
    name: 'Mailchimp',
    logo: '🐵',
    description: 'Export compatible with Mailchimp automation',
    format: 'html',
  },
  {
    id: 'aweber',
    name: 'AWeber',
    logo: '📧',
    description: 'Export for AWeber autoresponder series',
    format: 'csv',
  },
  {
    id: 'getresponse',
    name: 'GetResponse',
    logo: '🚀',
    description: 'Export for GetResponse automation',
    format: 'html',
  },
  {
    id: 'activecampaign',
    name: 'ActiveCampaign',
    logo: '⚡',
    description: 'Export for ActiveCampaign sequences',
    format: 'csv',
  },
  {
    id: 'convertkit',
    name: 'ConvertKit',
    logo: '🎯',
    description: 'Export for ConvertKit email sequences',
    format: 'html',
  },
];

export default function ExportModal({ sequence, onClose }: ExportModalProps) {
  const [selectedFormat, setSelectedFormat] = useState<string>('csv');
  const [selectedESP, setSelectedESP] = useState<string>('');
  const [isExporting, setIsExporting] = useState(false);
  const [exportComplete, setExportComplete] = useState(false);
  const [activeTab, setActiveTab] = useState<'format' | 'esp'>('format');

  const handleExport = async (format: string, espOptimized?: string) => {
    setIsExporting(true);
    
    try {
      const response = await fetch(`/api/sequences/${sequence.id}/export`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          format,
          esp_platform: espOptimized 
        }),
      });

      if (!response.ok) {
        throw new Error('Export failed');
      }

      const data = await response.json();
      
      // Create and trigger download
      const blob = new Blob([data.data], { 
        type: format === 'json' ? 'application/json' : 'text/plain' 
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = data.filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      setExportComplete(true);
      setTimeout(() => {
        setExportComplete(false);
        onClose();
      }, 2000);
    } catch (error) {
      console.error('Export failed:', error);
      alert('Export failed. Please try again.');
    } finally {
      setIsExporting(false);
    }
  };

  const handleCopyToClipboard = async () => {
    try {
      const response = await fetch(`/api/sequences/${sequence.id}/export`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ format: 'txt' }),
      });

      if (!response.ok) {
        throw new Error('Failed to get content');
      }

      const data = await response.json();
      await navigator.clipboard.writeText(data.data);
      
      setExportComplete(true);
      setTimeout(() => setExportComplete(false), 2000);
    } catch (error) {
      console.error('Copy failed:', error);
      alert('Copy to clipboard failed. Please try again.');
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-2xl max-w-4xl w-full max-h-[90vh] overflow-hidden shadow-2xl">
        {/* Header */}
        <div className="bg-gradient-to-r from-purple-50 to-blue-50 border-b border-gray-200 p-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 bg-gradient-to-br from-purple-600 to-blue-600 rounded-xl flex items-center justify-center">
                <Download className="w-6 h-6 text-white" />
              </div>
              <div>
                <h2 className="text-xl font-bold text-gray-900">
                  Export Email Sequence
                </h2>
                <p className="text-sm text-gray-600 mt-1">
                  Export "{sequence.name}" in your preferred format
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

        {/* Tabs */}
        <div className="border-b border-gray-200">
          <div className="flex">
            <button
              onClick={() => setActiveTab('format')}
              className={`flex-1 px-6 py-3 font-medium border-b-2 transition-colors ${
                activeTab === 'format'
                  ? 'border-purple-500 text-purple-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              <FileText className="w-4 h-4 inline-block mr-2" />
              File Formats
            </button>
            <button
              onClick={() => setActiveTab('esp')}
              className={`flex-1 px-6 py-3 font-medium border-b-2 transition-colors ${
                activeTab === 'esp'
                  ? 'border-purple-500 text-purple-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              <ExternalLink className="w-4 h-4 inline-block mr-2" />
              ESP-Optimized
            </button>
          </div>
        </div>

        <div className="h-[60vh] overflow-y-auto p-6">
          {activeTab === 'format' && (
            <div className="space-y-6">
              {/* Quick Copy Option */}
              <div className="bg-blue-50 border border-blue-200 rounded-xl p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Clipboard className="w-5 h-5 text-blue-600" />
                    <div>
                      <h3 className="font-medium text-blue-900">Quick Copy</h3>
                      <p className="text-sm text-blue-700">Copy all emails to clipboard as text</p>
                    </div>
                  </div>
                  <button
                    onClick={handleCopyToClipboard}
                    disabled={isExporting}
                    className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50"
                  >
                    {exportComplete ? (
                      <Check className="w-4 h-4" />
                    ) : (
                      'Copy All'
                    )}
                  </button>
                </div>
              </div>

              {/* Export Formats */}
              <div className="space-y-4">
                <h3 className="font-medium text-gray-900">Choose Export Format</h3>
                <p className="text-sm text-gray-600">
                  Select the format that works best for your workflow. Each format includes email subject, preview text, body copy, CTA text, and CTA URL.
                </p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {EXPORT_FORMATS.map((format) => {
                    const Icon = format.icon;
                    return (
                      <div
                        key={format.id}
                        className={`p-4 border-2 rounded-xl cursor-pointer transition-all ${
                          selectedFormat === format.id
                            ? 'border-purple-500 bg-purple-50'
                            : 'border-gray-200 hover:border-gray-300'
                        }`}
                        onClick={() => setSelectedFormat(format.id)}
                      >
                        <div className="flex items-start gap-3">
                          <Icon className={`w-6 h-6 ${format.color}`} />
                          <div className="flex-1">
                            <h4 className="font-medium text-gray-900">{format.name}</h4>
                            <p className="text-sm text-gray-600 mt-1">{format.description}</p>
                          </div>
                          {selectedFormat === format.id && (
                            <div className="w-2 h-2 bg-purple-500 rounded-full mt-2"></div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'esp' && (
            <div className="space-y-6">
              <div className="bg-purple-50 border border-purple-200 rounded-xl p-4">
                <div className="flex items-center gap-2 mb-2">
                  <ExternalLink className="w-5 h-5 text-purple-600" />
                  <h3 className="font-medium text-purple-900">ESP-Optimized Export</h3>
                </div>
                <p className="text-sm text-purple-700">
                  Export formatted specifically for popular email service providers. Each platform has optimized formatting and structure.
                </p>
              </div>

              <div className="space-y-4">
                <h3 className="font-medium text-gray-900">Choose Platform</h3>
                <p className="text-sm text-gray-600">
                  Export formatted specifically for your email service provider. Each export includes all email content in the optimal format for that platform.
                </p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {ESP_PLATFORMS.map((esp) => (
                    <div
                      key={esp.id}
                      className={`p-4 border-2 rounded-xl cursor-pointer transition-all ${
                        selectedESP === esp.id
                          ? 'border-purple-500 bg-purple-50'
                          : 'border-gray-200 hover:border-gray-300'
                      }`}
                      onClick={() => setSelectedESP(esp.id)}
                    >
                      <div className="flex items-start gap-3">
                        <span className="text-2xl">{esp.logo}</span>
                        <div className="flex-1">
                          <h4 className="font-medium text-gray-900">{esp.name}</h4>
                          <p className="text-sm text-gray-600 mt-1">{esp.description}</p>
                          <span className="inline-block mt-2 px-2 py-1 bg-gray-100 text-xs text-gray-600 rounded">
                            {esp.format.toUpperCase()} format
                          </span>
                        </div>
                        {selectedESP === esp.id && (
                          <div className="w-2 h-2 bg-purple-500 rounded-full mt-2"></div>
                        )}
                      </div>
                    </div>
                  ))}
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
            Cancel
          </button>
          
          <button
            onClick={() => {
              if (activeTab === 'format') {
                handleExport(selectedFormat);
              } else {
                const esp = ESP_PLATFORMS.find(p => p.id === selectedESP);
                if (esp) {
                  handleExport(esp.format, selectedESP);
                }
              }
            }}
            disabled={isExporting || (activeTab === 'esp' && !selectedESP)}
            className="px-8 py-2 bg-gradient-to-r from-purple-600 to-blue-600 text-white rounded-lg hover:from-purple-700 hover:to-blue-700 transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
          >
            {isExporting ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                Exporting...
              </>
            ) : exportComplete ? (
              <>
                <Check className="w-4 h-4" />
                Downloaded!
              </>
            ) : (
              <>
                <Download className="w-4 h-4" />
                Download Export
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
