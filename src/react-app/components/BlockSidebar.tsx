import { useState } from 'react';
import { ChevronLeft, ChevronRight, Plus, Download, Wand2, Clock, Share2, Copy, Folder } from 'lucide-react';
import { EmailBlockTypeT, BLOCK_TYPE_CONFIG, Sequence } from '@/shared/types';
import { EMAIL_TEMPLATES, TEMPLATE_CATEGORIES } from '@/react-app/data/emailTemplates';

interface BlockSidebarProps {
  onAddBlock: (type: EmailBlockTypeT, useAI?: boolean) => void;
  isCollapsed: boolean;
  onToggle: () => void;
  selectedSequence: Sequence | null;
  onExport: () => void;
  onSaveTemplate?: () => void;
  onCloneSequence?: () => void;
  onSwitchToTimeline?: () => void;
  onLoadTemplate?: (templateId: string) => void;
}

export default function BlockSidebar({ onAddBlock, isCollapsed, onToggle, selectedSequence, onExport, onSaveTemplate, onCloneSequence, onSwitchToTimeline, onLoadTemplate }: BlockSidebarProps) {
  const [viewMode, setViewMode] = useState<'blocks' | 'tools' | 'templates'>('blocks');

  return (
    <div className={`bg-white border-r border-gray-200 flex flex-col transition-all duration-300 ${
      isCollapsed ? 'w-16' : 'w-80'
    }`}>
      {/* Header */}
      <div className="p-4 border-b border-gray-100 flex items-center justify-between">
        {!isCollapsed && (
          <div className="flex items-center gap-2">
            <h2 className="font-semibold text-gray-900">Toolkit</h2>
          </div>
        )}
        <button
          onClick={onToggle}
          className="p-2 rounded-lg hover:bg-gray-100 transition-colors"
        >
          {isCollapsed ? (
            <ChevronRight className="w-5 h-5 text-gray-600" />
          ) : (
            <ChevronLeft className="w-5 h-5 text-gray-600" />
          )}
        </button>
      </div>

      {/* Tab Navigation */}
      {!isCollapsed && (
        <div className="flex border-b border-gray-100">
          <button
            onClick={() => setViewMode('blocks')}
            className={`flex-1 px-3 py-2 text-xs font-medium border-b-2 transition-colors ${
              viewMode === 'blocks'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            Email Blocks
          </button>
          <button
            onClick={() => setViewMode('templates')}
            className={`flex-1 px-3 py-2 text-xs font-medium border-b-2 transition-colors ${
              viewMode === 'templates'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            Templates
          </button>
          <button
            onClick={() => setViewMode('tools')}
            className={`flex-1 px-3 py-2 text-xs font-medium border-b-2 transition-colors ${
              viewMode === 'tools'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            Tools
          </button>
        </div>
      )}

      {/* Content */}
      <div className="flex-1 overflow-y-auto">
       {viewMode === 'blocks' && (
  <div className="p-4 space-y-3">
    {/* AI Feature Info Banner */}
    {!isCollapsed && (
      <div className="bg-gradient-to-r from-purple-50 to-blue-50 border border-purple-200 rounded-lg p-3 mb-4 flex gap-2 items-center">
        <Wand2 className="w-4 h-4 text-purple-600" />
        <div className="flex-1 text-sm text-purple-900">
          Want instant email copy? Use <span className="font-semibold">"Generate Content with AI"</span> inside the <span className="font-semibold">edit block</span> modal!
        </div>
      </div>
    )}

    {/* Email Block Types (NO GENERATE AI BUTTON HERE) */}
    {Object.entries(BLOCK_TYPE_CONFIG).map(([type, config]) => (
      <div key={type}>
        <button
          onClick={() => onAddBlock(type as EmailBlockTypeT, false)}
          className={`w-full p-4 text-left rounded-xl border-2 transition-all hover:shadow-md group ${
            config.bgColor
          } ${config.borderColor} hover:border-opacity-60`}
        >
          <div className="flex items-center gap-3">
            <span className="text-2xl">{config.icon}</span>
            {!isCollapsed && (
              <div className="flex-1">
                <h3 className={`font-medium ${config.color}`}>
                  {config.label}
                </h3>
                <p className="text-xs text-gray-600 mt-1">
                  Add to your sequence
                </p>
              </div>
            )}
            {!isCollapsed && (
              <Plus className={`w-5 h-5 ${config.color} opacity-60 group-hover:opacity-100 transition-opacity`} />
            )}
          </div>
        </button>
        {/* NO AI BUTTON HERE */}
      </div>
    ))}
  </div>
)}


        {viewMode === 'templates' && (
          <div className="p-4 space-y-4">
            {/* Templates Header */}
            <div className="bg-gradient-to-r from-orange-50 to-red-50 border border-orange-200 rounded-lg p-3 mb-4">
              <div className="flex items-center gap-2 mb-2">
                <Folder className="w-4 h-4 text-orange-600" />
                <span className="text-sm font-medium text-orange-900">Pre-Built Sequences</span>
              </div>
              <p className="text-xs text-orange-700">
                Professional email templates ready to import and customize.
              </p>
            </div>

            {/* Template Categories */}
            <div className="space-y-4">
              {TEMPLATE_CATEGORIES.map((category) => {
                const categoryTemplates = EMAIL_TEMPLATES.filter(t => t.category === category.id);
                if (categoryTemplates.length === 0) return null;
                
                return (
                  <div key={category.id} className="space-y-2">
                    <div className="flex items-center gap-2 px-2">
                      <span className="text-lg">{category.icon}</span>
                      <h3 className="font-semibold text-gray-900 text-sm">{category.name}</h3>
                      <span className="text-xs text-gray-500">({categoryTemplates.length})</span>
                    </div>
                    <div className="space-y-2">
                      {categoryTemplates.map((template) => (
                        <button
                          key={template.id}
                          onClick={() => onLoadTemplate && onLoadTemplate(template.id)}
                          className={`w-full p-3 text-left rounded-lg border-2 transition-all hover:shadow-md ${
                            template.bgColor
                          } ${template.borderColor} hover:border-opacity-60`}
                        >
                          <div className="flex items-start gap-2">
                            <span className="text-xl">{template.icon}</span>
                            <div className="flex-1 min-w-0">
                              <h4 className={`font-medium ${template.color} text-sm`}>
                                {template.name}
                              </h4>
                              <p className="text-xs text-gray-600 mt-1 line-clamp-2">
                                {template.description}
                              </p>
                              <div className="flex items-center gap-2 mt-2">
                                <span className="px-2 py-0.5 bg-white/60 text-xs rounded">
                                  {template.blocks.length} emails
                                </span>
                              </div>
                            </div>
                          </div>
                        </button>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {viewMode === 'tools' && (
          <div className="p-4 space-y-4">
            {/* Export Tools */}
            <div className="space-y-3">
              <h3 className="font-medium text-gray-900 text-sm">Export & Share</h3>
              
              <button
                onClick={onExport}
                disabled={!selectedSequence}
                className="w-full p-4 text-left rounded-xl border-2 border-green-200 bg-green-50 hover:bg-green-100 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <div className="flex items-center gap-3">
                  <Download className="w-5 h-5 text-green-600" />
                  <div className="flex-1">
                    <h4 className="font-medium text-green-700">Export Sequence</h4>
                    <p className="text-xs text-green-600 mt-1">
                      Download as CSV, HTML, or text
                    </p>
                  </div>
                </div>
              </button>
            </div>

            {/* View Tools */}
            <div className="space-y-3">
              <h3 className="font-medium text-gray-900 text-sm">View Options</h3>
              
              <button 
                onClick={() => onSwitchToTimeline && onSwitchToTimeline()}
                disabled={!selectedSequence}
                className="w-full p-4 text-left rounded-xl border-2 border-blue-200 bg-blue-50 hover:bg-blue-100 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <div className="flex items-center gap-3">
                  <Clock className="w-5 h-5 text-blue-600" />
                  <div className="flex-1">
                    <h4 className="font-medium text-blue-700">Timeline View</h4>
                    <p className="text-xs text-blue-600 mt-1">
                      View sequence by logical flow
                    </p>
                  </div>
                </div>
              </button>
            </div>

            {/* Templates & Collaboration Layer */}
            <div className="space-y-3">
              <h3 className="font-medium text-gray-900 text-sm">Templates & Sharing</h3>
              
              <button 
                onClick={() => onSaveTemplate && onSaveTemplate()}
                disabled={!selectedSequence}
                className="w-full p-4 text-left rounded-xl border-2 border-purple-200 bg-purple-50 hover:bg-purple-100 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <div className="flex items-center gap-3">
                  <Share2 className="w-5 h-5 text-purple-600" />
                  <div className="flex-1">
                    <h4 className="font-medium text-purple-700">Save as Template</h4>
                    <p className="text-xs text-purple-600 mt-1">
                      Create reusable template
                    </p>
                  </div>
                </div>
              </button>

              <button 
                onClick={() => onCloneSequence && onCloneSequence()}
                disabled={!selectedSequence}
                className="w-full p-4 text-left rounded-xl border-2 border-green-200 bg-green-50 hover:bg-green-100 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <div className="flex items-center gap-3">
                  <Copy className="w-5 h-5 text-green-600" />
                  <div className="flex-1">
                    <h4 className="font-medium text-green-700">Clone Sequence</h4>
                    <p className="text-xs text-green-600 mt-1">
                      Duplicate current flow
                    </p>
                  </div>
                </div>
              </button>
            </div>

            {/* Sequence Info */}
            {selectedSequence && (
              <div className="space-y-3">
                <h3 className="font-medium text-gray-900 text-sm">Current Sequence</h3>
                <div className="p-3 bg-gray-50 rounded-lg">
                  <h4 className="font-medium text-gray-900 text-sm">{selectedSequence.name}</h4>
                  {selectedSequence.description && (
                    <p className="text-xs text-gray-600 mt-1">{selectedSequence.description}</p>
                  )}
                  <div className="text-xs text-gray-500 mt-2">
                    Created {new Date(selectedSequence.created_at).toLocaleDateString()}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Quick Tips */}
      {!isCollapsed && (
        <div className="p-4 border-t border-gray-100">
          <div className="bg-blue-50 rounded-lg p-3">
            <h4 className="text-sm font-medium text-blue-900 mb-1">💡 Quick Tips</h4>
            <ul className="text-xs text-blue-800 space-y-1">
              <li>• Drag blocks to reposition them</li>
              <li>• Connect blocks by dragging handles</li>
              <li>• Double-click to edit block content</li>
              <li>• Use AI for instant content generation</li>
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}
