import { useState } from 'react';
import { X, ArrowRight, Zap } from 'lucide-react';
import { CONDITION_TYPE_CONFIG } from '@/shared/types';

interface ConnectionModalProps {
  sourceBlockName: string;
  targetBlockName: string;
  currentCondition: string;
  currentCustomLabel?: string;
  onClose: () => void;
  onSave: (conditionType: string, customLabel?: string) => void;
}

export default function ConnectionModal({ 
  sourceBlockName, 
  targetBlockName, 
  currentCondition,
  currentCustomLabel,
  onClose, 
  onSave 
}: ConnectionModalProps) {
  const [selectedCondition, setSelectedCondition] = useState(currentCondition);
  const [customLabel, setCustomLabel] = useState(currentCustomLabel || '');

  const handleSave = () => {
    onSave(selectedCondition, customLabel.trim() || undefined);
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4 overflow-y-auto">
      <div className="bg-white rounded-2xl max-w-2xl w-full shadow-2xl my-8 max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="bg-gradient-to-r from-blue-50 to-purple-50 border-b border-gray-200 p-6 flex-shrink-0">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-gradient-to-br from-blue-600 to-purple-600 rounded-xl flex items-center justify-center">
                <Zap className="w-5 h-5 text-white" />
              </div>
              <div>
                <h2 className="text-xl font-bold text-gray-900">
                  Connection Logic
                </h2>
                <p className="text-sm text-gray-600 mt-1">
                  Define when to send the next email
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

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto">
          {/* Connection Preview */}
          <div className="p-6 border-b border-gray-100">
            <div className="flex items-center justify-center gap-4 p-4 bg-gray-50 rounded-xl">
              <div className="px-4 py-2 bg-blue-100 text-blue-700 rounded-lg font-medium">
                {sourceBlockName}
              </div>
              <ArrowRight className="w-5 h-5 text-gray-400" />
              <div className="px-4 py-2 bg-green-100 text-green-700 rounded-lg font-medium">
                {targetBlockName}
              </div>
            </div>
          </div>

          {/* Condition Selection */}
          <div className="p-6">
            <h3 className="font-medium text-gray-900 mb-4">
              When should "{targetBlockName}" be sent?
            </h3>
            
            <div className="space-y-3">
              {Object.entries(CONDITION_TYPE_CONFIG).map(([conditionType, config]) => (
                <label
                  key={conditionType}
                  className={`flex items-center p-4 border-2 rounded-xl cursor-pointer transition-all ${
                    selectedCondition === conditionType
                      ? 'border-blue-500 bg-blue-50'
                      : 'border-gray-200 hover:border-gray-300'
                  }`}
                >
                  <input
                    type="radio"
                    name="condition"
                    value={conditionType}
                    checked={selectedCondition === conditionType}
                    onChange={(e) => setSelectedCondition(e.target.value)}
                    className="sr-only"
                  />
                  <div className="flex-1">
                    <div className="flex items-center gap-3">
                      <div className={`w-3 h-3 rounded-full ${
                        selectedCondition === conditionType ? 'bg-blue-500' : 'bg-gray-300'
                      }`}></div>
                      <span className={`font-medium ${config.color}`}>
                        {config.label}
                      </span>
                    </div>
                    <p className="text-sm text-gray-600 mt-1 ml-6">
                      {getConditionDescription(conditionType)}
                    </p>
                  </div>
                </label>
              ))}
            </div>

            {/* Custom Label Section */}
            <div className="mt-6 pt-6 border-t border-gray-200">
              <h4 className="font-medium text-gray-900 mb-3">
                Custom Connection Label (Optional)
              </h4>
              <p className="text-sm text-gray-600 mb-3">
                Add a custom label to describe this connection. This will appear on the connection arrow in your flow.
              </p>
              <input
                type="text"
                value={customLabel}
                onChange={(e) => setCustomLabel(e.target.value)}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="e.g., High Intent Users, After 3 Days, VIP Customers"
                maxLength={50}
              />
              <p className="text-xs text-gray-500 mt-1">
                {customLabel.length}/50 characters
              </p>
            </div>
          </div>
        </div>

        {/* Footer - Fixed at bottom */}
        <div className="border-t border-gray-200 p-6 flex justify-end gap-3 flex-shrink-0 bg-white">
          <button
            onClick={onClose}
            className="px-6 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            className="px-8 py-2 bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-lg hover:from-blue-700 hover:to-purple-700 transition-all"
          >
            Save Connection
          </button>
        </div>
      </div>
    </div>
  );
}

function getConditionDescription(conditionType: string): string {
  switch (conditionType) {
    case 'default':
      return 'Send immediately after the previous email (default flow)';
    case 'opened':
      return 'Send only if the previous email was opened';
    case 'clicked':
      return 'Send only if a link in the previous email was clicked';
    case 'not_opened':
      return 'Send only if the previous email was NOT opened';
    case 'not_clicked':
      return 'Send only if no links in the previous email were clicked';
    case 'purchased':
      return 'Send only if a purchase was made';
    case 'not_purchased':
      return 'Send only if no purchase was made';
    default:
      return 'Custom condition logic';
  }
}
