import { useState, useEffect } from 'react';
import { Save, Check, Loader2 } from 'lucide-react';

interface AutoSaveIndicatorProps {
  lastSaved: Date | null;
  isSaving: boolean;
  onManualSave: () => void;
}

export default function AutoSaveIndicator({ lastSaved, isSaving, onManualSave }: AutoSaveIndicatorProps) {
  const [showToast, setShowToast] = useState(false);
  const [toastMessage, setToastMessage] = useState('');

  useEffect(() => {
    if (lastSaved && !isSaving) {
      setToastMessage(`✅ Auto-saved at ${lastSaved.toLocaleTimeString()}`);
      setShowToast(true);
      const timer = setTimeout(() => setShowToast(false), 3000);
      return () => clearTimeout(timer);
    }
  }, [lastSaved, isSaving]);

  const handleManualSave = () => {
    onManualSave();
    setToastMessage('💾 Sequence saved successfully');
    setShowToast(true);
    const timer = setTimeout(() => setShowToast(false), 3000);
    return () => clearTimeout(timer);
  };

  return (
    <>
      {/* Save Button and Indicator */}
      <div className="flex items-center gap-3">
        {/* Manual Save Button */}
        <button
          onClick={handleManualSave}
          disabled={isSaving}
          className="flex items-center gap-2 px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          title="Save Sequence"
        >
          {isSaving ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <Save className="w-4 h-4" />
          )}
          <span className="hidden sm:inline">Save Sequence</span>
        </button>

        {/* Auto-save status */}
        {lastSaved && (
          <div className="flex items-center gap-2 text-sm text-gray-500">
            {isSaving ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-blue-500" />
                <span>Saving...</span>
              </>
            ) : (
              <>
                <Check className="w-4 h-4 text-green-500" />
                <span className="hidden md:inline">
                  Last saved: {lastSaved.toLocaleTimeString()}
                </span>
              </>
            )}
          </div>
        )}
      </div>

      {/* Toast Notification */}
      {showToast && (
        <div className="fixed top-20 right-6 z-50 bg-white border border-gray-200 rounded-lg shadow-lg p-3 max-w-sm animate-in slide-in-from-top-2">
          <div className="flex items-center gap-2">
            <div className="text-sm font-medium text-gray-900">
              {toastMessage}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
