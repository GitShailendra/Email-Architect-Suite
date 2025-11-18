import { useState } from 'react';
import { ChevronDown, Plus, FolderOpen } from 'lucide-react';
import { Sequence } from '@/shared/types';

interface SequenceSelectorProps {
  sequences: Sequence[];
  selectedSequence: Sequence | null;
  onSelectSequence: (sequence: Sequence) => void;
  onCreateSequence: (name: string, description?: string) => Promise<void>;
  loading: boolean;
}

export default function SequenceSelector({
  sequences,
  selectedSequence,
  onSelectSequence,
  onCreateSequence,
  loading
}: SequenceSelectorProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newSequenceName, setNewSequenceName] = useState('');
  const [newSequenceDescription, setNewSequenceDescription] = useState('');

  const handleCreateSequence = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newSequenceName.trim()) {
      try {
        await onCreateSequence(newSequenceName.trim(), newSequenceDescription.trim() || undefined);
        setNewSequenceName('');
        setNewSequenceDescription('');
        setShowCreateForm(false);
        setIsOpen(false);
      } catch (error) {
        console.error('Failed to create sequence:', error);
        alert('Failed to create sequence. Please try again.');
      }
    }
  };

  return (
    <div className="relative">
      {/* Selector Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-3 px-4 py-2 bg-white border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors min-w-[250px]"
      >
        <FolderOpen className="w-4 h-4 text-gray-500" />
        <span className="flex-1 text-left text-sm">
          {selectedSequence ? selectedSequence.name : 'Select a sequence...'}
        </span>
        <ChevronDown className={`w-4 h-4 text-gray-500 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      {/* Dropdown */}
      {isOpen && (
        <div className="absolute top-full left-0 mt-2 w-full bg-white border border-gray-200 rounded-lg shadow-lg z-20 max-h-80 overflow-y-auto">
          {/* Create New Button */}
          <button
            onClick={() => setShowCreateForm(true)}
            className="w-full flex items-center gap-3 px-4 py-3 hover:bg-blue-50 border-b border-gray-100 text-blue-600"
          >
            <Plus className="w-4 h-4" />
            <span className="text-sm font-medium">Create New Sequence</span>
          </button>

          {/* Sequences List */}
          {loading ? (
            <div className="p-4 text-center text-gray-500 text-sm">
              Loading sequences...
            </div>
          ) : sequences.length === 0 ? (
            <div className="p-4 text-center text-gray-500 text-sm">
              No sequences yet. Create your first one!
            </div>
          ) : (
            sequences.map((sequence) => (
              <button
                key={sequence.id}
                onClick={() => {
                  onSelectSequence(sequence);
                  setIsOpen(false);
                }}
                className={`w-full text-left p-4 hover:bg-gray-50 border-b border-gray-100 last:border-b-0 ${
                  selectedSequence?.id === sequence.id ? 'bg-blue-50' : ''
                }`}
              >
                <div className="font-medium text-gray-900 text-sm">{sequence.name}</div>
                {sequence.description && (
                  <div className="text-xs text-gray-600 mt-1 line-clamp-2">
                    {sequence.description}
                  </div>
                )}
                <div className="text-xs text-gray-500 mt-1">
                  Updated {new Date(sequence.updated_at).toLocaleDateString()}
                </div>
              </button>
            ))
          )}
        </div>
      )}

      {/* Create Form Modal */}
      {showCreateForm && (
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
                    setShowCreateForm(false);
                    setNewSequenceName('');
                    setNewSequenceDescription('');
                    setIsOpen(false);
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
    </div>
  );
}
