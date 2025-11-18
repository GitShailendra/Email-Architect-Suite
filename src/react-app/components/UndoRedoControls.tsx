import { Undo, Redo } from 'lucide-react';

interface UndoRedoControlsProps {
  canUndo: boolean;
  canRedo: boolean;
  onUndo: () => void;
  onRedo: () => void;
  hasUnsavedChanges?: boolean;
}

export default function UndoRedoControls({ 
  canUndo, 
  canRedo, 
  onUndo, 
  onRedo, 
  hasUnsavedChanges 
}: UndoRedoControlsProps) {
  return (
    <div className="flex items-center gap-2 bg-white border border-gray-200 rounded-lg shadow-sm p-2">
      <button
        onClick={onUndo}
        disabled={!canUndo}
        className={`p-2 rounded-lg transition-colors ${
          canUndo 
            ? 'hover:bg-gray-100 text-gray-700' 
            : 'text-gray-400 cursor-not-allowed'
        }`}
        title="Undo (Ctrl+Z)"
      >
        <Undo className="w-4 h-4" />
      </button>
      
      <div className="w-px h-6 bg-gray-300"></div>
      
      <button
        onClick={onRedo}
        disabled={!canRedo}
        className={`p-2 rounded-lg transition-colors ${
          canRedo 
            ? 'hover:bg-gray-100 text-gray-700' 
            : 'text-gray-400 cursor-not-allowed'
        }`}
        title="Redo (Ctrl+Y)"
      >
        <Redo className="w-4 h-4" />
      </button>

      {hasUnsavedChanges && (
        <>
          <div className="w-px h-6 bg-gray-300"></div>
          <div className="w-2 h-2 bg-orange-500 rounded-full" title="Unsaved changes"></div>
        </>
      )}
    </div>
  );
}
