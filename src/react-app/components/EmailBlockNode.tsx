import { Handle, Position, NodeProps } from 'reactflow';
import { EmailBlock, BLOCK_TYPE_CONFIG } from '@/shared/types';
import { Clock, Edit, Trash2, StickyNote, Copy } from 'lucide-react';

interface EmailBlockNodeData extends EmailBlock {
  onEdit: (block: EmailBlock) => void;
  onDelete: (blockId: string) => void;
  onDuplicate: (block: EmailBlock) => void;
}

export default function EmailBlockNode({ data }: NodeProps<EmailBlockNodeData>) {
  const config = BLOCK_TYPE_CONFIG[data.type];
  
  const formatDelay = (hours: number) => {
    if (hours === 0) return 'Immediate';
    if (hours < 24) return `${hours}h`;
    const days = Math.floor(hours / 24);
    const remainingHours = hours % 24;
    return remainingHours === 0 ? `${days}d` : `${days}d ${remainingHours}h`;
  };

  return (
    <div className={`
      relative bg-white rounded-xl border-2 shadow-lg min-w-[280px] max-w-[320px]
      ${config.borderColor} hover:shadow-xl transition-all duration-200
    `}>
      <Handle
        type="target"
        position={Position.Top}
        className="w-3 h-3 bg-gray-400 border-2 border-white"
      />
      
      {/* Header */}
      <div className={`${config.bgColor} px-4 py-3 rounded-t-xl border-b ${config.borderColor}`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-lg">{config.icon}</span>
            <span className={`font-semibold ${config.color}`}>
              {config.label}
            </span>
          </div>
          <div className="flex items-center gap-1">
            <button
              onClick={() => data.onEdit(data)}
              className="p-1 hover:bg-white/50 rounded transition-colors"
              title="Edit block"
            >
              <Edit className="w-4 h-4 text-gray-600" />
            </button>
            <button
              onClick={() => data.onDuplicate(data)}
              className="p-1 hover:bg-blue-100 rounded transition-colors"
              title="Duplicate block"
            >
              <Copy className="w-4 h-4 text-blue-600" />
            </button>
            <button
              onClick={() => data.onDelete(data.id)}
              className="p-1 hover:bg-red-100 rounded transition-colors"
              title="Delete block"
            >
              <Trash2 className="w-4 h-4 text-red-600" />
            </button>
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="p-4 space-y-3">
        <div>
          <h3 className="font-semibold text-gray-900 truncate">
            {data.name}
          </h3>
          {data.subject_line && (
            <p className="text-sm text-gray-600 truncate mt-1">
              Subject: {data.subject_line}
            </p>
          )}
        </div>

        {data.preview_text && (
          <p className="text-xs text-gray-500 line-clamp-2">
            {data.preview_text}
          </p>
        )}

        {data.send_delay_hours > 0 && (
          <div className="flex items-center gap-2 text-xs text-gray-500">
            <Clock className="w-3 h-3" />
            <span>Delay: {formatDelay(data.send_delay_hours)}</span>
          </div>
        )}

        {data.cta_text && (
          <div className="mt-2">
            <div className="inline-block px-3 py-1 bg-blue-600 text-white text-xs rounded-full">
              {data.cta_text}
            </div>
          </div>
        )}

        {data.notes && (
          <div className="flex items-center gap-1 text-xs text-gray-500 mt-2">
            <StickyNote className="w-3 h-3" />
            <span className="line-clamp-1">Note: {data.notes}</span>
          </div>
        )}
      </div>

      <Handle
        type="source"
        position={Position.Bottom}
        className="w-3 h-3 bg-gray-400 border-2 border-white"
      />
    </div>
  );
}
