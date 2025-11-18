import { useMemo } from 'react';
import { Clock, Edit, Trash2, Mail, Calendar, GitBranch } from 'lucide-react';
import { EmailBlock, Connection, BLOCK_TYPE_CONFIG, CONDITION_TYPE_CONFIG } from '@/shared/types';

interface TimelineViewProps {
  blocks: EmailBlock[];
  connections: Connection[];
  onEditBlock: (block: EmailBlock) => void;
  onDeleteBlock: (blockId: string) => void;
}

interface TimelineNode {
  block: EmailBlock;
  children: TimelineNode[];
  depth: number;
  condition?: string;
  parentId?: string;
}

export default function TimelineView({ blocks, connections, onEditBlock, onDeleteBlock }: TimelineViewProps) {
  // Build hierarchical structure based on connections, not just delay
  const timelineStructure = useMemo(() => {
    if (!blocks.length) return [];

    // Create a map for quick lookups
    const blockMap = new Map(blocks.map(b => [b.id, b]));
    const childrenMap = new Map<string, Array<{ blockId: string; condition: string }>>();

    // Build parent-child relationships
    connections.forEach(conn => {
      if (!childrenMap.has(conn.source_block_id)) {
        childrenMap.set(conn.source_block_id, []);
      }
      childrenMap.get(conn.source_block_id)!.push({
        blockId: conn.target_block_id,
        condition: conn.condition_type
      });
    });

    // Find root nodes (blocks that are not targets of any connection)
    const targetBlocks = new Set(connections.map(c => c.target_block_id));
    const rootBlocks = blocks.filter(b => !targetBlocks.has(b.id));

    // If no connections exist, sort by delay as fallback
    if (connections.length === 0) {
      return blocks
        .sort((a, b) => a.send_delay_hours - b.send_delay_hours)
        .map(block => ({ block, children: [], depth: 0 }));
    }

    // Build tree structure recursively
    function buildTree(blockId: string, depth = 0, condition?: string, parentId?: string): TimelineNode | null {
      const block = blockMap.get(blockId);
      if (!block) return null;

      const children = childrenMap.get(blockId) || [];
      const childNodes = children
        .map(child => buildTree(child.blockId, depth + 1, child.condition, blockId))
        .filter(Boolean) as TimelineNode[];

      // Sort children by delay within the same branch
      childNodes.sort((a, b) => a.block.send_delay_hours - b.block.send_delay_hours);

      return {
        block,
        children: childNodes,
        depth,
        condition,
        parentId
      };
    }

    // Start with root blocks and build the tree
    const trees = rootBlocks
      .map(root => buildTree(root.id))
      .filter(Boolean) as TimelineNode[];

    // Sort root blocks by delay
    trees.sort((a, b) => a.block.send_delay_hours - b.block.send_delay_hours);

    return trees;
  }, [blocks, connections]);

  const formatDelay = (hours: number) => {
    if (hours === 0) return 'Immediately';
    if (hours < 24) return `${hours}h`;
    const days = Math.floor(hours / 24);
    const remainingHours = hours % 24;
    return remainingHours === 0 ? `${days}d` : `${days}d ${remainingHours}h`;
  };

  const formatDateTime = (hours: number, condition?: string) => {
    const baseTime = hours === 0 ? 'Send immediately' : `Send after ${formatDelay(hours)}`;
    if (condition && condition !== 'default') {
      const conditionConfig = CONDITION_TYPE_CONFIG[condition as keyof typeof CONDITION_TYPE_CONFIG];
      return `${baseTime} (${conditionConfig?.label || condition})`;
    }
    return baseTime;
  };

  const renderTimelineNode = (node: TimelineNode): React.ReactElement[] => {
    const { block, children, depth, condition } = node;
    const config = BLOCK_TYPE_CONFIG[block.type];
    const hasChildren = children.length > 0;
    const isConditionalBranch = condition && condition !== 'default';

    const elements: React.ReactElement[] = [];

    // Main block element
    elements.push(
      <div key={block.id} className="relative flex items-start gap-6" style={{ marginLeft: depth * 32 }}>
        {/* Connection line from parent */}
        {depth > 0 && (
          <>
            <div className="absolute -left-8 top-8 w-8 h-0.5 bg-gray-300"></div>
            <div className="absolute -left-8 top-0 w-0.5 h-8 bg-gray-300"></div>
          </>
        )}

        {/* Timeline marker */}
        <div className={`relative z-10 flex items-center justify-center w-16 h-16 bg-white border-4 rounded-full shadow-lg ${
          isConditionalBranch ? 'border-purple-500' : 'border-blue-500'
        }`}>
          <span className="text-2xl">{config.icon}</span>
        </div>

        {/* Content */}
        <div className="flex-1 bg-white rounded-xl shadow-sm border border-gray-200 p-6 hover:shadow-md transition-shadow">
          <div className="flex items-start justify-between mb-4">
            <div className="flex-1">
              <div className="flex items-center gap-3 mb-2">
                <span className={`px-3 py-1 rounded-full text-sm font-medium ${config.bgColor} ${config.color}`}>
                  {config.label}
                </span>
                <div className="flex items-center gap-2 text-sm text-gray-500">
                  <Calendar className="w-4 h-4" />
                  <span>{formatDateTime(block.send_delay_hours, condition)}</span>
                </div>
                {isConditionalBranch && (
                  <div className="flex items-center gap-2 text-sm text-purple-600">
                    <GitBranch className="w-4 h-4" />
                    <span className="font-medium">Conditional Branch</span>
                  </div>
                )}
              </div>
              
              <h3 className="text-lg font-semibold text-gray-900 mb-1">
                {block.name}
              </h3>
              
              {block.subject_line && (
                <p className="text-gray-600 mb-2">
                  <Mail className="w-4 h-4 inline-block mr-1" />
                  Subject: {block.subject_line}
                </p>
              )}
              
              {block.preview_text && (
                <p className="text-sm text-gray-500 line-clamp-2">
                  {block.preview_text}
                </p>
              )}
            </div>

            <div className="flex items-center gap-2 ml-4">
              <button
                onClick={() => onEditBlock(block)}
                className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
                title="Edit email"
              >
                <Edit className="w-4 h-4 text-gray-600" />
              </button>
              <button
                onClick={() => onDeleteBlock(block.id)}
                className="p-2 hover:bg-red-50 rounded-lg transition-colors"
                title="Delete email"
              >
                <Trash2 className="w-4 h-4 text-red-600" />
              </button>
            </div>
          </div>

          {/* Send delay info */}
          <div className="flex items-center justify-between text-sm">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2 text-blue-600">
                <Clock className="w-4 h-4" />
                <span>Send delay: {formatDelay(block.send_delay_hours)}</span>
              </div>
              
              {block.cta_text && (
                <div className="inline-block px-3 py-1 bg-blue-600 text-white text-xs rounded-full">
                  {block.cta_text}
                </div>
              )}
            </div>
            
            <span className="text-gray-400 font-medium">
              Depth {depth + 1}
            </span>
          </div>

          {/* Body preview */}
          {block.body_copy && (
            <div className="mt-4 p-3 bg-gray-50 rounded-lg">
              <p className="text-sm text-gray-700 line-clamp-3">
                {block.body_copy}
              </p>
            </div>
          )}
        </div>

        {/* Vertical line for children */}
        {hasChildren && (
          <div className="absolute left-8 top-16 w-0.5 bg-gray-300" style={{ height: 'calc(100% + 32px)' }}></div>
        )}
      </div>
    );

    // Add branch separator if there are multiple children
    if (children.length > 1) {
      elements.push(
        <div key={`separator-${block.id}`} className="relative" style={{ marginLeft: depth * 32 + 64 }}>
          <div className="h-8 flex items-center">
            <div className="flex-1 border-t-2 border-dashed border-gray-300"></div>
            <div className="px-3 bg-gray-100 rounded-full text-xs text-gray-600 font-medium">
              Branching Logic
            </div>
            <div className="flex-1 border-t-2 border-dashed border-gray-300"></div>
          </div>
        </div>
      );
    }

    // Recursively render children
    children.forEach((child) => {
      const childElements = renderTimelineNode(child);
      elements.push(...childElements);
    });

    return elements;
  };

  if (blocks.length === 0) {
    return (
      <div className="flex-1 h-full bg-gray-50 flex items-center justify-center">
        <div className="text-center p-8 max-w-md">
          <div className="text-6xl mb-4">⏰</div>
          <h3 className="text-xl font-bold text-gray-900 mb-2">
            Timeline View
          </h3>
          <p className="text-gray-600 mb-4">
            Add email blocks to see them arranged by logical flow structure. This view shows the sequence hierarchy and branching logic.
          </p>
          <div className="text-sm text-gray-500 space-y-1">
            <p>💡 Tip: Blocks are organized by flow relationships</p>
            <p>💡 Tip: Conditional branches are grouped under their parent</p>
            <p>💡 Tip: Timing delays are shown for each email</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 h-full bg-gray-50 overflow-y-auto">
      <div className="max-w-5xl mx-auto p-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <Clock className="w-6 h-6 text-blue-600" />
            <h2 className="text-2xl font-bold text-gray-900">Timeline View</h2>
          </div>
          <p className="text-gray-600">
            Your email sequence arranged by logical flow structure and timing
          </p>
        </div>

        {/* Legend */}
        <div className="mb-8 bg-blue-50 border border-blue-200 rounded-xl p-4">
          <h4 className="font-medium text-blue-900 mb-3">Timeline Legend</h4>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 border-2 border-blue-500 rounded-full bg-white"></div>
              <span className="text-blue-800">Standard Email</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 border-2 border-purple-500 rounded-full bg-white"></div>
              <span className="text-purple-800">Conditional Branch</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-1 border-t-2 border-dashed border-gray-300"></div>
              <span className="text-gray-700">Branch Separator</span>
            </div>
          </div>
        </div>

        {/* Timeline Structure */}
        <div className="relative space-y-8">
          {/* Main timeline line */}
          <div className="absolute left-8 top-0 bottom-0 w-0.5 bg-gradient-to-b from-blue-500 to-purple-500"></div>

          {/* Render timeline nodes */}
          {timelineStructure.map(tree => renderTimelineNode(tree))}

          {/* End marker */}
          <div className="relative flex items-start gap-6 mt-8">
            <div className="relative z-10 flex items-center justify-center w-16 h-16 bg-green-100 border-4 border-green-500 rounded-full shadow-lg">
              <span className="text-2xl">🎯</span>
            </div>
            
            <div className="flex-1 bg-gradient-to-r from-green-50 to-blue-50 rounded-xl border-2 border-dashed border-green-300 p-6">
              <h3 className="text-lg font-semibold text-green-900 mb-2">
                Sequence Complete
              </h3>
              <p className="text-green-700">
                Your email sequence ends here. Subscribers have completed the full journey through all branches!
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
