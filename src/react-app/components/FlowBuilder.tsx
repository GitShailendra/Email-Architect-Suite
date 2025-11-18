import { useCallback, useMemo, useEffect, useRef } from 'react';
import ReactFlow, {
  Node,
  Edge,
  Connection,
  useNodesState,
  useEdgesState,
  Controls,
  Background,
  MiniMap,
  BackgroundVariant,
} from 'reactflow';
import 'reactflow/dist/style.css';

import EmailBlockNode from './EmailBlockNode';
import UndoRedoControls from './UndoRedoControls';
import useUndoRedo from '@/react-app/hooks/useUndoRedo';
import { EmailBlock, Connection as DBConnection, BLOCK_TYPE_CONFIG, CONDITION_TYPE_CONFIG } from '@/shared/types';

const nodeTypes = {
  emailBlock: EmailBlockNode,
};

interface FlowBuilderProps {
  blocks: EmailBlock[];
  connections: DBConnection[];
  onUpdateBlock: (blockId: string, updates: { position_x: number; position_y: number }) => void;
  onEditBlock: (block: EmailBlock) => void;
  onDeleteBlock: (blockId: string) => void;
  onDuplicateBlock: (block: EmailBlock) => void;
  onCreateConnection: (sourceId: string, targetId: string) => void;
  onDeleteConnection: (connectionId: string) => void;
}

interface FlowState {
  blocks: EmailBlock[];
  connections: DBConnection[];
}

export default function FlowBuilder({
  blocks,
  connections,
  onUpdateBlock,
  onEditBlock,
  onDeleteBlock,
  onDuplicateBlock,
  onCreateConnection,
  onDeleteConnection,
}: FlowBuilderProps) {
  // Initialize undo/redo state
  const {
    state: flowState,
    setState: setFlowState,
    undo,
    redo,
    canUndo,
    canRedo,
    reset,
    hasUnsavedChanges
  } = useUndoRedo<FlowState>({
    blocks: blocks || [],
    connections: connections || [],
  });

  // Track the previous block and connection count to detect when to reset history
  const prevBlockCountRef = useRef<number>(0);
  const prevConnectionCountRef = useRef<number>(0);
  const initializedRef = useRef(false);
  const isInternalUpdateRef = useRef(false);

  useEffect(() => {
  // Skip if this is an internal update (from undo/redo or drag)
  if (isInternalUpdateRef.current) {
    isInternalUpdateRef.current = false;
    return;
  }

  const isInitialLoad = !initializedRef.current;
  const currentBlockCount = blocks?.length || 0;
  const currentConnectionCount = connections?.length || 0;
  
  // Only reset on initial load
  if (isInitialLoad) {
    const newState = {
      blocks: blocks || [],
      connections: connections || [],
    };
    reset(newState);
    prevBlockCountRef.current = currentBlockCount;
    prevConnectionCountRef.current = currentConnectionCount;
    initializedRef.current = true;
    return;
  }

  // Check if counts changed (new block/connection added or deleted externally)
  const blocksChanged = currentBlockCount !== prevBlockCountRef.current;
  const connectionsChanged = currentConnectionCount !== prevConnectionCountRef.current;
  
  // Only update if count changed (external add/delete from API)
  if (blocksChanged || connectionsChanged) {
    setFlowState({
      blocks: blocks || [],
      connections: connections || [],
    });
    prevBlockCountRef.current = currentBlockCount;
    prevConnectionCountRef.current = currentConnectionCount;
  }
}, [blocks, connections, reset, setFlowState]);

  // Use flow state for current blocks and connections
  const currentBlocks = flowState.blocks;
  const currentConnections = flowState.connections;
  // Track if we're in the middle of applying undo/redo to prevent backend sync
  // const isApplyingHistoryRef = useRef(false);

  // Handle block deletion with undo/redo
  const handleDeleteBlock = useCallback((blockId: string) => {
  isInternalUpdateRef.current = true; // Mark as internal update
  
  setFlowState((prevState) => ({
    blocks: prevState.blocks.filter(block => block.id !== blockId),
    connections: prevState.connections.filter(conn => 
      conn.source_block_id !== blockId && conn.target_block_id !== blockId
    ),
  }));
  
  // Always call backend API for delete
  onDeleteBlock(blockId);
}, [setFlowState, onDeleteBlock]);

const handleDeleteConnection = useCallback((connectionId: string) => {
  isInternalUpdateRef.current = true; // Mark as internal update
  
  setFlowState((prevState) => ({
    ...prevState,
    connections: prevState.connections.filter(conn => conn.id !== connectionId),
  }));
  
  // Always call backend API for delete
  onDeleteConnection(connectionId);
}, [setFlowState, onDeleteConnection]);


  // Override undo/redo to set the flag
  // const handleUndo = useCallback(() => {
  //   isApplyingHistoryRef.current = true;
  //   undo();
  //   setTimeout(() => {
  //     isApplyingHistoryRef.current = false;
  //   }, 0);
  // }, [undo]);

  // const handleRedo = useCallback(() => {
  //   isApplyingHistoryRef.current = true;
  //   redo();
  //   setTimeout(() => {
  //     isApplyingHistoryRef.current = false;
  //   }, 0);
  // }, [redo]);

  // Handle keyboard shortcuts
  useEffect(() => {
  const handleKeyDown = (event: KeyboardEvent) => {
    if ((event.ctrlKey || event.metaKey) && event.key === 'z' && !event.shiftKey) {
      event.preventDefault();
      if (canUndo) {
        undo(); // Use directly
      }
    }
    if (((event.ctrlKey || event.metaKey) && event.key === 'y') || 
        ((event.ctrlKey || event.metaKey) && event.shiftKey && event.key === 'Z')) {
      event.preventDefault();
      if (canRedo) {
        redo(); // Use directly
      }
    }
  };

  document.addEventListener('keydown', handleKeyDown);
  return () => document.removeEventListener('keydown', handleKeyDown);
}, [undo, redo, canUndo, canRedo]); // Update dependencies


  // Convert blocks to React Flow nodes
  const nodes: Node[] = useMemo(() => 
    currentBlocks.map((block) => {
      // Find the latest block data from the blocks prop (which has fresh API data)
      const latestBlock = blocks.find(b => b.id === block.id) || block;
      
      return {
        id: block.id,
        type: 'emailBlock',
        position: { x: block.position_x, y: block.position_y },
        data: {
          ...latestBlock,
          // Override position from currentBlocks to ensure it's in sync with undo/redo
          position_x: block.position_x,
          position_y: block.position_y,
          onEdit: onEditBlock,
          onDelete: handleDeleteBlock,
          onDuplicate: onDuplicateBlock,
        },
      };
    }),
    [currentBlocks, blocks, onEditBlock, handleDeleteBlock, onDuplicateBlock]
  );

  // Convert connections to React Flow edges
  const edges: Edge[] = useMemo(() => 
    currentConnections.map((connection) => {
      const conditionConfig = CONDITION_TYPE_CONFIG[connection.condition_type as keyof typeof CONDITION_TYPE_CONFIG];
      
      // Use custom label if available, otherwise fall back to condition label
      let displayLabel = undefined;
      if (connection.custom_label?.trim()) {
        displayLabel = connection.custom_label.trim();
      } else if (connection.condition_type !== 'default') {
        displayLabel = conditionConfig?.label || connection.condition_type;
      }
      
      return {
        id: connection.id,
        source: connection.source_block_id,
        target: connection.target_block_id,
        type: 'smoothstep',
        animated: connection.condition_type !== 'default' || !!connection.custom_label,
        style: {
          stroke: connection.custom_label ? '#8b5cf6' : // Purple for custom labels
                  connection.condition_type === 'default' ? '#6366f1' : 
                  connection.condition_type.includes('not') ? '#ef4444' : '#10b981',
          strokeWidth: 2,
        },
        label: displayLabel,
        labelStyle: {
          fontSize: 11,
          fontWeight: 500,
          color: connection.custom_label ? '#8b5cf6' : conditionConfig?.color || '#6b7280'
        },
        labelBgStyle: {
          fill: '#ffffff',
          fillOpacity: 0.9,
          rx: 4,
          ry: 4,
        },
      };
    }),
    [currentConnections]
  );

  const [reactFlowNodes, setNodes, onNodesChange] = useNodesState(nodes);
  const [reactFlowEdges, setEdges, onEdgesChange] = useEdgesState(edges);

  // Update nodes when blocks change
  useMemo(() => {
    setNodes(nodes);
  }, [nodes, setNodes]);

  // Update edges when connections change
  useMemo(() => {
    setEdges(edges);
  }, [edges, setEdges]);

  // Handle node position changes with undo/redo
  const onNodeDragStop = useCallback((_event: React.MouseEvent, node: Node) => {
  isInternalUpdateRef.current = true; // Mark as internal update
  
  setFlowState((prevState) => ({
    ...prevState,
    blocks: prevState.blocks.map(block => 
      block.id === node.id
        ? { ...block, position_x: Math.round(node.position.x), position_y: Math.round(node.position.y) }
        : block
    ),
  }));
  
  onUpdateBlock(node.id, {
    position_x: Math.round(node.position.x),
    position_y: Math.round(node.position.y),
  });
}, [setFlowState, onUpdateBlock]);


  // Handle new connections
  const onConnect = useCallback((params: Connection) => {
    if (params.source && params.target) {
      onCreateConnection(params.source, params.target);
    }
  }, [onCreateConnection]);

  // Handle edge deletion
  const onEdgeDoubleClick = useCallback((event: React.MouseEvent, edge: Edge) => {
    event.preventDefault();
    handleDeleteConnection(edge.id);
  }, [handleDeleteConnection]);

  // Generate minimap node colors
  const getMiniMapNodeColor = (node: Node) => {
    const block = currentBlocks.find(b => b.id === node.id);
    if (!block) return '#gray';
    const config = BLOCK_TYPE_CONFIG[block.type];
    return config.borderColor.includes('blue') ? '#3b82f6' :
           config.borderColor.includes('green') ? '#10b981' :
           config.borderColor.includes('purple') ? '#8b5cf6' :
           config.borderColor.includes('orange') ? '#f59e0b' :
           config.borderColor.includes('red') ? '#ef4444' :
           config.borderColor.includes('yellow') ? '#eab308' :
           config.borderColor.includes('pink') ? '#ec4899' : '#6b7280';
  };

  return (
    <div className="flex-1 h-full bg-gray-50">
      <ReactFlow
        nodes={reactFlowNodes}
        edges={reactFlowEdges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        onNodeDragStop={onNodeDragStop}
        onEdgeDoubleClick={onEdgeDoubleClick}
        nodeTypes={nodeTypes}
        fitView={currentBlocks.length === 0}
        fitViewOptions={{ padding: 50 }}
        minZoom={0.1}
        maxZoom={2}
        defaultViewport={{ x: 0, y: 0, zoom: 0.8 }}
        connectionLineStyle={{
          stroke: '#6366f1',
          strokeWidth: 2,
        }}
        snapToGrid
        snapGrid={[20, 20]}
      >
        {/* Undo/Redo Controls */}
        <div className="absolute top-4 left-4 z-10">
          <UndoRedoControls
  canUndo={canUndo}
  canRedo={canRedo}
  onUndo={undo}  // Changed from handleUndo
  onRedo={redo}  // Changed from handleRedo
  hasUnsavedChanges={hasUnsavedChanges}
/>

        </div>
        <Background
          variant={BackgroundVariant.Dots}
          gap={20}
          size={1}
          color="#e5e7eb"
        />
        
        <Controls
          showZoom
          showFitView
          showInteractive
          position="bottom-right"
          className="bg-white border border-gray-200 rounded-lg shadow-lg"
        />
        
        <MiniMap
          nodeColor={getMiniMapNodeColor}
          nodeStrokeWidth={3}
          pannable
          zoomable
          position="top-right"
          className="bg-white border border-gray-200 rounded-lg shadow-lg"
        />
      </ReactFlow>

      {/* Instructions Overlay */}
      {currentBlocks.length === 0 && (
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <div className="text-center p-8 bg-white rounded-2xl shadow-lg border-2 border-dashed border-gray-300 max-w-md">
            <div className="text-6xl mb-4">📧</div>
            <h3 className="text-xl font-bold text-gray-900 mb-2">
              Start Building Your Email Sequence
            </h3>
            <p className="text-gray-600 mb-4">
              Click on email blocks in the sidebar to add them to your flow. Connect them by dragging from the bottom handle to create your sequence.
            </p>
            <div className="text-sm text-gray-500 space-y-1">
              <p>💡 Tip: Double-click blocks to edit their content</p>
              <p>💡 Tip: Double-click connections to delete them</p>
              <p>💡 Tip: Drag to connect blocks together</p>
              <p>💡 Tip: Drag blocks to rearrange them</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
