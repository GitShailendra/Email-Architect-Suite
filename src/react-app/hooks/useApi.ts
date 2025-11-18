import { useState, useEffect, useCallback } from 'react';
import { Sequence, EmailBlock, Connection } from '@/shared/types';

// Sequences hook
export function useSequences() {
  const [sequences, setSequences] = useState<Sequence[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchSequences = useCallback(async () => {
    try {
      const response = await fetch('/api/sequences');
      if (response.ok) {
        const data = await response.json();
        setSequences(data);
      }
    } catch (error) {
      console.error('Failed to fetch sequences:', error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSequences();
  }, [fetchSequences]);

  const createSequence = useCallback(async (name: string, description?: string) => {
    const response = await fetch('/api/sequences', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, description }),
    });

    if (!response.ok) {
      throw new Error('Failed to create sequence');
    }

    const newSequence = await response.json();
    setSequences(prev => [newSequence, ...prev]);
    return newSequence;
  }, []);

  const duplicateSequence = useCallback(async (sequenceId: string) => {
    const response = await fetch(`/api/sequences/${sequenceId}/duplicate`, {
      method: 'POST',
    });

    if (!response.ok) {
      throw new Error('Failed to duplicate sequence');
    }

    const duplicatedSequence = await response.json();
    setSequences(prev => [duplicatedSequence, ...prev]);
    return duplicatedSequence;
  }, []);

  const deleteSequence = useCallback(async (sequenceId: string) => {
    const response = await fetch(`/api/sequences/${sequenceId}`, {
      method: 'DELETE',
    });

    if (!response.ok) {
      throw new Error('Failed to delete sequence');
    }

    setSequences(prev => prev.filter(seq => seq.id !== sequenceId));
  }, []);

  return {
    sequences,
    loading,
    createSequence,
    duplicateSequence,
    deleteSequence,
    refetch: fetchSequences,
  };
}

// Sequence data hook (blocks and connections)
export function useSequenceData(sequenceId: string | null) {
  const [blocks, setBlocks] = useState<EmailBlock[]>([]);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [loading, setLoading] = useState(false);

  const fetchSequenceData = useCallback(async () => {
    if (!sequenceId) {
      setBlocks([]);
      setConnections([]);
      return;
    }

    setLoading(true);
    try {
      const response = await fetch(`/api/sequences/${sequenceId}`);
      if (response.ok) {
        const data = await response.json();
        setBlocks(data.blocks || []);
        setConnections(data.connections || []);
      }
    } catch (error) {
      console.error('Failed to fetch sequence data:', error);
    } finally {
      setLoading(false);
    }
  }, [sequenceId]);

  useEffect(() => {
    fetchSequenceData();
  }, [fetchSequenceData]);

  const createBlock = useCallback(async (
    type: string,
    name: string,
    position_x: number = 0,
    position_y: number = 0
  ) => {
    if (!sequenceId) return;

    const response = await fetch(`/api/sequences/${sequenceId}/blocks`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sequence_id: sequenceId, type, name, position_x, position_y }),
    });

    if (!response.ok) {
      throw new Error('Failed to create block');
    }

    const newBlock = await response.json();
    setBlocks(prev => [...prev, newBlock]);
    return newBlock;
  }, [sequenceId]);

  const updateBlock = useCallback(async (blockId: string, updates: Partial<EmailBlock>) => {
    const response = await fetch(`/api/blocks/${blockId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    });

    if (!response.ok) {
      throw new Error('Failed to update block');
    }

    const updatedBlock = await response.json();
    setBlocks(prev => prev.map(block => block.id === blockId ? updatedBlock : block));
    return updatedBlock;
  }, []);

  const duplicateBlock = useCallback(async (blockId: string) => {
    const response = await fetch(`/api/blocks/${blockId}/duplicate`, {
      method: 'POST',
    });

    if (!response.ok) {
      throw new Error('Failed to duplicate block');
    }

    const newBlock = await response.json();
    setBlocks(prev => [...prev, newBlock]);
    return newBlock;
  }, []);

  const deleteBlock = useCallback(async (blockId: string) => {
    const response = await fetch(`/api/blocks/${blockId}`, {
      method: 'DELETE',
    });

    if (!response.ok) {
      throw new Error('Failed to delete block');
    }

    setBlocks(prev => prev.filter(block => block.id !== blockId));
    setConnections(prev => prev.filter(conn => 
      conn.source_block_id !== blockId && conn.target_block_id !== blockId
    ));
  }, []);

  const createConnection = useCallback(async (
    sourceId: string,
    targetId: string,
    conditionType: string = 'default',
    customLabel?: string
  ) => {
    if (!sequenceId) return;

    const response = await fetch('/api/connections', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        sequence_id: sequenceId,
        source_block_id: sourceId,
        target_block_id: targetId,
        condition_type: conditionType,
        custom_label: customLabel,
      }),
    });

    if (!response.ok) {
      throw new Error('Failed to create connection');
    }

    const newConnection = await response.json();
    setConnections(prev => [...prev, newConnection]);
    return newConnection;
  }, [sequenceId]);

  const deleteConnection = useCallback(async (connectionId: string) => {
    const response = await fetch(`/api/connections/${connectionId}`, {
      method: 'DELETE',
    });

    if (!response.ok) {
      throw new Error('Failed to delete connection');
    }

    setConnections(prev => prev.filter(conn => conn.id !== connectionId));
  }, []);

  return {
    blocks,
    connections,
    loading,
    createBlock,
    updateBlock,
    duplicateBlock,
    deleteBlock,
    createConnection,
    deleteConnection,
    refetch: fetchSequenceData,
  };
}
