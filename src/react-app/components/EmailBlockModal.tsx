import { useState, useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { X, Mail, Clock, MousePointer, Type, Eye, RefreshCw, Calendar,Wand2 } from 'lucide-react';
import { EmailBlock, BLOCK_TYPE_CONFIG } from '@/shared/types';
import RichTextEditor from './RichTextEditor';
import AIContentModal from './AIContentModal';
interface EmailBlockModalProps {
  block: EmailBlock | null;
  onClose: () => void;
  onSave: (blockId: string, updates: Partial<EmailBlock>) => void;
}

interface FormData {
  name: string;
  subject_line: string;
  preview_text: string;
  body_copy: string;
  cta_text: string;
  cta_url: string;
  send_delay_hours: number;
  send_delay_days: number;
  send_delay_remaining_hours: number;
  notes: string;
}

export default function EmailBlockModal({ block, onClose, onSave }: EmailBlockModalProps) {
  const [activeTab, setActiveTab] = useState<'content' | 'scheduling' | 'preview'>('content');
  const [isRewriting, setIsRewriting] = useState(false);
  const [scheduleType, setScheduleType] = useState<'immediate' | 'delay' | 'specific'>('delay');
  const [specificDate, setSpecificDate] = useState('');
  const [showAIModal, setShowAIModal] = useState(false);

  const { register, handleSubmit, reset, watch, setValue } = useForm<FormData>({
    defaultValues: {
      name: '',
      subject_line: '',
      preview_text: '',
      body_copy: '',
      cta_text: '',
      cta_url: '',
      send_delay_hours: 0,
      send_delay_days: 0,
      send_delay_remaining_hours: 0,
      notes: '',
    }
  });

  useEffect(() => {
    if (block) {
      const totalHours = block.send_delay_hours || 0;
      const days = Math.floor(totalHours / 24);
      const remainingHours = totalHours % 24;
      
      reset({
        name: block.name,
        subject_line: block.subject_line || '',
        preview_text: block.preview_text || '',
        body_copy: block.body_copy || '',
        cta_text: block.cta_text || '',
        cta_url: block.cta_url || '',
        send_delay_hours: totalHours,
        send_delay_days: days,
        send_delay_remaining_hours: remainingHours,
        notes: block.notes || '',
      });

      // Set schedule type based on delay
      if (totalHours === 0) {
        setScheduleType('immediate');
      } else {
        setScheduleType('delay');
      }
    }
  }, [block, reset]);

  const watchedValues = watch();
  const config = block ? BLOCK_TYPE_CONFIG[block.type] : null;

  if (!block || !config) return null;

  const onSubmit = (data: FormData) => {
    let finalSendDelayHours = 0;

    if (scheduleType === 'delay') {
      finalSendDelayHours = (data.send_delay_days * 24) + data.send_delay_remaining_hours;
    } else if (scheduleType === 'specific' && specificDate) {
      // Calculate hours from now to specific date
      const targetDate = new Date(specificDate);
      const now = new Date();
      const diffMs = targetDate.getTime() - now.getTime();
      finalSendDelayHours = Math.max(0, Math.floor(diffMs / (1000 * 60 * 60)));
    }

    const updates = {
      name: data.name,
      subject_line: data.subject_line,
      preview_text: data.preview_text,
      body_copy: data.body_copy,
      cta_text: data.cta_text,
      cta_url: data.cta_url,
      send_delay_hours: finalSendDelayHours,
      notes: data.notes,
    };

    onSave(block.id, updates);
    onClose();
  };

  const handleRewriteContent = async (tone: 'friendly' | 'professional' | 'casual' | 'persuasive' | 'urgent') => {
    setIsRewriting(true);
    
    try {
      const response = await fetch('/api/ai/rewrite-content', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subject_line: watchedValues.subject_line,
          preview_text: watchedValues.preview_text,
          body_copy: watchedValues.body_copy,
          cta_text: watchedValues.cta_text,
          tone,
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to rewrite content');
      }

      const rewrittenContent = await response.json();
      
      // Update form with rewritten content
      setValue('subject_line', rewrittenContent.subject_line || watchedValues.subject_line);
      setValue('preview_text', rewrittenContent.preview_text || watchedValues.preview_text);
      setValue('body_copy', rewrittenContent.body_copy || watchedValues.body_copy);
      setValue('cta_text', rewrittenContent.cta_text || watchedValues.cta_text);
    } catch (error) {
      console.error('Rewrite failed:', error);
      alert('Failed to rewrite content. Please try again.');
    } finally {
      setIsRewriting(false);
    }
  };

  const formatDelay = () => {
    if (scheduleType === 'immediate') return 'Immediately';
    if (scheduleType === 'specific' && specificDate) {
      return `On ${new Date(specificDate).toLocaleString()}`;
    }
    
    const days = watchedValues.send_delay_days || 0;
    const hours = watchedValues.send_delay_remaining_hours || 0;
    
    if (days === 0 && hours === 0) return 'Immediately';
    if (days === 0) return `${hours} hour${hours > 1 ? 's' : ''}`;
    if (hours === 0) return `${days} day${days > 1 ? 's' : ''}`;
    return `${days} day${days > 1 ? 's' : ''} ${hours} hour${hours > 1 ? 's' : ''}`;
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-2xl max-w-4xl w-full max-h-[90vh] overflow-hidden shadow-2xl">
        {/* Header */}
        <div className={`${config.bgColor} border-b ${config.borderColor} p-6`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className="text-2xl">{config.icon}</span>
              <div>
                <h2 className={`text-xl font-bold ${config.color}`}>
                  Edit {config.label} Block
                </h2>
                <p className="text-sm text-gray-600 mt-1">
                  Configure your email content and settings
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
              onClick={() => setActiveTab('content')}
              className={`px-6 py-3 font-medium border-b-2 transition-colors ${
                activeTab === 'content'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              <Type className="w-4 h-4 inline-block mr-2" />
              Content
            </button>
            <button
              onClick={() => setActiveTab('scheduling')}
              className={`px-6 py-3 font-medium border-b-2 transition-colors ${
                activeTab === 'scheduling'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              <Clock className="w-4 h-4 inline-block mr-2" />
              Scheduling
            </button>
            <button
              onClick={() => setActiveTab('preview')}
              className={`px-6 py-3 font-medium border-b-2 transition-colors ${
                activeTab === 'preview'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              <Eye className="w-4 h-4 inline-block mr-2" />
              Preview
            </button>
          </div>
        </div>

        <form onSubmit={handleSubmit(onSubmit)}>
          <div className="h-[60vh] overflow-y-auto">
            {activeTab === 'content' && (
              <div className="p-6 space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
  {/* Left column */}
  <div className="flex flex-col gap-4">
    {/* Block Name */}
    <div>
      <label className="block text-sm font-medium text-gray-700 mb-2">Block Name</label>
      <input
        {...register('name', { required: true })}
        className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
        placeholder="e.g., Welcome Email"
      />
    </div>
    {/* Notes */}
    <div>
      <label className="block text-sm font-medium text-gray-700 mb-2">Notes</label>
      <textarea
        {...register('notes')}
        rows={3}
        className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
        placeholder="Add notes about this email block..."
      />
    </div>
    {/* Send Schedule */}
    <div className="bg-blue-50 p-4 rounded-lg flex flex-col justify-between">
      <div className="flex items-center gap-2 mb-2">
        <Clock className="w-4 h-4 text-blue-600" />
        <span className="text-sm font-medium text-blue-900">Send Schedule</span>
      </div>
      <p className="text-sm text-blue-700">Will send {formatDelay()}</p>
      <button
        type="button"
        onClick={() => setActiveTab('scheduling')}
        className="text-xs text-blue-600 hover:text-blue-800 mt-1 self-start"
      >
        Click to modify schedule →
      </button>
    </div>
  </div>
  {/* Right column */}
  <div className="flex flex-col gap-4 h-full">
    {/* Subject Line */}
    <div>
      <label className="block text-sm font-medium text-gray-700 mb-2">
        <Mail className="w-4 h-4 inline-block mr-1" />
        Subject Line
      </label>
      <input
        {...register('subject_line')}
        className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
        placeholder="Your email subject line"
      />
    </div>
    {/* Preview Text */}
    <div>
      <label className="block text-sm font-medium text-gray-700 mb-2">Preview Text</label>
      <input
        {...register('preview_text')}
        className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
        placeholder="Preview text that appears in inbox"
      />
    </div>
    {/* AI Generate Button "Card" */}
    <div className="bg-purple-50 border-2 border-purple-200 rounded-xl p-4 flex flex-col justify-center items-start mt-2">
      <button
        type="button"
        onClick={() => setShowAIModal(true)}
        className="flex items-center gap-3 focus:outline-none"
      >
        <div className="w-10 h-10 bg-gradient-to-br from-purple-600 to-blue-600 rounded-lg flex items-center justify-center">
          <Wand2 className="w-5 h-5 text-white" />
        </div>
        <div className="flex-1 text-left">
          <h4 className="font-medium text-purple-900">
            Generate Content with AI
          </h4>
          <p className="text-xs text-purple-700 mt-0.5">
            Let AI create email content for you
          </p>
        </div>
      </button>
    </div>
  </div>
</div>


                <div>
                  <div className="flex items-center justify-between mb-2">
                    <label className="block text-sm font-medium text-gray-700">
                      Email Body
                    </label>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-gray-500">AI Rewrite:</span>
                      <button
                        type="button"
                        onClick={() => handleRewriteContent('friendly')}
                        disabled={isRewriting}
                        className="px-2 py-1 text-xs bg-green-100 text-green-700 rounded hover:bg-green-200 transition-colors disabled:opacity-50"
                      >
                        Friendly
                      </button>
                      <button
                        type="button"
                        onClick={() => handleRewriteContent('professional')}
                        disabled={isRewriting}
                        className="px-2 py-1 text-xs bg-blue-100 text-blue-700 rounded hover:bg-blue-200 transition-colors disabled:opacity-50"
                      >
                        Professional
                      </button>
                      <button
                        type="button"
                        onClick={() => handleRewriteContent('casual')}
                        disabled={isRewriting}
                        className="px-2 py-1 text-xs bg-cyan-100 text-cyan-700 rounded hover:bg-cyan-200 transition-colors disabled:opacity-50"
                      >
                        Casual
                      </button>
                      <button
                        type="button"
                        onClick={() => handleRewriteContent('persuasive')}
                        disabled={isRewriting}
                        className="px-2 py-1 text-xs bg-purple-100 text-purple-700 rounded hover:bg-purple-200 transition-colors disabled:opacity-50"
                      >
                        Persuasive
                      </button>
                      <button
                        type="button"
                        onClick={() => handleRewriteContent('urgent')}
                        disabled={isRewriting}
                        className="px-2 py-1 text-xs bg-red-100 text-red-700 rounded hover:bg-red-200 transition-colors disabled:opacity-50"
                      >
                        Urgent
                      </button>
                      {isRewriting && (
                        <RefreshCw className="w-3 h-3 text-purple-600 animate-spin" />
                      )}
                    </div>
                  </div>
                  <RichTextEditor
                    value={watchedValues.body_copy || ''}
                    onChange={(value) => setValue('body_copy', value)}
                    placeholder="Write your email content here..."
                    rows={8}
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      <MousePointer className="w-4 h-4 inline-block mr-1" />
                      CTA Button Text
                    </label>
                    <input
                      {...register('cta_text')}
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      placeholder="e.g., Shop Now, Learn More"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      CTA URL
                    </label>
                    <input
                      {...register('cta_url')}
                      type="url"
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      placeholder="https://example.com"
                    />
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'scheduling' && (
              <div className="p-6 space-y-6">
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">Send Schedule</h3>
                  
                  {/* Schedule Type Selection */}
                  <div className="space-y-4">
                    <div className="flex items-center gap-3">
                      <input
                        type="radio"
                        id="immediate"
                        checked={scheduleType === 'immediate'}
                        onChange={() => setScheduleType('immediate')}
                        className="h-4 w-4 text-blue-600"
                      />
                      <label htmlFor="immediate" className="text-sm font-medium text-gray-700">
                        Send immediately
                      </label>
                    </div>

                    <div className="flex items-center gap-3">
                      <input
                        type="radio"
                        id="delay"
                        checked={scheduleType === 'delay'}
                        onChange={() => setScheduleType('delay')}
                        className="h-4 w-4 text-blue-600"
                      />
                      <label htmlFor="delay" className="text-sm font-medium text-gray-700">
                        Send after delay
                      </label>
                    </div>

                    {scheduleType === 'delay' && (
                      <div className="ml-7 grid grid-cols-2 gap-4 mt-3">
                        <div>
                          <label className="block text-xs text-gray-600 mb-1">Days</label>
                          <input
                            {...register('send_delay_days', { 
                              valueAsNumber: true,
                              min: 0,
                              max: 365
                            })}
                            type="number"
                            min="0"
                            max="365"
                            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                            placeholder="0"
                          />
                        </div>
                        <div>
                          <label className="block text-xs text-gray-600 mb-1">Hours</label>
                          <input
                            {...register('send_delay_remaining_hours', { 
                              valueAsNumber: true,
                              min: 0,
                              max: 23
                            })}
                            type="number"
                            min="0"
                            max="23"
                            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                            placeholder="0"
                          />
                        </div>
                      </div>
                    )}

                    <div className="flex items-center gap-3">
                      <input
                        type="radio"
                        id="specific"
                        checked={scheduleType === 'specific'}
                        onChange={() => setScheduleType('specific')}
                        className="h-4 w-4 text-blue-600"
                      />
                      <label htmlFor="specific" className="text-sm font-medium text-gray-700">
                        Send on specific date & time
                      </label>
                    </div>

                    {scheduleType === 'specific' && (
                      <div className="ml-7 mt-3">
                        <div className="flex items-center gap-2">
                          <Calendar className="w-4 h-4 text-gray-500" />
                          <input
                            type="datetime-local"
                            value={specificDate}
                            onChange={(e) => setSpecificDate(e.target.value)}
                            min={new Date().toISOString().slice(0, 16)}
                            className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                          />
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Schedule Preview */}
                  <div className="mt-6 p-4 bg-gray-50 rounded-lg">
                    <h4 className="text-sm font-medium text-gray-900 mb-2">Schedule Preview</h4>
                    <p className="text-sm text-gray-600">
                      This email will send: <span className="font-medium">{formatDelay()}</span>
                    </p>
                    {scheduleType === 'specific' && specificDate && (
                      <p className="text-xs text-gray-500 mt-1">
                        From now: approximately {Math.floor((new Date(specificDate).getTime() - new Date().getTime()) / (1000 * 60 * 60))} hours
                      </p>
                    )}
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'preview' && (
              <div className="p-6">
                <div className="max-w-2xl mx-auto bg-gray-50 rounded-xl p-6">
                  <div className="bg-white rounded-lg shadow-sm border p-6">
                    {/* Email Header */}
                    <div className="border-b pb-4 mb-4">
                      <h3 className="font-bold text-lg">
                        {watchedValues.subject_line || 'Subject Line'}
                      </h3>
                      {watchedValues.preview_text && (
                        <p className="text-sm text-gray-600 mt-1">
                          {watchedValues.preview_text}
                        </p>
                      )}
                    </div>

                    {/* Email Body */}
                    <div className="prose prose-sm max-w-none">
                      {watchedValues.body_copy ? (
                        <div 
                          className="whitespace-pre-wrap p-4"
                          style={{ marginLeft: '1rem' }}
                          dangerouslySetInnerHTML={{ 
                            __html: watchedValues.body_copy
                              .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                              .replace(/\*(.*?)\*/g, '<em>$1</em>')
                              .replace(/<u>(.*?)<\/u>/g, '<u>$1</u>')
                              .replace(/^# (.*$)/gm, '<h1 class="text-xl font-bold mb-2 ml-4">$1</h1>')
                              .replace(/^## (.*$)/gm, '<h2 class="text-lg font-semibold mb-2 ml-4">$1</h2>')
                              .replace(/^\• (.*)$/gm, '<li class="ml-8 mb-1">$1</li>')
                              .replace(/^1\. (.*)$/gm, '<li class="ml-8 mb-1">$1</li>')
                              // Handle images with styles before regular links
                              .replace(/\[IMAGE:\s*([^\]]*)\]\(([^)]+)\)\{([^}]+)\}/g, (_, alt, src, styles) => {
                                let imgStyle = 'max-width: 100%; height: auto; display: block; margin: 10px 0;';
                                
                                // Parse styles - handle both semicolon and comma separators
                                const styleProps = styles.split(/[;,]/).reduce((acc: any, prop: string) => {
                                  const [key, value] = prop.split(':').map((s: string) => s.trim());
                                  if (key && value) acc[key] = value;
                                  return acc;
                                }, {});
                                
                                // Apply width first
                                if (styleProps.width) {
                                  imgStyle += ` width: ${styleProps.width};`;
                                }
                                
                                // Apply alignment - this must come after width to avoid overriding
                                if (styleProps.align) {
                                  if (styleProps.align === 'center') {
                                    imgStyle += ' margin-left: auto; margin-right: auto;';
                                  } else if (styleProps.align === 'right') {
                                    imgStyle += ' margin-left: auto; margin-right: 0;';
                                  } else if (styleProps.align === 'left') {
                                    imgStyle += ' margin-left: 0; margin-right: auto;';
                                  }
                                }
                                
                                return `<img src="${src}" alt="${alt}" style="${imgStyle}" />`;
                              })
                              .replace(/\[IMAGE:\s*([^\]]*)\]\(([^)]+)\)/g, '<img src="$2" alt="$1" style="max-width: 100%; height: auto; display: block; margin: 10px 0;" />')
                              .replace(/\[IMAGE\]\(([^)]+)\)/g, '<img src="$1" alt="Image" style="max-width: 100%; height: auto; display: block; margin: 10px 0;" />')
                              // Handle regular links
                              .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" class="text-blue-600 underline">$1</a>')
                              .replace(/\n/g, '<br>')
                          }}
                        />
                      ) : (
                        <p className="text-gray-400 italic">Email body content will appear here...</p>
                      )}
                    </div>

                    {/* CTA Button */}
                    {watchedValues.cta_text && (
                      <div className="mt-6 text-center">
                        <a
                          href={watchedValues.cta_url || '#'}
                          className="inline-block px-6 py-3 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition-colors"
                        >
                          {watchedValues.cta_text}
                        </a>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="border-t border-gray-200 p-6 flex justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              className="px-6 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
            >
              Save Changes
            </button>
          </div>
        </form>
      </div>
      {/* AI Content Modal */}
{showAIModal && (
  <AIContentModal
    blockType={block.type}
    onClose={() => setShowAIModal(false)}
    onGenerate={(content) => {
      // Fill form with AI-generated content
      setValue('name', content.name);
      setValue('subject_line', content.subject_line);
      setValue('preview_text', content.preview_text);
      setValue('body_copy', content.body_copy);
      setValue('cta_text', content.cta_text);
      setValue('cta_url', content.cta_url);
      setShowAIModal(false);
    }}
  />
)}

    </div>
  );
}
