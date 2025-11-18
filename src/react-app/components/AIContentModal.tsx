import { useState, useEffect } from 'react';
import { X, Wand2, ChevronDown, Loader2, Coins } from 'lucide-react';
import { EmailBlockTypeT, BLOCK_TYPE_CONFIG } from '@/shared/types';
import { SUBJECT_LINE_TEMPLATES, CTA_TEMPLATES } from '@/react-app/data/emailTemplates';

interface AIContentModalProps {
  blockType: EmailBlockTypeT;
  onClose: () => void;
  onGenerate: (content: any) => void;
}

export default function AIContentModal({ blockType, onClose, onGenerate }: AIContentModalProps) {
  const [answers, setAnswers] = useState<Record<string, string>>({});
  const [tone, setTone] = useState<'friendly' | 'professional' | 'casual' | 'persuasive' | 'urgent'>('friendly');
  const [customSubject, setCustomSubject] = useState('');
  const [customCTA, setCustomCTA] = useState('');
  const [showSubjectTemplates, setShowSubjectTemplates] = useState(false);
  const [showCTATemplates, setShowCTATemplates] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [creditsBalance, setCreditsBalance] = useState<number | null>(null);

  const config = BLOCK_TYPE_CONFIG[blockType];
  const subjectTemplates = SUBJECT_LINE_TEMPLATES[blockType as keyof typeof SUBJECT_LINE_TEMPLATES] || [];
  const ctaTemplates = CTA_TEMPLATES[blockType as keyof typeof CTA_TEMPLATES] || [];
  
  // Estimated cost for AI generation (~1500 credits)
  const estimatedCost = 1500;

  // Fetch user credits on mount
  useEffect(() => {
    const fetchCredits = async () => {
      try {
        const response = await fetch('/api/users/me/credits');
        if (response.ok) {
          const data = await response.json();
          setCreditsBalance(data.credits_balance);
        }
      } catch (error) {
        console.error('Failed to fetch credits:', error);
      }
    };
    fetchCredits();
  }, []);

  const handleGenerate = async () => {
    setIsGenerating(true);
    
    try {
      console.log('[Frontend] Starting AI generation with data:', {
        type: blockType,
        answers,
        tone,
        custom_subject: customSubject,
        custom_cta: customCTA,
        answersCount: Object.keys(answers).length
      });

      const response = await fetch('/api/ai/generate-content', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: blockType,
          answers,
          tone,
          custom_subject: customSubject,
          custom_cta: customCTA,
        }),
      });

      console.log('[Frontend] API response status:', response.status);
      console.log('[Frontend] API response headers:', Object.fromEntries(response.headers.entries()));

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
        console.error('[Frontend] API error response:', errorData);
        
        if (response.status === 403 && errorData.error === 'Insufficient AI Credits') {
          alert(`Insufficient AI Credits!\n\nYou need ${errorData.credits_needed} credits but only have ${errorData.credits_balance} credits remaining.\n\nPlease upgrade your plan or purchase more credits to continue.`);
          onClose();
          return;
        }
        
        throw new Error(errorData.error || `API returned ${response.status}`);
      }

      const content = await response.json();
      console.log('[Frontend] Generated content received:', content);
      
      // Update credits balance after successful generation
      if (content.credits_used) {
        setCreditsBalance(prev => prev !== null ? prev - content.credits_used : null);
        
        // Show success message with credits used
        alert(`✅ Content generated successfully!\n\n📊 Credits used: ${content.credits_used}\n📝 Words generated: ${content.word_count}\n💰 Remaining credits: ${creditsBalance !== null ? creditsBalance - content.credits_used : 'Unknown'}`);
      }
      
      onGenerate(content);
    } catch (error) {
      console.error('[Frontend] AI generation failed:', error);
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      alert(`Failed to generate content: ${errorMessage}. Please try again.`);
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-[100] p-4 overflow-y-auto">
  <div className="bg-white rounded-2xl max-w-2xl w-full my-8 shadow-2xl flex flex-col max-h-[95vh]">

        {/* Header */}
        <div className={`${config.bgColor} border-b ${config.borderColor} p-6`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 bg-gradient-to-br from-purple-600 to-blue-600 rounded-xl flex items-center justify-center">
                <Wand2 className="w-6 h-6 text-white" />
              </div>
              <div>
                <h2 className="text-xl font-bold text-gray-900">
                  AI Content Generator
                </h2>
                <p className="text-sm text-gray-600 mt-1">
                  Generate {config.label} content with AI
                </p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              {creditsBalance !== null && (
                <div className="flex items-center gap-2 px-3 py-2 bg-white/60 rounded-lg border border-gray-200">
                  <Coins className="w-4 h-4 text-yellow-600" />
                  <span className="text-sm font-medium text-gray-900">
                    {creditsBalance.toLocaleString()} credits
                  </span>
                </div>
              )}
              <button
                onClick={onClose}
                className="p-2 hover:bg-white/50 rounded-lg transition-colors"
              >
                <X className="w-6 h-6 text-gray-600" />
              </button>
            </div>
          </div>
        </div>

        <div className="p-6 flex-1 overflow-y-auto">

          {/* Questions */}
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Tell us about your {config.label.toLowerCase()}:
              </h3>
              <div className="space-y-4">
                {config.questions.map((question, index) => (
                  <div key={index}>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      {question}
                    </label>
                    <textarea
                      value={answers[index] || ''}
                      onChange={(e) => setAnswers({ ...answers, [index]: e.target.value })}
                      className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent resize-none"
                      rows={2}
                      placeholder="Type your answer here..."
                    />
                  </div>
                ))}
              </div>
            </div>

            {/* Tone Selection */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-3">
                Choose the tone:
              </label>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                {['friendly', 'professional', 'casual', 'persuasive', 'urgent'].map((toneOption) => (
                  <button
                    key={toneOption}
                    onClick={() => setTone(toneOption as any)}
                    className={`p-3 text-sm font-medium rounded-lg border-2 transition-all ${
                      tone === toneOption
                        ? 'border-purple-500 bg-purple-50 text-purple-700'
                        : 'border-gray-200 text-gray-700 hover:border-gray-300'
                    }`}
                  >
                    {toneOption.charAt(0).toUpperCase() + toneOption.slice(1)}
                  </button>
                ))}
              </div>
            </div>

            {/* Custom Subject Line */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="block text-sm font-medium text-gray-700">
                  Custom Subject Line (optional)
                </label>
                {subjectTemplates.length > 0 && (
                  <div className="relative">
                    <button
                      type="button"
                      onClick={() => setShowSubjectTemplates(!showSubjectTemplates)}
                      className="flex items-center gap-1 text-xs text-blue-600 hover:text-blue-800"
                    >
                      Use Template
                      <ChevronDown className={`w-3 h-3 transition-transform ${showSubjectTemplates ? 'rotate-180' : ''}`} />
                    </button>
                    {showSubjectTemplates && (
                      <div className="absolute top-full right-0 mt-1 bg-white border border-gray-300 rounded-lg shadow-lg z-10 min-w-[300px] max-h-48 overflow-y-auto">
                        {subjectTemplates.map((template, index) => (
                          <button
                            key={index}
                            onClick={() => {
                              setCustomSubject(template);
                              setShowSubjectTemplates(false);
                            }}
                            className="w-full px-3 py-2 text-left text-xs hover:bg-gray-100 border-b border-gray-100 last:border-b-0"
                          >
                            {template}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
              <input
                type="text"
                value={customSubject}
                onChange={(e) => setCustomSubject(e.target.value)}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                placeholder="Leave empty to let AI generate"
              />
            </div>

            {/* Custom CTA */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="block text-sm font-medium text-gray-700">
                  Custom Call-to-Action Text (optional)
                </label>
                {ctaTemplates.length > 0 && (
                  <div className="relative">
                    <button
                      type="button"
                      onClick={() => setShowCTATemplates(!showCTATemplates)}
                      className="flex items-center gap-1 text-xs text-blue-600 hover:text-blue-800"
                    >
                      Use Template
                      <ChevronDown className={`w-3 h-3 transition-transform ${showCTATemplates ? 'rotate-180' : ''}`} />
                    </button>
                    {showCTATemplates && (
                      <div className="absolute top-full right-0 mt-1 bg-white border border-gray-300 rounded-lg shadow-lg z-10 min-w-[200px] max-h-48 overflow-y-auto">
                        {ctaTemplates.map((template, index) => (
                          <button
                            key={index}
                            onClick={() => {
                              setCustomCTA(template);
                              setShowCTATemplates(false);
                            }}
                            className="w-full px-3 py-2 text-left text-xs hover:bg-gray-100 border-b border-gray-100 last:border-b-0"
                          >
                            {template}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
              <input
                type="text"
                value={customCTA}
                onChange={(e) => setCustomCTA(e.target.value)}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                placeholder="Leave empty to let AI generate"
              />
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="border-t border-gray-200 p-6">
          {/* Cost estimate banner */}
          {creditsBalance !== null && (
            <div className={`mb-4 p-3 rounded-lg ${
              creditsBalance < estimatedCost 
                ? 'bg-red-50 border border-red-200' 
                : 'bg-blue-50 border border-blue-200'
            }`}>
              <div className="flex items-center gap-2 text-sm">
                <Coins className={`w-4 h-4 ${creditsBalance < estimatedCost ? 'text-red-600' : 'text-blue-600'}`} />
                <span className={`font-medium ${creditsBalance < estimatedCost ? 'text-red-900' : 'text-blue-900'}`}>
                  {creditsBalance < estimatedCost ? (
                    `Insufficient credits! You need ~${estimatedCost.toLocaleString()} credits but only have ${creditsBalance.toLocaleString()}`
                  ) : (
                    `Estimated cost: ~${estimatedCost.toLocaleString()} credits (5 credits per word generated)`
                  )}
                </span>
              </div>
            </div>
          )}
          
          <div className="flex justify-between items-center">
            {/* Show helper text when button is disabled */}
            {Object.keys(answers).filter(answer => answer.trim()).length === 0 && (
              <p className="text-sm text-gray-500">
                💡 Please answer at least one question above to enable content generation
              </p>
            )}
            {Object.keys(answers).filter(answer => answer.trim()).length > 0 && creditsBalance !== null && creditsBalance < estimatedCost && (
              <p className="text-sm text-red-600 font-medium">
                ⚠️ Insufficient AI credits - please upgrade your plan
              </p>
            )}
            
            <div className="flex gap-3 ml-auto">
              <button
                onClick={onClose}
                className="px-6 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleGenerate}
                disabled={isGenerating || Object.keys(answers).filter(answer => answer.trim()).length === 0 || (creditsBalance !== null && creditsBalance < estimatedCost)}
                className="flex items-center gap-2 px-6 py-2 bg-gradient-to-r from-purple-600 to-blue-600 text-white rounded-lg hover:from-purple-700 hover:to-blue-700 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                title={
                  creditsBalance !== null && creditsBalance < estimatedCost 
                    ? "Insufficient AI credits" 
                    : Object.keys(answers).filter(answer => answer.trim()).length === 0 
                      ? "Please answer at least one question to generate content" 
                      : "Generate AI content"
                }
              >
                {isGenerating ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Generating...
                  </>
                ) : (
                  <>
                    <Wand2 className="w-4 h-4" />
                    Generate Content
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
