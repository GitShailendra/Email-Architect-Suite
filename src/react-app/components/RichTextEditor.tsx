import { useState, useRef, useEffect } from 'react';
import { Bold, Italic, Underline, List, ListOrdered, Heading1, Heading2, Link, Image, Palette, Type, Code, Eye, AlignLeft, AlignCenter, AlignRight, AlignJustify } from 'lucide-react';

interface RichTextEditorProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  rows?: number;
  className?: string;
}

export default function RichTextEditor({ value, onChange, placeholder, rows = 8, className }: RichTextEditorProps) {
  const [showLinkDialog, setShowLinkDialog] = useState(false);
  const [showImageDialog, setShowImageDialog] = useState(false);
  const [showColorPicker, setShowColorPicker] = useState(false);
  const [showFontSizeMenu, setShowFontSizeMenu] = useState(false);
  const [showCustomColorPicker, setShowCustomColorPicker] = useState(false);
  const [linkText, setLinkText] = useState('');
  const [linkUrl, setLinkUrl] = useState('');
  const [imageUrl, setImageUrl] = useState('');
  const [imageAlt, setImageAlt] = useState('');
  const [viewMode, setViewMode] = useState<'visual' | 'html'>('visual');
  const [htmlContent, setHtmlContent] = useState('');
  const [customColor, setCustomColor] = useState('#000000');
  const [selectedImage, setSelectedImage] = useState<HTMLImageElement | null>(null);
  const [imageControlsPosition, setImageControlsPosition] = useState<{ x: number; y: number } | null>(null);
  const editorRef = useRef<HTMLDivElement>(null);
  const lastCursorPosition = useRef<{ node: Node | null; offset: number } | null>(null);

  // Convert markdown-like syntax to HTML for the visual editor
  const convertToHtml = (text: string) => {
    if (!text) return '';
    return text
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/^# (.*$)/gm, '<h1 style="font-size: 1.5em; font-weight: bold; margin-bottom: 0.5em;">$1</h1>')
      .replace(/^## (.*$)/gm, '<h2 style="font-size: 1.25em; font-weight: 600; margin-bottom: 0.5em;">$1</h2>')
      .replace(/^\• (.*)$/gm, '<li style="margin-left: 1.5em;">$1</li>')
      .replace(/^1\. (.*)$/gm, '<li style="margin-left: 1.5em;">$1</li>')
      // Handle alignment tags
      .replace(/<center>(.*?)<\/center>/g, '<div style="text-align: center;">$1</div>')
      .replace(/<right>(.*?)<\/right>/g, '<div style="text-align: right;">$1</div>')
      .replace(/<left>(.*?)<\/left>/g, '<div style="text-align: left;">$1</div>')
      // Handle images with styles before regular links
      .replace(/\[IMAGE:\s*([^\]]*)\]\(([^)]+)\)\{([^}]+)\}/g, (_, alt, src, styles) => {
        let imgStyle = 'max-width: 100%; height: auto; display: block; margin: 10px 0;';
        
        // Parse styles - handle both semicolon and comma separators
        const styleProps = styles.split(/[;,]/).reduce((acc: any, prop: string) => {
          const [key, value] = prop.split(':').map(s => s.trim());
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
      .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" style="color: #2563eb; text-decoration: underline;">$1</a>')
      .replace(/\n/g, '<br>');
  };

  // Convert HTML back to markdown-like syntax for storage
  const convertToMarkdown = (html: string) => {
    if (!html) return '';
    
    // Create a temporary div to parse HTML
    const temp = document.createElement('div');
    temp.innerHTML = html;
    
    let result = temp.innerHTML;
    
    // Convert back to markdown-like syntax
    result = result
      .replace(/<strong[^>]*>(.*?)<\/strong>/gi, '**$1**')
      .replace(/<b[^>]*>(.*?)<\/b>/gi, '**$1**')
      .replace(/<em[^>]*>(.*?)<\/em>/gi, '*$1*')
      .replace(/<i[^>]*>(.*?)<\/i>/gi, '*$1*')
      .replace(/<u[^>]*>(.*?)<\/u>/gi, '<u>$1</u>')
      .replace(/<h1[^>]*>(.*?)<\/h1>/gi, '# $1')
      .replace(/<h2[^>]*>(.*?)<\/h2>/gi, '## $1')
      .replace(/<li[^>]*>(.*?)<\/li>/gi, '• $1')
      .replace(/<a[^>]*href="([^"]*)"[^>]*>(.*?)<\/a>/gi, '[$2]($1)')
      // Preserve image styles and convert to extended markdown syntax
      .replace(/<img([^>]*)>/gi, (fullMatch, attrs) => {
        // Extract attributes using more robust parsing
        const srcMatch = attrs.match(/src=["']([^"']*)["']/);
        const altMatch = attrs.match(/alt=["']([^"']*)["']/);
        const styleMatch = attrs.match(/style=["']([^"']*)["']/);
        
        const src = srcMatch ? srcMatch[1] : '';
        const alt = altMatch ? altMatch[1] : 'Image';
        const style = styleMatch ? styleMatch[1] : '';
        
        if (!src) return fullMatch;
        
        // More comprehensive style parsing
        const styles = [];
        let alignment = '';
        
        if (style) {
          // Extract width - match various formats
          const widthMatch = style.match(/(?:^|;|\s)width\s*:\s*([^;]+)/i);
          if (widthMatch) {
            const width = widthMatch[1].trim();
            if (width && width !== '100%' && width !== 'auto') {
              styles.push(`width:${width}`);
            }
          }
          
          // Extract alignment from margin properties - more flexible matching
          const marginMatch = style.match(/margin\s*:\s*([^;]+)/i);
          const marginLeftMatch = style.match(/margin-left\s*:\s*([^;]+)/i);
          const marginRightMatch = style.match(/margin-right\s*:\s*([^;]+)/i);
          
          if (marginLeftMatch && marginRightMatch) {
            const marginLeft = marginLeftMatch[1].trim();
            const marginRight = marginRightMatch[1].trim();
            
            if (marginLeft === 'auto' && marginRight === 'auto') {
              alignment = 'center';
            } else if (marginLeft === 'auto' && (marginRight === '0' || marginRight === '0px')) {
              alignment = 'right';
            } else if ((marginLeft === '0' || marginLeft === '0px') && marginRight === 'auto') {
              alignment = 'left';
            }
          } else if (marginMatch) {
            // Handle shorthand margin property
            const margin = marginMatch[1].trim();
            if (margin.includes('auto')) {
              // Check if it's center alignment (auto on left and right)
              const marginParts = margin.split(/\s+/);
              if (marginParts.length >= 2 && marginParts[1] === 'auto') {
                alignment = 'center';
              }
            }
          }
        }
        
        if (alignment) {
          styles.push(`align:${alignment}`);
        }
        
        let result = `[IMAGE: ${alt}](${src})`;
        if (styles.length > 0) {
          result += `{${styles.join(';')}}`;
        }
        
        return result;
      })
      .replace(/<img[^>]*src="([^"]*)"[^>]*>/gi, '[IMAGE]($1)')
      .replace(/<br\s*\/?>/gi, '\n')
      // Handle div alignment
      .replace(/<div[^>]*style="[^"]*text-align:\s*center[^"]*"[^>]*>(.*?)<\/div>/gi, '<center>$1</center>')
      .replace(/<div[^>]*style="[^"]*text-align:\s*right[^"]*"[^>]*>(.*?)<\/div>/gi, '<right>$1</right>')
      .replace(/<div[^>]*style="[^"]*text-align:\s*left[^"]*"[^>]*>(.*?)<\/div>/gi, '<left>$1</left>')
      .replace(/<div[^>]*>(.*?)<\/div>/gi, '\n$1')
      .replace(/<p[^>]*style="[^"]*text-align:\s*center[^"]*"[^>]*>(.*?)<\/p>/gi, '<center>$1</center>')
      .replace(/<p[^>]*style="[^"]*text-align:\s*right[^"]*"[^>]*>(.*?)<\/p>/gi, '<right>$1</right>')
      .replace(/<p[^>]*style="[^"]*text-align:\s*left[^"]*"[^>]*>(.*?)<\/p>/gi, '<left>$1</left>')
      .replace(/<p[^>]*>/gi, '')
      .replace(/<\/p>/gi, '\n');
    
    return result.trim();
  };

  // Save cursor position
  const saveCursorPosition = () => {
    const selection = window.getSelection();
    if (selection && selection.rangeCount > 0 && editorRef.current?.contains(selection.focusNode)) {
      const range = selection.getRangeAt(0);
      lastCursorPosition.current = {
        node: range.startContainer,
        offset: range.startOffset
      };
    }
  };

  

  // Initialize editor with HTML content
  useEffect(() => {
    if (editorRef.current && viewMode === 'visual') {
      const htmlVersion = convertToHtml(value);
      const currentContent = editorRef.current.innerHTML;
      
      // Normalize both for comparison, but be more precise about image tags
      const normalizeForComparison = (html: string) => {
        return html
          .replace(/\s+/g, ' ')
          .replace(/>\s+</g, '><')
          .trim();
      };
      
      const normalizedCurrent = normalizeForComparison(currentContent);
      const normalizedNew = normalizeForComparison(htmlVersion);
      
      // Only update if content has meaningfully changed
      if (normalizedCurrent !== normalizedNew) {
        // Additional check: don't update if only image styles might have changed
        const currentImages = currentContent.match(/<img[^>]*>/gi) || [];
        const newImages = htmlVersion.match(/<img[^>]*>/gi) || [];
        
        // If same number of images and they have the same src, might just be style changes
        // In that case, preserve the current state to avoid losing user's size/alignment changes
        if (currentImages.length === newImages.length && currentImages.length > 0) {
          const currentSrcs = currentImages.map(img => {
            const match = img.match(/src=["']([^"']+)["']/);
            return match ? match[1] : '';
          }).sort();
          const newSrcs = newImages.map(img => {
            const match = img.match(/src=["']([^"']+)["']/);
            return match ? match[1] : '';
          }).sort();
          
          // If srcs are the same, don't update to preserve image styling
          if (JSON.stringify(currentSrcs) === JSON.stringify(newSrcs)) {
            return;
          }
        }
        
        editorRef.current.innerHTML = htmlVersion || '';
      }
    }
  }, [value, viewMode]);

  // Update HTML content when switching to HTML view
  useEffect(() => {
    if (viewMode === 'html') {
      // Get the current visual content to preserve any unsaved changes
      const currentHtml = editorRef.current?.innerHTML || '';
      if (currentHtml && viewMode === 'html') {
        // Convert current visual state to markdown first, then to HTML for display
        const currentMarkdown = convertToMarkdown(currentHtml);
        setHtmlContent(convertToHtml(currentMarkdown));
      } else {
        setHtmlContent(convertToHtml(value));
      }
    }
  }, [viewMode, value]);

  const handleVisualInput = () => {
    if (editorRef.current) {
      const htmlContent = editorRef.current.innerHTML;
      const markdownContent = convertToMarkdown(htmlContent);
      
      // Always update to ensure image style changes are captured
      onChange(markdownContent);
    }
  };

  const handleClick = (event: React.MouseEvent) => {
    const target = event.target as HTMLElement;
    
    if (target.tagName === 'IMG') {
      const img = target as HTMLImageElement;
      setSelectedImage(img);
      
      // Calculate position for image controls
      const rect = img.getBoundingClientRect();
      const editorRect = editorRef.current?.getBoundingClientRect();
      
      if (editorRect) {
        setImageControlsPosition({
          x: rect.right - editorRect.left,
          y: rect.top - editorRect.top
        });
      }
    } else {
      setSelectedImage(null);
      setImageControlsPosition(null);
    }
    
    setShowColorPicker(false);
    setShowFontSizeMenu(false);
    setShowCustomColorPicker(false);
    saveCursorPosition();
  };

  const applyTextAlignment = (alignment: 'left' | 'center' | 'right' | 'justify') => {
    const selection = window.getSelection();
    if (!selection || !editorRef.current) return;

    try {
      let command = '';
      switch (alignment) {
        case 'left':
          command = 'justifyLeft';
          break;
        case 'center':
          command = 'justifyCenter';
          break;
        case 'right':
          command = 'justifyRight';
          break;
        case 'justify':
          command = 'justifyFull';
          break;
      }
      
      document.execCommand(command, false);
      handleVisualInput();
    } catch (e) {
      console.error('Text alignment error:', e);
    }
  };

  const updateImageSize = (size: string) => {
    if (selectedImage && editorRef.current?.contains(selectedImage)) {
      // Store current alignment settings
      const currentMarginLeft = selectedImage.style.marginLeft;
      const currentMarginRight = selectedImage.style.marginRight;
      const currentMarginTop = selectedImage.style.marginTop;
      const currentMarginBottom = selectedImage.style.marginBottom;
      
      // Apply new size with preserved styling
      selectedImage.style.width = size;
      selectedImage.style.height = 'auto';
      selectedImage.style.maxWidth = '100%';
      selectedImage.style.display = 'block';
      
      // Restore alignment margins exactly as they were
      selectedImage.style.marginLeft = currentMarginLeft || '0';
      selectedImage.style.marginRight = currentMarginRight || 'auto';
      selectedImage.style.marginTop = currentMarginTop || '10px';
      selectedImage.style.marginBottom = currentMarginBottom || '0px';
      
      // Force immediate update and save
      setTimeout(() => {
        if (selectedImage && editorRef.current?.contains(selectedImage)) {
          handleVisualInput();
        }
      }, 0);
    }
  };

  const updateImageAlignment = (alignment: 'left' | 'center' | 'right') => {
    if (selectedImage && editorRef.current?.contains(selectedImage)) {
      // Store current size settings
      const currentWidth = selectedImage.style.width;
      const currentHeight = selectedImage.style.height || 'auto';
      const currentMaxWidth = selectedImage.style.maxWidth || '100%';
      
      // Apply alignment with preserved size settings
      selectedImage.style.display = 'block';
      selectedImage.style.maxWidth = currentMaxWidth;
      selectedImage.style.height = currentHeight;
      if (currentWidth) {
        selectedImage.style.width = currentWidth;
      }
      
      // Set alignment margins
      switch (alignment) {
        case 'left':
          selectedImage.style.marginLeft = '0';
          selectedImage.style.marginRight = 'auto';
          break;
        case 'center':
          selectedImage.style.marginLeft = 'auto';
          selectedImage.style.marginRight = 'auto';
          break;
        case 'right':
          selectedImage.style.marginLeft = 'auto';
          selectedImage.style.marginRight = '0';
          break;
      }
      
      // Set consistent top/bottom margins
      selectedImage.style.marginTop = '10px';
      selectedImage.style.marginBottom = '0px';
      
      // Force immediate update and save
      setTimeout(() => {
        if (selectedImage && editorRef.current?.contains(selectedImage)) {
          handleVisualInput();
        }
      }, 0);
    }
  };

  const applyFormatting = (command: string, value?: string) => {
    const selection = window.getSelection();
    if (!selection || selection.rangeCount === 0) {
      alert('Please select text first to apply formatting');
      return;
    }
    
    const range = selection.getRangeAt(0);
    if (range.collapsed || range.toString().length === 0) {
      alert('Please select text first to apply formatting');
      return;
    }

    // Ensure we're working within the editor
    if (!editorRef.current?.contains(range.commonAncestorContainer)) {
      alert('Please select text within the editor');
      return;
    }

    try {
      if (command === 'bold' || command === 'italic' || command === 'underline') {
        // Get the exact selected text
        const selectedText = range.toString();
        
        // Create the wrapper element
        let wrapper;
        if (command === 'bold') {
          wrapper = document.createElement('strong');
        } else if (command === 'italic') {
          wrapper = document.createElement('em');
        } else {
          wrapper = document.createElement('u');
        }
        
        // Set the wrapper's text content to the selected text
        wrapper.textContent = selectedText;
        
        // Delete the selected content and insert the wrapper
        range.deleteContents();
        range.insertNode(wrapper);
        
        // Move cursor after the inserted element
        range.setStartAfter(wrapper);
        range.collapse(true);
        selection.removeAllRanges();
        selection.addRange(range);
      } else {
        // For other commands like formatBlock
        document.execCommand(command, false, value);
      }
      
      handleVisualInput();
    } catch (e) {
      console.error('Formatting error:', e);
      // Fallback to execCommand
      document.execCommand(command, false, value);
      handleVisualInput();
    }
  };

  const applyColor = (color: string) => {
    const selection = window.getSelection();
    if (!selection || selection.rangeCount === 0) {
      alert('Please select text first to apply color');
      return;
    }

    const range = selection.getRangeAt(0);
    if (range.toString().length === 0) {
      alert('Please select text first to apply color');
      return;
    }

    // Ensure we're working within the editor
    if (!editorRef.current?.contains(range.commonAncestorContainer)) {
      alert('Please select text within the editor');
      return;
    }

    try {
      // Get the exact selected text
      const selectedText = range.toString();
      
      // Create a span with the color
      const span = document.createElement('span');
      span.style.color = color;
      span.textContent = selectedText;
      
      // Delete the selected content and insert the span
      range.deleteContents();
      range.insertNode(span);
      
      // Move cursor after the inserted element
      range.setStartAfter(span);
      range.collapse(true);
      selection.removeAllRanges();
      selection.addRange(range);
      
      handleVisualInput();
    } catch (e) {
      // Fallback to execCommand
      document.execCommand('foreColor', false, color);
      handleVisualInput();
    }
    
    setShowColorPicker(false);
  };

  const applyFontSize = (size: string) => {
    const selection = window.getSelection();
    if (!selection || selection.rangeCount === 0) {
      alert('Please select text first to apply font size');
      return;
    }

    const range = selection.getRangeAt(0);
    if (range.toString().length === 0) {
      alert('Please select text first to apply font size');
      return;
    }

    // Ensure we're working within the editor
    if (!editorRef.current?.contains(range.commonAncestorContainer)) {
      alert('Please select text within the editor');
      return;
    }

    try {
      // Get the exact selected text
      const selectedText = range.toString();
      
      // Create a span with the font size
      const span = document.createElement('span');
      span.style.fontSize = size;
      span.textContent = selectedText;
      
      // Delete the selected content and insert the span
      range.deleteContents();
      range.insertNode(span);
      
      // Move cursor after the inserted element
      range.setStartAfter(span);
      range.collapse(true);
      selection.removeAllRanges();
      selection.addRange(range);
      
      handleVisualInput();
    } catch (e) {
      // Fallback
      document.execCommand('fontSize', false, '7');
      const fontElements = editorRef.current?.querySelectorAll('font[size="7"]');
      fontElements?.forEach(el => {
        const span = document.createElement('span');
        span.style.fontSize = size;
        span.innerHTML = el.innerHTML;
        el.parentNode?.replaceChild(span, el);
      });
      handleVisualInput();
    }
    
    setShowFontSizeMenu(false);
  };

  const insertLink = () => {
    if (linkText && linkUrl) {
      const selection = window.getSelection();
      if (selection && editorRef.current) {
        // Insert at cursor position
        const range = selection.rangeCount > 0 ? selection.getRangeAt(0) : null;
        if (range && editorRef.current.contains(range.commonAncestorContainer)) {
          const link = document.createElement('a');
          link.href = linkUrl;
          link.style.color = '#2563eb';
          link.style.textDecoration = 'underline';
          link.textContent = linkText;
          
          range.deleteContents();
          range.insertNode(link);
          
          // Move cursor after link
          range.setStartAfter(link);
          range.collapse(true);
          selection.removeAllRanges();
          selection.addRange(range);
        } else {
          // Fallback to execCommand
          const link = `<a href="${linkUrl}" style="color: #2563eb; text-decoration: underline;">${linkText}</a>`;
          document.execCommand('insertHTML', false, link);
        }
        
        handleVisualInput();
        setLinkText('');
        setLinkUrl('');
        setShowLinkDialog(false);
      }
    }
  };

  const insertImage = () => {
    if (imageUrl && editorRef.current) {
      const selection = window.getSelection();
      let imageInserted = false;
      
      if (selection && selection.rangeCount > 0) {
        const range = selection.getRangeAt(0);
        
        // Check if the selection is within the editor
        if (editorRef.current.contains(range.commonAncestorContainer)) {
          try {
            const img = document.createElement('img');
            img.src = imageUrl;
            img.alt = imageAlt || 'Image';
            img.style.maxWidth = '100%';
            img.style.height = 'auto';
            img.style.display = 'block';
            img.style.margin = '10px 0';
            
            range.deleteContents();
            range.insertNode(img);
            
            // Add a line break after the image
            const br = document.createElement('br');
            range.setStartAfter(img);
            range.insertNode(br);
            
            // Move cursor after line break
            range.setStartAfter(br);
            range.collapse(true);
            selection.removeAllRanges();
            selection.addRange(range);
            
            imageInserted = true;
          } catch (e) {
            console.error('Image insertion error:', e);
          }
        }
      }
      
      // Fallback: if no valid selection or insertion failed, append to the end
      if (!imageInserted) {
        try {
          // Focus the editor first
          editorRef.current.focus();
          
          // Create a range at the end of the content
          const range = document.createRange();
          range.selectNodeContents(editorRef.current);
          range.collapse(false); // Move to end
          
          const img = document.createElement('img');
          img.src = imageUrl;
          img.alt = imageAlt || 'Image';
          img.style.maxWidth = '100%';
          img.style.height = 'auto';
          img.style.display = 'block';
          img.style.margin = '10px 0';
          
          // Add a line break before image if content exists
          if (editorRef.current.innerHTML.trim()) {
            const br = document.createElement('br');
            range.insertNode(br);
            range.setStartAfter(br);
          }
          
          range.insertNode(img);
          
          // Add a line break after the image
          const br = document.createElement('br');
          range.setStartAfter(img);
          range.insertNode(br);
          
          // Move cursor after line break
          range.setStartAfter(br);
          range.collapse(true);
          
          const selection = window.getSelection();
          selection?.removeAllRanges();
          selection?.addRange(range);
          
          imageInserted = true;
        } catch (e) {
          console.error('Fallback image insertion error:', e);
          
          // Last resort: use innerHTML
          const imgHtml = `<img src="${imageUrl}" alt="${imageAlt || 'Image'}" style="max-width: 100%; height: auto; display: block; margin: 10px 0;" /><br />`;
          if (editorRef.current.innerHTML.trim()) {
            editorRef.current.innerHTML += '<br />' + imgHtml;
          } else {
            editorRef.current.innerHTML = imgHtml;
          }
        }
      }
      
      handleVisualInput();
      setImageUrl('');
      setImageAlt('');
      setShowImageDialog(false);
    }
  };

  const insertList = (ordered: boolean = false) => {
    const selection = window.getSelection();
    if (!selection || !editorRef.current) return;

    // Get current cursor position
    const range = selection.rangeCount > 0 ? selection.getRangeAt(0) : null;
    if (!range || !editorRef.current.contains(range.commonAncestorContainer)) {
      alert('Please place cursor in the editor first');
      return;
    }

    try {
      if (ordered) {
        document.execCommand('insertOrderedList', false);
      } else {
        document.execCommand('insertUnorderedList', false);
      }
      handleVisualInput();
    } catch (e) {
      console.error('List insertion error:', e);
    }
  };

  const handleHtmlChange = (newHtml: string) => {
    setHtmlContent(newHtml);
    const markdownText = convertToMarkdown(newHtml);
    onChange(markdownText);
  };

  const colorCategories = {
    'Blacks & Grays': [
      '#000000', '#333333', '#4A4A4A', '#666666', '#808080', '#9B9B9B', '#CCCCCC', '#FFFFFF'
    ],
    'Reds & Pinks': [
      '#8B0000', '#B22222', '#DC143C', '#F44E3B', '#FF69B4', '#FFB6C1', '#FA28FF', '#FDA1FF'
    ],
    'Oranges & Yellows': [
      '#FF8C00', '#FFA500', '#FE9200', '#FFD700', '#FCDC00', '#FFFF00', '#FFFFE0', '#FFF8DC'
    ],
    'Greens': [
      '#006400', '#228B22', '#32CD32', '#68BC00', '#A4DD00', '#ADFF2F', '#98FB98', '#90EE90'
    ],
    'Blues & Cyans': [
      '#000080', '#4169E1', '#1E90FF', '#009CE0', '#00BFFF', '#87CEEB', '#73D8FF', '#68CCCA'
    ],
    'Purples': [
      '#4B0082', '#8A2BE2', '#9932CC', '#7B64FF', '#BA55D3', '#DDA0DD', '#AEA1FF', '#E6E6FA'
    ]
  };

  const fontSizes = [
    { label: 'Small', value: '12px' },
    { label: 'Normal', value: '14px' },
    { label: 'Large', value: '18px' },
    { label: 'Extra Large', value: '24px' },
    { label: 'Huge', value: '36px' }
  ];

  const editorHeight = rows ? `${rows * 1.5}rem` : 'auto';

  return (
    <div className={className}>
      {/* Toolbar */}
      <div className="border border-gray-300 border-b-0 rounded-t-lg bg-gray-50 p-3 flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-1 flex-wrap">
          <button
            type="button"
            onClick={() => applyFormatting('bold')}
            className="p-2 rounded hover:bg-gray-100 transition-colors"
            title="Bold (select text first)"
          >
            <Bold className="w-4 h-4" />
          </button>
          
          <button
            type="button"
            onClick={() => applyFormatting('italic')}
            className="p-2 rounded hover:bg-gray-100 transition-colors"
            title="Italic (select text first)"
          >
            <Italic className="w-4 h-4" />
          </button>
          
          <button
            type="button"
            onClick={() => applyFormatting('underline')}
            className="p-2 rounded hover:bg-gray-100 transition-colors"
            title="Underline (select text first)"
          >
            <Underline className="w-4 h-4" />
          </button>
          
          <div className="w-px h-6 bg-gray-300 mx-1"></div>
          
          <button
            type="button"
            onClick={() => applyFormatting('formatBlock', 'h1')}
            className="p-2 rounded hover:bg-gray-100 transition-colors"
            title="Heading 1"
          >
            <Heading1 className="w-4 h-4" />
          </button>
          
          <button
            type="button"
            onClick={() => applyFormatting('formatBlock', 'h2')}
            className="p-2 rounded hover:bg-gray-100 transition-colors"
            title="Heading 2"
          >
            <Heading2 className="w-4 h-4" />
          </button>
          
          <div className="w-px h-6 bg-gray-300 mx-1"></div>

          {/* Text Alignment */}
          <button
            type="button"
            onClick={() => applyTextAlignment('left')}
            className="p-2 rounded hover:bg-gray-100 transition-colors"
            title="Align Left"
          >
            <AlignLeft className="w-4 h-4" />
          </button>
          
          <button
            type="button"
            onClick={() => applyTextAlignment('center')}
            className="p-2 rounded hover:bg-gray-100 transition-colors"
            title="Center Text"
          >
            <AlignCenter className="w-4 h-4" />
          </button>
          
          <button
            type="button"
            onClick={() => applyTextAlignment('right')}
            className="p-2 rounded hover:bg-gray-100 transition-colors"
            title="Align Right"
          >
            <AlignRight className="w-4 h-4" />
          </button>
          
          <button
            type="button"
            onClick={() => applyTextAlignment('justify')}
            className="p-2 rounded hover:bg-gray-100 transition-colors"
            title="Justify Text"
          >
            <AlignJustify className="w-4 h-4" />
          </button>
          
          <div className="w-px h-6 bg-gray-300 mx-1"></div>

          {/* Font Size Dropdown */}
          <div className="relative">
            <button
              type="button"
              onClick={() => {
                setShowFontSizeMenu(!showFontSizeMenu);
                setShowColorPicker(false);
              }}
              className="p-2 rounded hover:bg-gray-100 transition-colors"
              title="Font Size (select text first)"
            >
              <Type className="w-4 h-4" />
            </button>
            {showFontSizeMenu && (
              <div className="absolute top-full left-0 mt-1 bg-white border border-gray-300 rounded-lg shadow-lg z-10 min-w-[120px]">
                {fontSizes.map((size) => (
                  <button
                    key={size.value}
                    type="button"
                    onClick={() => applyFontSize(size.value)}
                    className="w-full px-3 py-2 text-left hover:bg-gray-100 first:rounded-t-lg last:rounded-b-lg"
                    style={{ fontSize: size.value }}
                  >
                    {size.label}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Color Picker Dropdown */}
          <div className="relative">
            <button
              type="button"
              onClick={() => {
                setShowColorPicker(!showColorPicker);
                setShowFontSizeMenu(false);
                setShowCustomColorPicker(false);
              }}
              className="p-2 rounded hover:bg-gray-100 transition-colors"
              title="Text Color (select text first)"
            >
              <Palette className="w-4 h-4" />
            </button>
            {showColorPicker && (
              <div className="absolute top-full left-0 mt-1 bg-white border border-gray-300 rounded-lg shadow-lg z-10 p-4 w-80">
                <h4 className="text-sm font-medium mb-3">Choose Color</h4>
                
                {/* Color Categories */}
                <div className="space-y-3 mb-4">
                  {Object.entries(colorCategories).map(([category, colors]) => (
                    <div key={category}>
                      <h5 className="text-xs font-medium text-gray-600 mb-1">{category}</h5>
                      <div className="grid grid-cols-8 gap-1">
                        {colors.map((color) => (
                          <button
                            key={color}
                            type="button"
                            onClick={() => applyColor(color)}
                            className="w-6 h-6 rounded border border-gray-300 hover:border-gray-500 hover:scale-110 transition-all shadow-sm"
                            style={{ backgroundColor: color }}
                            title={color}
                          />
                        ))}
                      </div>
                    </div>
                  ))}
                </div>

                {/* Custom Color Section */}
                <div className="border-t pt-3">
                  <div className="flex items-center justify-between mb-2">
                    <h5 className="text-xs font-medium text-gray-600">Custom Color</h5>
                    <button
                      type="button"
                      onClick={() => setShowCustomColorPicker(!showCustomColorPicker)}
                      className="text-xs text-blue-600 hover:text-blue-800"
                    >
                      {showCustomColorPicker ? 'Hide' : 'Advanced'}
                    </button>
                  </div>
                  
                  <div className="flex items-center gap-2">
                    <input
                      type="color"
                      value={customColor}
                      onChange={(e) => setCustomColor(e.target.value)}
                      className="w-8 h-8 rounded border border-gray-300 cursor-pointer"
                      title="Pick custom color"
                    />
                    <input
                      type="text"
                      value={customColor}
                      onChange={(e) => setCustomColor(e.target.value)}
                      placeholder="#000000"
                      className="flex-1 px-2 py-1 text-xs border border-gray-300 rounded focus:ring-1 focus:ring-blue-500"
                    />
                    <button
                      type="button"
                      onClick={() => applyColor(customColor)}
                      className="px-2 py-1 text-xs bg-blue-600 text-white rounded hover:bg-blue-700"
                    >
                      Apply
                    </button>
                  </div>

                  {showCustomColorPicker && (
                    <div className="mt-3 p-3 bg-gray-50 rounded-lg">
                      <div className="grid grid-cols-12 gap-1 mb-2">
                        {/* Color spectrum - generate more precise colors */}
                        {Array.from({ length: 144 }, (_, i) => {
                          const hue = (i % 12) * 30;
                          const saturation = Math.floor(i / 12) < 6 ? 100 - (Math.floor(i / 12) * 20) : 100;
                          const lightness = Math.floor(i / 12) < 6 ? 50 : 20 + (Math.floor(i / 12) - 6) * 15;
                          const color = `hsl(${hue}, ${saturation}%, ${lightness}%)`;
                          return (
                            <button
                              key={i}
                              type="button"
                              onClick={() => {
                                // Convert HSL to HEX for consistency
                                const tempDiv = document.createElement('div');
                                tempDiv.style.color = color;
                                document.body.appendChild(tempDiv);
                                const computedColor = window.getComputedStyle(tempDiv).color;
                                document.body.removeChild(tempDiv);
                                
                                // Extract RGB values and convert to hex
                                const rgb = computedColor.match(/\d+/g);
                                if (rgb) {
                                  const hex = '#' + rgb.map((x) => {
                                    const hex = parseInt(x).toString(16);
                                    return hex.length === 1 ? '0' + hex : hex;
                                  }).join('');
                                  setCustomColor(hex);
                                  applyColor(hex);
                                }
                              }}
                              className="w-3 h-3 rounded-sm border border-gray-200 hover:scale-150 transition-transform"
                              style={{ backgroundColor: color }}
                              title={color}
                            />
                          );
                        })}
                      </div>
                      <p className="text-xs text-gray-500">Click any color above to use it</p>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
          
          <div className="w-px h-6 bg-gray-300 mx-1"></div>
          
          <button
            type="button"
            onClick={() => insertList(false)}
            className="p-2 rounded hover:bg-gray-100 transition-colors"
            title="Bullet List"
          >
            <List className="w-4 h-4" />
          </button>
          
          <button
            type="button"
            onClick={() => insertList(true)}
            className="p-2 rounded hover:bg-gray-100 transition-colors"
            title="Numbered List"
          >
            <ListOrdered className="w-4 h-4" />
          </button>
          
          <div className="w-px h-6 bg-gray-300 mx-1"></div>
          
          <button
            type="button"
            onClick={() => setShowLinkDialog(true)}
            className="p-2 rounded hover:bg-gray-100 transition-colors"
            title="Insert Link"
          >
            <Link className="w-4 h-4" />
          </button>
          
          <button
            type="button"
            onClick={() => setShowImageDialog(true)}
            className="p-2 rounded hover:bg-gray-100 transition-colors"
            title="Insert Image"
          >
            <Image className="w-4 h-4" />
          </button>
        </div>

        {/* View Mode Toggle */}
        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={() => setViewMode('visual')}
            className={`px-3 py-1 text-sm rounded transition-colors ${
              viewMode === 'visual' ? 'bg-blue-100 text-blue-700' : 'hover:bg-gray-100'
            }`}
          >
            <Eye className="w-3 h-3 inline mr-1" />
            Visual
          </button>
          <button
            type="button"
            onClick={() => setViewMode('html')}
            className={`px-3 py-1 text-sm rounded transition-colors ${
              viewMode === 'html' ? 'bg-blue-100 text-blue-700' : 'hover:bg-gray-100'
            }`}
          >
            <Code className="w-3 h-3 inline mr-1" />
            HTML
          </button>
        </div>
      </div>

      {/* Editor Content */}
      {viewMode === 'visual' ? (
        <div
          ref={editorRef}
          contentEditable
          onInput={handleVisualInput}
          onBlur={handleVisualInput}
          onKeyUp={saveCursorPosition}
          onMouseUp={saveCursorPosition}
          onClick={handleClick}
          className="w-full px-4 py-2 border border-gray-300 rounded-b-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent focus:outline-none overflow-y-auto relative"
          style={{ 
            minHeight: editorHeight,
            maxHeight: '400px'
          }}
          data-placeholder={placeholder}
        />
      ) : (
        <textarea
          value={htmlContent}
          onChange={(e) => handleHtmlChange(e.target.value)}
          placeholder="Edit HTML directly..."
          rows={rows}
          className="w-full px-4 py-2 border border-gray-300 rounded-b-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none font-mono text-sm"
        />
      )}

      {/* Link Dialog */}
      {showLinkDialog && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Insert Link</h3>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Link Text
                </label>
                <input
                  type="text"
                  value={linkText}
                  onChange={(e) => setLinkText(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="Click here"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  URL
                </label>
                <input
                  type="url"
                  value={linkUrl}
                  onChange={(e) => setLinkUrl(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="https://example.com"
                />
              </div>
            </div>
            
            <div className="flex justify-end gap-3 mt-6">
              <button
                type="button"
                onClick={() => setShowLinkDialog(false)}
                className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={insertLink}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                disabled={!linkText || !linkUrl}
              >
                Insert Link
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Image Dialog */}
      {showImageDialog && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Insert Image</h3>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Image URL <span className="text-red-500">*</span>
                </label>
                <input
                  type="url"
                  value={imageUrl}
                  onChange={(e) => setImageUrl(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="https://example.com/image.jpg"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Alt Text (optional)
                </label>
                <input
                  type="text"
                  value={imageAlt}
                  onChange={(e) => setImageAlt(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="Description of image"
                />
              </div>
            </div>
            
            <div className="flex justify-end gap-3 mt-6">
              <button
                type="button"
                onClick={() => {
                  setShowImageDialog(false);
                  setImageUrl('');
                  setImageAlt('');
                }}
                className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={insertImage}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                disabled={!imageUrl}
              >
                Insert Image
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Image Controls */}
      {selectedImage && imageControlsPosition && (
        <div 
          className="absolute bg-white border border-gray-300 rounded-lg shadow-lg p-3 z-20"
          style={{
            left: `${imageControlsPosition.x + 10}px`,
            top: `${imageControlsPosition.y}px`
          }}
        >
          <div className="text-xs font-medium text-gray-700 mb-2">Image Controls</div>
          
          {/* Size Controls */}
          <div className="mb-3">
            <div className="text-xs text-gray-600 mb-1">Size</div>
            <div className="flex gap-1">
              <button
                type="button"
                onClick={() => updateImageSize('25%')}
                className="px-2 py-1 text-xs border border-gray-300 rounded hover:bg-gray-100"
              >
                25%
              </button>
              <button
                type="button"
                onClick={() => updateImageSize('50%')}
                className="px-2 py-1 text-xs border border-gray-300 rounded hover:bg-gray-100"
              >
                50%
              </button>
              <button
                type="button"
                onClick={() => updateImageSize('75%')}
                className="px-2 py-1 text-xs border border-gray-300 rounded hover:bg-gray-100"
              >
                75%
              </button>
              <button
                type="button"
                onClick={() => updateImageSize('100%')}
                className="px-2 py-1 text-xs border border-gray-300 rounded hover:bg-gray-100"
              >
                100%
              </button>
            </div>
          </div>

          {/* Alignment Controls */}
          <div className="mb-2">
            <div className="text-xs text-gray-600 mb-1">Alignment</div>
            <div className="flex gap-1">
              <button
                type="button"
                onClick={() => updateImageAlignment('left')}
                className="p-1 border border-gray-300 rounded hover:bg-gray-100"
                title="Align Left"
              >
                <AlignLeft className="w-3 h-3" />
              </button>
              <button
                type="button"
                onClick={() => updateImageAlignment('center')}
                className="p-1 border border-gray-300 rounded hover:bg-gray-100"
                title="Center"
              >
                <AlignCenter className="w-3 h-3" />
              </button>
              <button
                type="button"
                onClick={() => updateImageAlignment('right')}
                className="p-1 border border-gray-300 rounded hover:bg-gray-100"
                title="Align Right"
              >
                <AlignRight className="w-3 h-3" />
              </button>
            </div>
          </div>

          <button
            type="button"
            onClick={() => {
              setSelectedImage(null);
              setImageControlsPosition(null);
            }}
            className="text-xs text-gray-500 hover:text-gray-700 w-full text-center"
          >
            Close
          </button>
        </div>
      )}

      <style>{`
        [contenteditable]:empty:before {
          content: attr(data-placeholder);
          color: #9ca3af;
          pointer-events: none;
        }
        [contenteditable] {
          white-space: pre-wrap;
        }
        [contenteditable] ul, [contenteditable] ol {
          margin-left: 1.5em;
          margin-top: 0.5em;
          margin-bottom: 0.5em;
        }
        [contenteditable] li {
          margin-bottom: 0.25em;
        }
        [contenteditable] img {
          max-width: 100%;
          height: auto;
          display: block;
          margin: 10px 0;
          cursor: pointer;
        }
        [contenteditable] img:hover {
          outline: 2px solid #3b82f6;
          outline-offset: 2px;
        }
        [contenteditable] img.selected {
          outline: 2px solid #3b82f6;
          outline-offset: 2px;
        }
      `}</style>
    </div>
  );
}
