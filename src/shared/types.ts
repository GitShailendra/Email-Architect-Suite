import z from "zod";

// Email block types
export const EmailBlockType = z.enum([
  "welcome",
  "follow-up", 
  "offer",
  "reminder",
  "upsell",
  "abandon-cart",
  "reactivation"
]);

export type EmailBlockTypeT = z.infer<typeof EmailBlockType>;

// Email block schema
export const EmailBlockSchema = z.object({
  id: z.string(),
  sequence_id: z.string(),
  type: EmailBlockType,
  name: z.string(),
  subject_line: z.string().optional(),
  preview_text: z.string().optional(),
  body_copy: z.string().optional(),
  cta_text: z.string().optional(),
  cta_url: z.string().optional(),
  send_delay_hours: z.number().default(0),
  position_x: z.number().default(0),
  position_y: z.number().default(0),
  notes: z.string().optional(),
  created_at: z.string(),
  updated_at: z.string(),
});

export type EmailBlock = z.infer<typeof EmailBlockSchema>;

// Sequence schema
export const SequenceSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string().optional(),
  user_id: z.string(),
  created_at: z.string(),
  updated_at: z.string(),
});

export type Sequence = z.infer<typeof SequenceSchema>;

// Connection schema
export const ConnectionSchema = z.object({
  id: z.string(),
  sequence_id: z.string(),
  source_block_id: z.string(),
  target_block_id: z.string(),
  condition_type: z.enum(["default", "opened", "clicked", "not_opened", "not_clicked", "purchased", "not_purchased"]).default("default"),
  custom_label: z.string().optional(),
  created_at: z.string(),
  updated_at: z.string(),
});

export type Connection = z.infer<typeof ConnectionSchema>;

// Template schema
export const TemplateSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string().optional(),
  created_by_user_id: z.string(),
  is_public: z.boolean().default(false),
  sequence_data: z.string(), // JSON string
  created_at: z.string(),
  updated_at: z.string(),
});

export type Template = z.infer<typeof TemplateSchema>;

// Block type configurations
export const BLOCK_TYPE_CONFIG: Record<EmailBlockTypeT, {
  label: string;
  color: string;
  bgColor: string;
  borderColor: string;
  icon: string;
  defaultName: string;
  questions: string[];
}> = {
  welcome: {
    label: "Welcome",
    color: "text-blue-700",
    bgColor: "bg-blue-50",
    borderColor: "border-blue-200",
    icon: "👋",
    defaultName: "Welcome Email",
    questions: [
      "What is your product, offer, or promotion about?",
      "What's your product/service name?",
      "Who is your target audience?"
    ]
  },
  "follow-up": {
    label: "Follow-Up",
    color: "text-green-700",
    bgColor: "bg-green-50", 
    borderColor: "border-green-200",
    icon: "📧",
    defaultName: "Follow-Up Email",
    questions: [
      "What is your product, offer, or promotion about?",
      "What's the main benefit or result to highlight?",
      "What action do you want them to take next?"
    ]
  },
  offer: {
    label: "Offer",
    color: "text-purple-700",
    bgColor: "bg-purple-50",
    borderColor: "border-purple-200", 
    icon: "🎁",
    defaultName: "Special Offer",
    questions: [
      "What is your product, offer, or promotion about?",
      "What's the discount or promotion?",
      "What creates urgency? (limited time, limited spots, etc.)"
    ]
  },
  reminder: {
    label: "Reminder",
    color: "text-orange-700",
    bgColor: "bg-orange-50",
    borderColor: "border-orange-200",
    icon: "⏰",
    defaultName: "Reminder Email",
    questions: [
      "What is your product, offer, or promotion about?",
      "What are you reminding them about?",
      "What's the deadline or urgency?"
    ]
  },
  upsell: {
    label: "Upsell",
    color: "text-red-700", 
    bgColor: "bg-red-50",
    borderColor: "border-red-200",
    icon: "⬆️",
    defaultName: "Upsell Offer",
    questions: [
      "What is your product, offer, or promotion about?",
      "What's the upgrade offer?",
      "Why is it valuable to them?"
    ]
  },
  "abandon-cart": {
    label: "Abandon Cart",
    color: "text-yellow-700",
    bgColor: "bg-yellow-50",
    borderColor: "border-yellow-200",
    icon: "🛒",
    defaultName: "Abandon Cart Recovery",
    questions: [
      "What is your product, offer, or promotion about?",
      "What product was left behind?",
      "What incentive will you offer to complete purchase?"
    ]
  },
  reactivation: {
    label: "Reactivation",
    color: "text-pink-700",
    bgColor: "bg-pink-50",
    borderColor: "border-pink-200",
    icon: "🔄",
    defaultName: "Reactivation Campaign",
    questions: [
      "What is your product, offer, or promotion about?",
      "What's new since they last engaged?",
      "What return incentive are you offering?"
    ]
  }
};

// Condition type configurations
export const CONDITION_TYPE_CONFIG = {
  default: { label: "Always", color: "text-gray-700" },
  opened: { label: "If Opened", color: "text-green-700" },
  clicked: { label: "If Clicked", color: "text-blue-700" },
  not_opened: { label: "If Not Opened", color: "text-red-700" },
  not_clicked: { label: "If Not Clicked", color: "text-orange-700" },
  purchased: { label: "If Purchased", color: "text-purple-700" },
  not_purchased: { label: "If Not Purchased", color: "text-pink-700" }
};

// API schemas
export const CreateSequenceSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
});

export const CreateEmailBlockSchema = z.object({
  sequence_id: z.string(),
  type: EmailBlockType,
  name: z.string(),
  position_x: z.number().default(0),
  position_y: z.number().default(0),
});

export const UpdateEmailBlockSchema = z.object({
  name: z.string().optional(),
  subject_line: z.string().optional(),
  preview_text: z.string().optional(),
  body_copy: z.string().optional(),
  cta_text: z.string().optional(),
  cta_url: z.string().optional(),
  send_delay_hours: z.number().optional(),
  position_x: z.number().optional(),
  position_y: z.number().optional(),
  notes: z.string().optional(),
});

export const CreateConnectionSchema = z.object({
  sequence_id: z.string(),
  source_block_id: z.string(),
  target_block_id: z.string(),
  condition_type: z.enum(["default", "opened", "clicked", "not_opened", "not_clicked", "purchased", "not_purchased"]).default("default"),
  custom_label: z.string().optional(),
});

export const CreateTemplateSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  is_public: z.boolean().default(false),
});

export const ExportSequenceSchema = z.object({
  format: z.enum(["csv", "txt", "html", "json"]),
});

// AI Content Generation
export const GenerateContentSchema = z.object({
  type: EmailBlockType,
  answers: z.record(z.string()),
  tone: z.enum(["friendly", "professional", "casual", "persuasive", "urgent"]).default("friendly"),
  custom_subject: z.string().optional(),
  custom_cta: z.string().optional(),
});

export type GenerateContentRequest = z.infer<typeof GenerateContentSchema>;
