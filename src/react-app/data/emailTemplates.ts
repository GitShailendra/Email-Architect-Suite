import { EmailBlockTypeT } from '@/shared/types';

export interface EmailTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  icon: string;
  color: string;
  bgColor: string;
  borderColor: string;
  blocks: Array<{
    type: EmailBlockTypeT;
    name: string;
    subject_line: string;
    preview_text: string;
    body_copy: string;
    cta_text: string;
    cta_url: string;
    send_delay_hours: number;
    position_x: number;
    position_y: number;
  }>;
  connections: Array<{
    source_index: number;
    target_index: number;
    condition_type: string;
  }>;
}

export const TEMPLATE_CATEGORIES = [
  { id: 'onboarding', name: 'Onboarding', icon: '👋', color: 'blue' },
  { id: 'lead-generation', name: 'Lead Generation', icon: '🌱', color: 'green' },
  { id: 'sales', name: 'Sales & Conversion', icon: '💰', color: 'purple' },
  { id: 'ecommerce', name: 'E-commerce', icon: '🛒', color: 'yellow' },
  { id: 'retention', name: 'Retention & Loyalty', icon: '🔄', color: 'pink' },
  { id: 'marketing', name: 'Marketing Campaigns', icon: '🚀', color: 'indigo' },
  { id: 'education', name: 'Education & Courses', icon: '🎓', color: 'violet' },
  { id: 'events', name: 'Event Marketing', icon: '🎥', color: 'cyan' },
];

export const SUBJECT_LINE_TEMPLATES = {
  welcome: [
    "Welcome to [PRODUCT NAME]! Here's what's next...",
    "🎉 You're in! Your [PRODUCT NAME] journey starts now",
    "Thanks for joining [PRODUCT NAME] - let's get started!",
    "Your [PRODUCT NAME] account is ready. Here's your first step",
    "Welcome aboard! Here's how to get the most from [PRODUCT NAME]"
  ],
  "follow-up": [
    "How are you enjoying [PRODUCT NAME] so far?",
    "Quick check-in: Need help with [PRODUCT NAME]?",
    "Your [PRODUCT NAME] progress looks great! Here's what's next",
    "Don't miss out on these [PRODUCT NAME] features",
    "Ready to take [PRODUCT NAME] to the next level?"
  ],
  "webinar-promotion": [
    "🔴 LIVE: Join the exclusive webinar tomorrow",
    "Last chance: Webinar starts in 2 hours", 
    "Breaking: New webinar series announced for [TOPIC]",
    "RSVP Required: Limited spots for tomorrow's [WEBINAR TITLE]",
    "Going live in 24 hours: [WEBINAR TITLE] masterclass"
  ],
  "product-update": [
    "🚀 New update: [FEATURE] is now live in [PRODUCT]",
    "You asked, we delivered: [NEW FEATURE] is here",
    "Product update: 3 new features you'll love",
    "Fresh from development: [PRODUCT] just got better",
    "Surprise! We just released [FEATURE] early"
  ],
  "course-launch": [
    "📚 Now open: [COURSE NAME] enrollment",
    "Class starts Monday: Secure your spot in [COURSE NAME]",
    "Limited enrollment: [COURSE NAME] now accepting students",
    "🎓 Master [SKILL] in 30 days with [COURSE NAME]",
    "Early bird pricing: Save 40% on [COURSE NAME]"
  ],
  offer: [
    "🎁 Special offer just for you: [DISCOUNT]% off [PRODUCT NAME]",
    "Limited time: Save [DISCOUNT]% on [PRODUCT NAME]",
    "Your exclusive [PRODUCT NAME] discount expires soon",
    "Flash sale: [DISCOUNT]% off [PRODUCT NAME] (24 hours only)",
    "VIP pricing: Get [PRODUCT NAME] for [DISCOUNT]% off"
  ],
  reminder: [
    "⏰ Don't forget: [ACTION] deadline is tomorrow",
    "Final reminder: [ACTION] expires in 24 hours",
    "Last chance to [ACTION] before it's gone",
    "Time is running out to [ACTION]",
    "48 hours left to [ACTION] - don't miss out!"
  ],
  upsell: [
    "Ready to upgrade your [PRODUCT NAME] experience?",
    "Unlock premium features: Upgrade to [PRODUCT NAME] Pro",
    "Take [PRODUCT NAME] to the next level with these features",
    "Your [PRODUCT NAME] upgrade is waiting (special price inside)",
    "Why [CUSTOMER NAME] upgraded to [PRODUCT NAME] Pro"
  ],
  "abandon-cart": [
    "You left something in your cart...",
    "Still thinking about [PRODUCT NAME]?",
    "Your [PRODUCT NAME] is waiting for you",
    "Complete your order: [PRODUCT NAME] + 10% discount",
    "Don't miss out on [PRODUCT NAME] (free shipping included)"
  ],
  reactivation: [
    "We miss you! Here's what you've been missing",
    "Come back to [PRODUCT NAME] - we have exciting updates",
    "Your [PRODUCT NAME] account has been waiting for you",
    "We've improved [PRODUCT NAME] - come see what's new",
    "Special welcome back offer: Return to [PRODUCT NAME]"
  ]
};

export const CTA_TEMPLATES = {
  welcome: [
    "Get Started Now",
    "Complete Setup",
    "Start Your Journey",
    "Begin Today",
    "Take the First Step"
  ],
  "follow-up": [
    "Continue Learning",
    "Explore More",
    "Next Steps",
    "Keep Going",
    "Learn More"
  ],
  offer: [
    "Shop Now",
    "Claim Discount",
    "Save Today",
    "Get This Deal",
    "Buy Now & Save"
  ],
  reminder: [
    "Don't Miss Out",
    "Act Now",
    "Claim Before Expiry",
    "Secure Your Spot",
    "Complete Now"
  ],
  upsell: [
    "Upgrade Now",
    "Unlock Premium",
    "Get Pro Features",
    "Upgrade Today",
    "Go Premium"
  ],
  "abandon-cart": [
    "Complete Purchase",
    "Finish Order",
    "Buy Now",
    "Return to Cart",
    "Complete Checkout"
  ],
  reactivation: [
    "Welcome Back",
    "Restart Journey",
    "Reactivate Account",
    "Come Back",
    "Try Again"
  ],
  "webinar-promotion": [
    "Reserve My Seat",
    "Join the Webinar",
    "Register Now",
    "Save My Spot",
    "Attend Live"
  ],
  "product-update": [
    "Try It Now",
    "Explore Features",
    "Update Now",
    "See What's New",
    "Get the Update"
  ],
  "course-launch": [
    "Enroll Today",
    "Join the Course",
    "Start Learning",
    "Claim Early Bird",
    "Secure Your Spot"
  ]
};

export const EMAIL_TEMPLATES: EmailTemplate[] = [
  {
    id: 'welcome-series',
    name: 'Welcome Series',
    description: 'Complete 3-email welcome sequence for new subscribers',
    category: 'onboarding',
    icon: '👋',
    color: 'text-blue-700',
    bgColor: 'bg-blue-50',
    borderColor: 'border-blue-200',
    blocks: [
      {
        type: 'welcome',
        name: 'Welcome Email',
        subject_line: '🎉 Welcome to [PRODUCT NAME]! Here\'s what\'s next...',
        preview_text: 'Thanks for joining us! Here\'s how to get started',
        body_copy: 'Hi **[FIRST NAME]**,\n\n# Welcome to [PRODUCT NAME]! 🎉\n\nThanks for joining us — we\'re excited to have you on board.\n\nWith [PRODUCT NAME], you\'ll be able to **[PRIMARY OUTCOME]** without the usual overwhelm.\n\nHere\'s what you can do next:\n\n1. **Log in to your account** and take a quick look around.\n2. **Complete your basic setup** so the app can start working for you.\n3. **Save this email** so you can always find your login and support links.\n\nOver the next few days, we\'ll send you short, practical tips to help you get results fast — no fluff.\n\nIf you ever feel stuck, just hit reply. A real person on our team will help you out.\n\nTalk soon,\n**The [PRODUCT NAME] Team**',
        cta_text: '✨ Complete Setup Now',
        cta_url: 'https://yourapp.com/setup',
        send_delay_hours: 0,
        position_x: 100,
        position_y: 100,
      },
      {
        type: 'follow-up',
        name: 'Getting Started Tips',
        subject_line: '💡 Your first week with [PRODUCT NAME]: Pro tips inside',
        preview_text: 'Make the most of your first week with these insider tips',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## How\'s your first week with [PRODUCT NAME]? 👋\n\nTo help you get value quickly, here are three simple steps our most successful users follow:\n\n### 1️⃣ Complete your core setup\nFinish your onboarding checklist inside [PRODUCT NAME] so everything is configured correctly. A solid setup now saves you hours later.\n\n### 2️⃣ Use [KEY FEATURE] at least once\nThis is the feature that usually creates the first "aha" moment. Try it today on a real task so you see what\'s possible.\n\n### 3️⃣ Review the quick-start resources\nInside your dashboard you\'ll find a short guide and a few examples. They\'ll show you how other users are using [PRODUCT NAME] to get results.\n\n---\n\n💬 Questions, ideas, or feedback? Just reply to this email — we read every message.\n\nYou\'ve got this,\n**The [PRODUCT NAME] Team**',
        cta_text: '🎯 View Pro Tips',
        cta_url: 'https://yourapp.com/tips',
        send_delay_hours: 168,
        position_x: 450,
        position_y: 100,
      },
      {
        type: 'offer',
        name: 'Special Upgrade Offer',
        subject_line: '🎁 Exclusive upgrade offer: 30% off Premium',
        preview_text: 'Limited time offer just for new members',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## Ready to Get Even More From [PRODUCT NAME]? 🚀\n\nYou\'ve had some time to explore [PRODUCT NAME]. If you\'re starting to see the potential, now is the perfect moment to unlock our **Premium plan**.\n\nFor a limited time, you can upgrade with an **exclusive [X]% discount** available only to new users.\n\nWith Premium, you\'ll get:\n\n- 📊 **Advanced analytics** to see exactly what\'s working\n- ⚡ **Automation tools** so repetitive work runs on autopilot\n- 🔗 **Expanded integrations** with your favorite platforms\n- 🎨 **Custom branding** to keep everything on-brand\n- 🛟 **Priority support** when you need fast answers\n\nIf you\'re serious about [MAIN BENEFIT / OUTCOME], this upgrade will give you the speed and control to get there faster.\n\n⏰ This special new-user pricing is time-limited, so if you\'re considering Premium, now is the best time to lock it in.\n\nTalk soon,\n**The [PRODUCT NAME] Team**',
        cta_text: '🚀 Upgrade to Premium',
        cta_url: 'https://yourapp.com/upgrade?discount=WELCOME30',
        send_delay_hours: 336,
        position_x: 800,
        position_y: 100,
      }
    ],
    connections: [
      { source_index: 0, target_index: 1, condition_type: 'default' },
      { source_index: 1, target_index: 2, condition_type: 'opened' }
    ]
  },
  {
    id: 'trial-conversion',
    name: 'Free Trial to Paid Conversion',
    description: '4-email sequence to convert trial users into paying customers',
    category: 'onboarding',
    icon: '💳',
    color: 'text-blue-700',
    bgColor: 'bg-blue-50',
    borderColor: 'border-blue-200',
    blocks: [
      {
        type: 'welcome',
        name: 'Trial Welcome',
        subject_line: '🎉 Your free trial starts now!',
        preview_text: 'Get the most out of your 14-day trial',
        body_copy: 'Hi **[FIRST NAME]**,\n\n# Your Free Trial Is Live 🎉\n\nWelcome to your **[TRIAL LENGTH]-day trial** of [PRODUCT NAME]!\n\nThese next days are all about one thing: helping you see how [PRODUCT NAME] can make [SPECIFIC TASK/PROCESS] easier and more effective.\n\n## Here\'s how to get started today:\n\n1. **Log in** and complete the basic setup.\n2. **Run your first [KEY ACTION]** so you see a real result, not just a demo.\n3. **Bookmark your dashboard** so it\'s easy to come back.\n\nDuring your trial you have access to:\n\n- All core features\n- [X] projects or campaigns\n- Essential integrations\n- Help docs and email support\n\nWe\'ll send you a few short emails to guide you, but if you\'d rather talk to a human, just reply and we\'ll help you set things up.\n\nLet\'s make this trial count,\n**The [PRODUCT NAME] Team**',
        cta_text: '🚀 Start Your Journey',
        cta_url: 'https://yourapp.com/onboarding',
        send_delay_hours: 0,
        position_x: 100,
        position_y: 100,
      },
      {
        type: 'follow-up',
        name: 'Mid-Trial Check-in',
        subject_line: '📊 You\'re halfway through your trial',
        preview_text: 'How\'s it going so far?',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## You\'re Halfway Through Your Trial 🎯\n\nYou have about **[X] days left** to test [PRODUCT NAME] in your real workflow.\n\nTo make the most of it, here are a few features many trial users haven\'t explored yet:\n\n- **[FEATURE 1]** – great for saving time on [BENEFIT]\n- **[FEATURE 2]** – helps you automate [PROCESS]\n- **[FEATURE 3]** – gives you clarity on [METRIC / RESULT]\n\nPick one of these features and try it today on a real project. That\'s usually where things "click" and you see if [PRODUCT NAME] is right for you.\n\nIf you\'re unsure what to try next, reply to this email and tell us what you\'re working on. We\'ll suggest a simple next step.\n\nKeep going,\n**The [PRODUCT NAME] Team**',
        cta_text: '🎯 Explore Features',
        cta_url: 'https://yourapp.com/features',
        send_delay_hours: 168,
        position_x: 450,
        position_y: 100,
      },
      {
        type: 'reminder',
        name: '3 Days Left Warning',
        subject_line: '⏰ Only 3 days left in your trial',
        preview_text: 'Don\'t lose access to your work',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## Your Trial Ends in 3 Days ⏰\n\nJust a quick reminder: your [PRODUCT NAME] trial will end in **3 days**.\n\nWhen it ends:\n\n- You\'ll lose access to **premium features**\n- Some actions and automations will **pause**\n- Access to certain data and reports may be **restricted**\n\nIf [PRODUCT NAME] is helping you with **[OUTCOME]**, now is a good time to decide how you\'d like to continue.\n\n## Continue without interruption\n\nWhen you upgrade to a paid plan, you\'ll:\n\n- Keep all your existing projects and data\n- Maintain your current setup and automations\n- Unlock ongoing support and improvements\n\nWe\'ve added a **[X]% discount** for trial users who upgrade before the trial ends.\n\n**Code:** TRIAL20\n\nIf you have questions about which plan is right for you, just hit reply.\n\nThanks for trying [PRODUCT NAME],\n**The [PRODUCT NAME] Team**',
        cta_text: '💎 Upgrade Now',
        cta_url: 'https://yourapp.com/upgrade?code=TRIAL20',
        send_delay_hours: 264,
        position_x: 800,
        position_y: 100,
      },
      {
        type: 'offer',
        name: 'Final Day',
        subject_line: '🚨 FINAL DAY: Your trial expires tonight',
        preview_text: 'Last chance to save your work',
        body_copy: 'Hi **[FIRST NAME]**,\n\n# Last Day of Your Free Trial 🚨\n\nYour [PRODUCT NAME] trial **expires tonight at midnight**.\n\nIf you\'d like to keep:\n\n- Your existing projects and configurations\n- Any automations you\'ve already set up\n- Access to your saved data and reports\n\n…you\'ll need to upgrade to a paid plan before the trial ends.\n\n## Extended trial discount\n\nWe\'ve extended your **[X]% discount** for another 24 hours as a thank-you for testing [PRODUCT NAME].\n\n**Use code:** TRIAL20 at checkout.\n\nIf you\'re on the fence, reply and tell us what you\'re unsure about — we\'ll give you honest guidance, even if that means recommending a different plan.\n\nThank you for giving us a try,\n**The [PRODUCT NAME] Team**',
        cta_text: '🔥 Save My Work',
        cta_url: 'https://yourapp.com/upgrade?code=TRIAL20',
        send_delay_hours: 312,
        position_x: 1150,
        position_y: 100,
      }
    ],
    connections: [
      { source_index: 0, target_index: 1, condition_type: 'default' },
      { source_index: 1, target_index: 2, condition_type: 'default' },
      { source_index: 2, target_index: 3, condition_type: 'not_clicked' }
    ]
  },
  {
    id: 'product-launch',
    name: 'Product Launch Sequence',
    description: 'Build anticipation and drive sales for new product launches',
    category: 'marketing',
    icon: '🚀',
    color: 'text-purple-700',
    bgColor: 'bg-purple-50',
    borderColor: 'border-purple-200',
    blocks: [
      {
        type: 'welcome',
        name: 'Pre-Launch Announcement',
        subject_line: '🚀 Something big is coming...',
        preview_text: 'Get ready for our biggest launch yet',
        body_copy: 'Hi **[FIRST NAME]**,\n\n# Something New Is Coming Soon 👀\n\nWe\'ve been quietly working on a new project behind the scenes, and we\'re almost ready to share it.\n\nOn **[LAUNCH DATE]**, we\'re releasing **[NEW PRODUCT NAME]** — a solution designed to help you **[KEY BENEFIT / OUTCOME]** without [COMMON PAIN].\n\nAs a subscriber, you\'ll get:\n\n- Early access before the general public\n- Special launch-only pricing\n- Bonus content and resources worth **$[VALUE]**\n\nOver the next few days we\'ll share what [NEW PRODUCT NAME] does, who it\'s for, and how it can fit into your business.\n\nFor now, just mark **[LAUNCH DATE]** on your calendar — you won\'t want to miss it.\n\nTalk soon,\n**The [COMPANY NAME] Team**',
        cta_text: '👀 Learn More',
        cta_url: 'https://yourapp.com/launch-preview',
        send_delay_hours: 0,
        position_x: 100,
        position_y: 100,
      },
      {
        type: 'reminder',
        name: '48 Hour Warning',
        subject_line: '⏰ 48 hours until [NEW PRODUCT] launches',
        preview_text: 'Final reminder: Get ready for early access',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## Launch Is in 48 Hours 🚀\n\nA quick reminder: **[NEW PRODUCT NAME]** goes live in just **2 days**.\n\nIf you\'ve been waiting for a way to **[SOLVE MAIN PROBLEM]** more reliably, this is for you.\n\nAs part of our subscriber list, you\'ll receive:\n\n- **Early access** as soon as we open the doors\n- A **special launch discount** you won\'t see again for a while\n- A **bonus package** only available during launch\n\nWe\'ll send you the access link on **[LAUNCH DATE] at [LAUNCH TIME]**.\n\nIf you want a reminder closer to launch, add this event to your calendar.\n\nThanks for being with us,\n**The [COMPANY NAME] Team**',
        cta_text: '⏰ Set Reminder',
        cta_url: 'https://yourapp.com/set-reminder',
        send_delay_hours: 120,
        position_x: 450,
        position_y: 100,
      },
      {
        type: 'offer',
        name: 'Launch Day Special',
        subject_line: '🎉 IT\'S HERE! [NEW PRODUCT] is now live + 25% off',
        preview_text: 'Launch day special pricing - limited time only',
        body_copy: 'Hi **[FIRST NAME]**,\n\n# We\'re Live: [NEW PRODUCT NAME] Is Now Available 🎉\n\n[NEW PRODUCT NAME] is officially open, and you can get access starting today.\n\nIf you want to **[KEY BENEFIT]** without [FRUSTRATION / MANUAL WORK], this was built for you.\n\n## Launch-special pricing\n\nFor a limited time, you can get [NEW PRODUCT NAME] with **[X]% off** using the code **LAUNCH25** at checkout.\n\nInside, you\'ll get:\n\n- **[FEATURE 1]** – helps you with [BENEFIT]\n- **[FEATURE 2]** – saves time on [PROCESS]\n- **[FEATURE 3]** – gives clarity on [RESULT]\n- Plus launch-only bonuses: **[EXCLUSIVE BONUS]**\n\nLaunch pricing and bonuses are only available for a short window, so if this feels right for you, now is the time.\n\nAll the details are on the page here: [LINK]\n\nSee you inside,\n**The [COMPANY NAME] Team**',
        cta_text: '🔥 Get 25% Off Now',
        cta_url: 'https://yourapp.com/buy?code=LAUNCH25',
        send_delay_hours: 168,
        position_x: 800,
        position_y: 100,
      }
    ],
    connections: [
      { source_index: 0, target_index: 1, condition_type: 'default' },
      { source_index: 1, target_index: 2, condition_type: 'default' }
    ]
  },
  {
    id: 'flash-sale',
    name: 'Flash Sale Campaign',
    description: '3-email sequence for limited-time flash sales',
    category: 'marketing',
    icon: '⚡',
    color: 'text-indigo-700',
    bgColor: 'bg-indigo-50',
    borderColor: 'border-indigo-200',
    blocks: [
      {
        type: 'offer',
        name: 'Flash Sale Announcement',
        subject_line: '⚡ FLASH SALE: 50% off for 24 hours!',
        preview_text: 'Biggest discount of the year - today only',
        body_copy: 'Hi **[FIRST NAME]**,\n\n# Flash Sale: [OFFER] for 24 Hours ⚡\n\nFor the next **24 hours**, we\'re running a flash sale across **[STORE NAME]**.\n\nYou can get **[DISCOUNT]% off** selected products when you use the code below at checkout.\n\n**Your code:** FLASH50\n\nSome items you might want to check out:\n\n- **[PRODUCT 1]** – great for [BENEFIT]\n- **[PRODUCT 2]** – perfect if you need [BENEFIT]\n- **[PRODUCT 3]** – our customers\' go-to for [BENEFIT]\n\nThe sale ends tomorrow at **[TIME / TIMEZONE]**. Once it\'s over, prices go back to normal.\n\nShop the flash sale now: [LINK]\n\n**The [STORE NAME] Team**',
        cta_text: '🛍️ Shop Flash Sale',
        cta_url: 'https://yourstore.com/flash-sale?code=FLASH50',
        send_delay_hours: 0,
        position_x: 100,
        position_y: 100,
      },
      {
        type: 'reminder',
        name: '12 Hours Left',
        subject_line: '⏰ 12 hours left: 50% OFF everything',
        preview_text: 'Flash sale ending soon - don\'t miss out',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## 12 Hours Left in the Flash Sale ⏰\n\nA quick reminder that our **[DISCOUNT]% off** flash sale ends in about **12 hours**.\n\nHere\'s what shoppers are grabbing right now:\n\n- **[PRODUCT 1]** – close to selling out\n- **[PRODUCT 2]** – one of our top-rated items\n- **[PRODUCT 3]** – popular bundle for [USE CASE]\n\nUse your code **FLASH50** at checkout before the timer runs out.\n\nAfter that, everything returns to full price.\n\nBrowse the sale here: [LINK]\n\n**The [STORE NAME] Team**',
        cta_text: '🔥 Shop Before It Ends',
        cta_url: 'https://yourstore.com/flash-sale?code=FLASH50',
        send_delay_hours: 12,
        position_x: 450,
        position_y: 100,
      },
      {
        type: 'reminder',
        name: 'Final 2 Hours',
        subject_line: '🚨 FINAL 2 HOURS: Flash sale ending!',
        preview_text: 'Last chance for 50% off everything',
        body_copy: 'Hi **[FIRST NAME]**,\n\n# Last Call: 2 Hours Remaining 🕒\n\nThis is your final reminder — our flash sale ends in **2 hours**.\n\nIf there\'s anything you\'ve been eyeing, now\'s the best time to grab it at **[DISCOUNT]% off**.\n\nUse code **FLASH50** at checkout before **[END TIME]**.\n\nAfter that, the discount disappears and prices go back to normal.\n\nSee what\'s still available: [LINK]\n\n**The [STORE NAME] Team**',
        cta_text: '⚡ Shop Now',
        cta_url: 'https://yourstore.com/flash-sale?code=FLASH50',
        send_delay_hours: 22,
        position_x: 800,
        position_y: 100,
      }
    ],
    connections: [
      { source_index: 0, target_index: 1, condition_type: 'not_clicked' },
      { source_index: 1, target_index: 2, condition_type: 'not_clicked' }
    ]
  },
  {
    id: 'newsletter-digest',
    name: 'Weekly Newsletter Series',
    description: 'Consistent weekly content delivery for subscribers',
    category: 'marketing',
    icon: '📰',
    color: 'text-indigo-700',
    bgColor: 'bg-indigo-50',
    borderColor: 'border-indigo-200',
    blocks: [
      {
        type: 'follow-up',
        name: 'Weekly Digest',
        subject_line: '📰 This week\'s top stories and tips',
        preview_text: 'Your weekly roundup of insights and updates',
        body_copy: 'Hi **[FIRST NAME]**,\n\n# This Week in [INDUSTRY] 📰\n\nHere\'s a quick round-up of useful ideas, resources, and updates to help you with **[MAIN TOPIC / OUTCOME]**.\n\n## 🔥 Highlights\n\n**1. [HEADLINE 1]**\n[Short, clear summary of why this matters and what they\'ll learn.] [Read more →]\n\n**2. [HEADLINE 2]**\n[Short summary focused on a specific insight or tactic.] [Read more →]\n\n**3. [HEADLINE 3]**\n[Short summary with a clear "what\'s in it for me".] [Read more →]\n\n---\n\n## 💡 Tip of the Week\n\n[Share one simple, actionable tip your reader can implement today. Keep it practical and focused on a small win related to your topic.]\n\n---\n\n## 📊 Worth a Look\n\n- [Article 1] – [1-sentence reason it\'s useful]\n- [Article 2] – [1-sentence reason it\'s useful]\n- [Article 3] – [1-sentence reason it\'s useful]\n\nThanks for reading. Hit reply and tell us what you\'d like to see more of in future editions.\n\n**The [COMPANY NAME] Team**',
        cta_text: '📖 Read Full Newsletter',
        cta_url: 'https://yoursite.com/newsletter',
        send_delay_hours: 0,
        position_x: 100,
        position_y: 100,
      }
    ],
    connections: []
  },
  {
    id: 'cart-recovery',
    name: 'Cart Abandonment Recovery',
    description: 'Win back customers who left items in their cart',
    category: 'ecommerce',
    icon: '🛒',
    color: 'text-yellow-700',
    bgColor: 'bg-yellow-50',
    borderColor: 'border-yellow-200',
    blocks: [
      {
        type: 'abandon-cart',
        name: 'Cart Reminder',
        subject_line: '🛒 You left something in your cart...',
        preview_text: 'Complete your order and get free shipping',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## You Left Something Behind 🛒\n\nYou added these items to your cart on [STORE NAME]:\n\n[CART ITEMS]\n\nThey\'re still reserved for you for a little while longer.\n\nIf you\'d like to finish your order now, you can return to your cart with one click:\n\n[RETURN TO CART BUTTON / LINK]\n\nIf you have any questions about sizing, shipping, or anything else, just reply to this email and we\'ll help you out.\n\n**The [STORE NAME] Team**',
        cta_text: '✨ Complete My Order',
        cta_url: 'https://yourstore.com/checkout',
        send_delay_hours: 1,
        position_x: 100,
        position_y: 100,
      },
      {
        type: 'offer',
        name: 'Discount Incentive',
        subject_line: '🎁 Still thinking? Here\'s 10% off your cart',
        preview_text: 'Special discount just for you - limited time',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## A Little Nudge to Complete Your Order 💡\n\nWe noticed you still have items waiting in your cart:\n\n[CART ITEMS]\n\nIf you\'d like to complete your purchase, here\'s a **[X]% discount** to make the decision easier:\n\n**Code:** SAVE10\n\nUse it at checkout in the next **24 hours**.\n\nIf something stopped you from completing your order (shipping, payment, product questions), reply to this email and let us know — we\'d love to help.\n\n**The [STORE NAME] Team**',
        cta_text: '💸 Use 10% Discount',
        cta_url: 'https://yourstore.com/checkout?code=SAVE10',
        send_delay_hours: 25,
        position_x: 450,
        position_y: 100,
      },
      {
        type: 'reminder',
        name: 'Final Notice',
        subject_line: '⏰ Last chance: Your cart expires soon',
        preview_text: 'Your items will be released to other customers tomorrow',
        body_copy: 'Hi **[FIRST NAME]**,\n\n# Last Reminder About Your Cart ⏰\n\nThis is a quick note to let you know that your saved cart at [STORE NAME] will expire soon.\n\nYour items:\n\n[CART ITEMS]\n\nYour **[X]% discount (SAVE10)** is still active for a little longer, after which your cart may reset and prices may change.\n\nIf you still want them, you can complete your order here:\n\n[COMPLETE PURCHASE LINK]\n\nIf you don\'t need these right now, no worries — we just wanted to give you a final chance.\n\n**The [STORE NAME] Team**',
        cta_text: '🔥 Complete Order Now',
        cta_url: 'https://yourstore.com/checkout?code=SAVE10',
        send_delay_hours: 73,
        position_x: 800,
        position_y: 100,
      }
    ],
    connections: [
      { source_index: 0, target_index: 1, condition_type: 'not_clicked' },
      { source_index: 1, target_index: 2, condition_type: 'not_clicked' }
    ]
  },
  {
    id: 'post-purchase-upsell',
    name: 'Post-Purchase Upsell',
    description: '3-email sequence to upsell complementary products',
    category: 'ecommerce',
    icon: '💎',
    color: 'text-yellow-700',
    bgColor: 'bg-yellow-50',
    borderColor: 'border-yellow-200',
    blocks: [
      {
        type: 'welcome',
        name: 'Order Confirmation',
        subject_line: '🎉 Thank you for your order!',
        preview_text: 'Your order is confirmed and on its way',
        body_copy: 'Hi **[FIRST NAME]**,\n\n# Thanks for Your Order 🙌\n\nYour order **#[ORDER_NUMBER]** has been received.\n\n**Items:**\n\n[ORDER ITEMS]\n\nWe\'ll email you tracking details as soon as your package ships.\n\nIn the meantime, many customers who buy [MAIN PRODUCT] also find these helpful:\n\n- **[COMPLEMENTARY_1]** – great for [BENEFIT]\n- **[COMPLEMENTARY_2]** – helps with [BENEFIT]\n- **[COMPLEMENTARY_3]** – perfect if you need [BENEFIT]\n\nYou can take **[X]% off** these related items with code **THANKYOU15** for a limited time.\n\nWe appreciate your trust,\n**The [STORE NAME] Team**',
        cta_text: '🛍️ Shop Recommendations',
        cta_url: 'https://yourstore.com/recommendations',
        send_delay_hours: 0,
        position_x: 100,
        position_y: 100,
      },
      {
        type: 'upsell',
        name: 'Complete Your Set',
        subject_line: '💎 Complete your [PRODUCT] collection',
        preview_text: 'These items pair perfectly with your recent purchase',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## Make the Most of Your [PRODUCT] ✨\n\nYour **[PRODUCT]** will be arriving soon.\n\nTo help you get even more out of it, here are a few items that work especially well with your purchase:\n\n**[PRODUCT 1]**\nHow it helps: [Short benefit explanation]\n~~$[PRICE]~~ → **$[DISCOUNTED_PRICE]**\n\n**[PRODUCT 2]**\nHow it helps: [Short benefit explanation]\n~~$[PRICE]~~ → **$[DISCOUNTED_PRICE]**\n\n**[PRODUCT 3]**\nHow it helps: [Short benefit explanation]\n~~$[PRICE]~~ → **$[DISCOUNTED_PRICE]**\n\nYou can also bundle all three for **$[BUNDLE_PRICE]**.\n\nUse code **COMPLETE20** at checkout. The offer is available for **48 hours**.\n\n**The [STORE NAME] Team**',
        cta_text: '🔥 Add to Order',
        cta_url: 'https://yourstore.com/add-to-order',
        send_delay_hours: 24,
        position_x: 450,
        position_y: 100,
      },
      {
        type: 'follow-up',
        name: 'Review Request',
        subject_line: '⭐ How\'s your [PRODUCT]?',
        preview_text: 'Share your experience and get 10% off',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## How\'s Your New [PRODUCT] Working Out? ⭐\n\nYour **[PRODUCT]** should have arrived by now, and we\'d love to know what you think.\n\nYour feedback helps other customers make better decisions and helps us improve what we offer.\n\nIf you have a minute, please leave a quick review. As a thank-you, we\'ll give you **[X]% off** your next order with code **REVIEW10**.\n\nThanks again for choosing [STORE NAME],\n**The [STORE NAME] Team**',
        cta_text: '✍️ Write Review',
        cta_url: 'https://yourstore.com/review',
        send_delay_hours: 168,
        position_x: 800,
        position_y: 100,
      }
    ],
    connections: [
      { source_index: 0, target_index: 1, condition_type: 'default' },
      { source_index: 1, target_index: 2, condition_type: 'default' }
    ]
  },
  {
    id: 'browse-abandonment',
    name: 'Browse Abandonment Recovery',
    description: 'Re-engage users who viewed but didn\'t purchase',
    category: 'ecommerce',
    icon: '👀',
    color: 'text-yellow-700',
    bgColor: 'bg-yellow-50',
    borderColor: 'border-yellow-200',
    blocks: [
      {
        type: 'follow-up',
        name: 'Product Reminder',
        subject_line: '👀 Still interested in [PRODUCT]?',
        preview_text: 'We saved it for you + exclusive discount',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## Still Thinking About This? 👀\n\nWe noticed you were looking at **[PRODUCT NAME]** on [STORE NAME].\n\nHere\'s a quick reminder of why customers like it:\n\n- Rated **[RATING]** stars by [X] reviewers\n- Popular among people who need [USE CASE]\n- Often paired with [RELATED PRODUCT]\n\nIf you\'d like to give it a try, you can use code **BROWSE15** for **[X]% off** your order for the next **48 hours**.\n\nTake another look: [PRODUCT LINK]\n\n**The [STORE NAME] Team**',
        cta_text: '🛒 Add to Cart',
        cta_url: 'https://yourstore.com/product',
        send_delay_hours: 24,
        position_x: 100,
        position_y: 100,
      },
      {
        type: 'offer',
        name: 'Limited Stock Alert',
        subject_line: '⚠️ Low stock alert: [PRODUCT]',
        preview_text: 'Only a few left - your discount still active',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## Quick Stock Update ⚠️\n\n**[PRODUCT NAME]** is selling fast and there are only **[X] units** left in stock.\n\nYour **[X]% discount (code BROWSE15)** is still active for a little longer.\n\nIf you don\'t want to miss out, now\'s the best time to decide.\n\nSee details here: [PRODUCT LINK]\n\n**The [STORE NAME] Team**',
        cta_text: '🔥 Claim Discount',
        cta_url: 'https://yourstore.com/product?code=BROWSE15',
        send_delay_hours: 72,
        position_x: 450,
        position_y: 100,
      }
    ],
    connections: [
      { source_index: 0, target_index: 1, condition_type: 'not_clicked' }
    ]
  },
  {
    id: 'customer-reactivation',
    name: 'Customer Reactivation',
    description: 'Re-engage inactive customers and win them back',
    category: 'retention',
    icon: '🔄',
    color: 'text-pink-700',
    bgColor: 'bg-pink-50',
    borderColor: 'border-pink-200',
    blocks: [
      {
        type: 'reactivation',
        name: 'We Miss You',
        subject_line: '💙 We miss you! Here\'s what you\'ve been missing',
        preview_text: 'Come back and see all the exciting updates',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## It\'s Been a While 👋\n\nWe noticed you haven\'t used [PRODUCT NAME] recently, and we genuinely miss having you around.\n\nWhile you\'ve been away, we\'ve:\n\n- Added **[NEW FEATURE 1]** to help with [BENEFIT]\n- Improved performance so things run faster and smoother\n- Launched new integrations with **[POPULAR TOOLS]**\n- Refreshed the interface to make it easier to use\n\nYour account and data are still there, ready for you to pick up where you left off.\n\nIf you\'d like to see what\'s new, log in here: [LOGIN LINK]\n\n**The [PRODUCT NAME] Team**',
        cta_text: '✨ See What\'s New',
        cta_url: 'https://yourapp.com/whats-new',
        send_delay_hours: 0,
        position_x: 100,
        position_y: 100,
      },
      {
        type: 'offer',
        name: 'Welcome Back Discount',
        subject_line: '🎁 Welcome back! Here\'s 30% off your next purchase',
        preview_text: 'Special welcome back offer just for you',
        body_copy: 'Hi **[FIRST NAME]**,\n\n# A Special Offer to Welcome You Back 🎁\n\nWe\'d love to support you again inside [PRODUCT NAME].\n\nTo make it easier to return, here\'s a **[X]% discount** on your next purchase or subscription:\n\n**Code:** WELCOME30\n\nYou can apply this to:\n\n- Upgrading your plan\n- Renewing your subscription\n- Adding extra features or seats\n\nThe code is valid for **7 days**.\n\nIf you\'re unsure what plan fits your current needs, reply to this email and we\'ll help you choose.\n\n**The [PRODUCT NAME] Team**',
        cta_text: '🎉 Claim 30% Off',
        cta_url: 'https://yourapp.com/pricing?code=WELCOME30',
        send_delay_hours: 72,
        position_x: 450,
        position_y: 100,
      },
      {
        type: 'follow-up',
        name: 'How Can We Improve?',
        subject_line: '💭 Quick question: What made you leave?',
        preview_text: 'Help us improve with your feedback',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## We\'d Love Your Feedback 💬\n\nWe\'re always trying to make [PRODUCT NAME] better, and your perspective would really help.\n\nIf you have a few minutes, we\'d appreciate your honest thoughts:\n\n- What made you stop using [PRODUCT NAME]?\n- What would you like us to improve?\n- What would make you excited to come back?\n\nYou can reply directly to this email with your feedback.\n\nAs a thank-you, we\'ll extend your **WELCOME30** discount for another week once we hear from you.\n\nThanks for helping us improve,\n**The [PRODUCT NAME] Team**',
        cta_text: '💬 Share Feedback',
        cta_url: 'https://yourapp.com/feedback-survey',
        send_delay_hours: 168,
        position_x: 800,
        position_y: 100,
      }
    ],
    connections: [
      { source_index: 0, target_index: 1, condition_type: 'clicked' },
      { source_index: 1, target_index: 2, condition_type: 'not_clicked' }
    ]
  },
  {
    id: 'vip-loyalty-program',
    name: 'VIP Loyalty Program',
    description: 'Reward and retain your best customers',
    category: 'retention',
    icon: '👑',
    color: 'text-pink-700',
    bgColor: 'bg-pink-50',
    borderColor: 'border-pink-200',
    blocks: [
      {
        type: 'welcome',
        name: 'VIP Invitation',
        subject_line: '👑 You\'re invited to our VIP program!',
        preview_text: 'Exclusive perks for our best customers',
        body_copy: 'Hi **[FIRST NAME]**,\n\n# You\'re Invited to Our VIP Program 👑\n\nYou\'re one of our most loyal customers, and we\'d like to say thank you.\n\nWe\'ve created a **VIP program** with extra perks just for people like you.\n\nAs a VIP, you\'ll enjoy:\n\n- Early access to new collections\n- Exclusive discounts and special offers\n- Free or discounted shipping on selected orders\n- Occasional surprise gifts and bonuses\n\nThere\'s nothing you need to do — your VIP status is already active on your account.\n\nThank you for being such an important part of [STORE NAME],\n**The [STORE NAME] Team**',
        cta_text: '👑 Activate VIP Status',
        cta_url: 'https://yourstore.com/vip-activate',
        send_delay_hours: 0,
        position_x: 100,
        position_y: 100,
      },
      {
        type: 'offer',
        name: 'VIP Early Access',
        subject_line: '🎯 VIP Early Access: New collection launches',
        preview_text: '24 hours before everyone else',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## VIP Early Access Starts Now ✨\n\nAs a VIP member, you get **24-hour early access** to our new [COLLECTION / LAUNCH].\n\nHere are a few pieces we think you\'ll like:\n\n- **[PRODUCT 1]** – limited run\n- **[PRODUCT 2]** – new in [CATEGORY]\n- **[PRODUCT 3]** – updated version of a customer favorite\n\nFor this early access window, you can use code **VIP15** for an additional **[X]% off**.\n\nBrowse the collection here before it opens to the public: [LINK]\n\n**The [STORE NAME] Team**',
        cta_text: '🛍️ Shop VIP Collection',
        cta_url: 'https://yourstore.com/vip-collection',
        send_delay_hours: 168,
        position_x: 450,
        position_y: 100,
      },
      {
        type: 'follow-up',
        name: 'Points Balance Update',
        subject_line: '💰 Your VIP points: [X] points available',
        preview_text: 'See what you can redeem today',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## Your Current VIP Points Balance 💰\n\nYou currently have **[X] points** in your [STORE NAME] account.\n\nHere\'s what you can redeem them for:\n\n- [X] points → $10 off\n- [X] points → $25 off\n- [X] points → $50 off\n\nYou can earn more points when you:\n\n- Make purchases\n- Leave product reviews\n- Refer friends to [STORE NAME]\n\nLog in to your account to see your point options and apply them at checkout.\n\n**The [STORE NAME] Team**',
        cta_text: '💎 Redeem Points',
        cta_url: 'https://yourstore.com/vip-rewards',
        send_delay_hours: 720,
        position_x: 800,
        position_y: 100,
      }
    ],
    connections: [
      { source_index: 0, target_index: 1, condition_type: 'default' },
      { source_index: 1, target_index: 2, condition_type: 'default' }
    ]
  },
  {
    id: 'referral-program',
    name: 'Referral Program Campaign',
    description: 'Encourage customers to refer friends',
    category: 'retention',
    icon: '🤝',
    color: 'text-pink-700',
    bgColor: 'bg-pink-50',
    borderColor: 'border-pink-200',
    blocks: [
      {
        type: 'offer',
        name: 'Referral Introduction',
        subject_line: '🤝 Give $20, Get $20',
        preview_text: 'Share the love and earn rewards',
        body_copy: 'Hi **[FIRST NAME]**,\n\n# Share [PRODUCT NAME] and Get Rewarded 🤝\n\nIf [PRODUCT NAME] has helped you, we\'d love for you to share it with friends who might benefit too.\n\nHere\'s how our referral program works:\n\n1. Share your unique referral link.\n2. Your friend gets **[FRIEND INCENTIVE]** on their first purchase.\n3. You earn **[REFERRER REWARD]** for every friend who becomes a customer.\n\nYour referral link:\n\n**[UNIQUE_REFERRAL_LINK]**\n\nThere\'s no limit to how many people you can refer.\n\nThanks for spreading the word,\n**The [STORE NAME] / [PRODUCT NAME] Team**',
        cta_text: '🤝 Share & Earn',
        cta_url: 'https://yourstore.com/referrals',
        send_delay_hours: 0,
        position_x: 100,
        position_y: 100,
      },
      {
        type: 'follow-up',
        name: 'Referral Reminder',
        subject_line: '💰 You have [X] pending referral credits',
        preview_text: 'Your friends are waiting to join',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## Your Referral Rewards So Far 📊\n\nHere\'s a quick look at your current referral stats:\n\n- Successful referrals: **[X]**\n- Credit earned: **$[AMOUNT]**\n- Pending sign-ups: **[X]**\n\nYou\'re doing great — and you\'re close to your next reward tier.\n\nRemember, you can share your link via email, social media, or direct message:\n\n**Your link:** [UNIQUE_REFERRAL_LINK]\n\nThanks again for recommending us,\n**The [STORE NAME] / [PRODUCT NAME] Team**',
        cta_text: '🔗 Get Referral Link',
        cta_url: 'https://yourstore.com/referrals',
        send_delay_hours: 168,
        position_x: 450,
        position_y: 100,
      }
    ],
    connections: [
      { source_index: 0, target_index: 1, condition_type: 'default' }
    ]
  },
  {
    id: 'lead-nurturing',
    name: 'Lead Nurturing Sequence',
    description: 'Convert leads into customers with educational content',
    category: 'lead-generation',
    icon: '🌱',
    color: 'text-green-700',
    bgColor: 'bg-green-50',
    borderColor: 'border-green-200',
    blocks: [
      {
        type: 'welcome',
        name: 'Lead Magnet Delivery',
        subject_line: '📥 Your free guide is here + what\'s next',
        preview_text: 'Download your guide and discover next steps',
        body_copy: 'Hi **[FIRST NAME]**,\n\n# Here\'s Your Copy of "[LEAD MAGNET TITLE]" 📥\n\nThanks for requesting this — you\'ll find the download here:\n\n[DOWNLOAD LINK]\n\nInside, you\'ll learn **[KEY OUTCOME OR BENEFIT]** so you can start improving [AREA] right away.\n\nOver the next few days, I\'ll send you a few short emails with extra tips, examples, and real-world strategies to help you implement what\'s in the guide.\n\nTalk soon,\n**[YOUR NAME]**',
        cta_text: '📥 Download Guide',
        cta_url: 'https://yoursite.com/download-guide',
        send_delay_hours: 0,
        position_x: 100,
        position_y: 100,
      },
      {
        type: 'follow-up',
        name: 'Educational Content',
        subject_line: '⚠️ The #1 mistake most [TARGET AUDIENCE] make',
        preview_text: 'Avoid this common pitfall that costs thousands',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## A Common Mistake to Avoid 🚫\n\nNow that you\'ve seen "[LEAD MAGNET TITLE]," I want to highlight one big mistake many [TARGET AUDIENCE] make:\n\n> **[COMMON MISTAKE]**\n\nThis mistake often leads to **[NEGATIVE CONSEQUENCE]**, even if you\'re doing everything else right.\n\nHere\'s a simple way to avoid it:\n\n1. **[SOLUTION STEP 1]** – what to do first\n2. **[SOLUTION STEP 2]** – how to adjust your approach\n3. **[SOLUTION STEP 3]** – how to make it part of your routine\n\nIf you fix just this one thing, you\'ll already be ahead of most people in your space.\n\nI\'ll send you another email soon with a practical example so you can see this in action.\n\n**[YOUR NAME]**',
        cta_text: '🎥 Watch Free Training',
        cta_url: 'https://yoursite.com/free-training',
        send_delay_hours: 48,
        position_x: 450,
        position_y: 100,
      },
      {
        type: 'offer',
        name: 'Soft Pitch',
        subject_line: '📊 How [CLIENT NAME] achieved [RESULT] in [TIMEFRAME]',
        preview_text: 'Real case study + how you can get similar results',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## What This Looks Like in Real Life 🌟\n\nI want to share a quick story about a client, **[CLIENT NAME]**, who was struggling with **[PROBLEM]**.\n\nAfter we implemented the approach I\'ve been talking about — step by step — here\'s what changed:\n\n- **[RESULT 1]**\n- **[RESULT 2]**\n- **[RESULT 3]**\n\nWe didn\'t do anything fancy, just followed a clear, repeatable system:\n\n1. [STEP 1]\n2. [STEP 2]\n3. [STEP 3]\n\nIf you\'d like help applying this to your situation, I offer **[TYPE OF OFFER: strategy call / workshop / program]** where we map out a plan for your business.\n\nIf that sounds useful, reply to this email with "[KEYWORD]" and I\'ll send you the details.\n\n**[YOUR NAME]**',
        cta_text: '📞 Book Free Call',
        cta_url: 'https://yoursite.com/book-call',
        send_delay_hours: 120,
        position_x: 800,
        position_y: 100,
      }
    ],
    connections: [
      { source_index: 0, target_index: 1, condition_type: 'opened' },
      { source_index: 1, target_index: 2, condition_type: 'opened' }
    ]
  },
  {
    id: 'consultation-booking',
    name: 'Free Consultation Booking',
    description: 'Drive leads to book discovery calls',
    category: 'lead-generation',
    icon: '📞',
    color: 'text-green-700',
    bgColor: 'bg-green-50',
    borderColor: 'border-green-200',
    blocks: [
      {
        type: 'welcome',
        name: 'Consultation Offer',
        subject_line: '📞 Free 30-minute strategy session available',
        preview_text: 'Let\'s discuss your goals and challenges',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## Want Help Planning Your Next Steps? 📞\n\nI\'m opening a few spots for a **free [LENGTH] minute strategy call** where we\'ll look at your situation and outline a simple plan to reach **[DESIRED OUTCOME]**.\n\nOn the call, we can:\n\n- Review where you are right now\n- Identify the main bottlenecks holding you back\n- Outline a few clear actions you can take in the next 30 days\n\nThere\'s no obligation — the call is focused on giving you clarity and direction.\n\nIf you\'d like one of the open spots, choose a time here: [BOOKING LINK]\n\n**[YOUR NAME]**',
        cta_text: '📅 Book Your Session',
        cta_url: 'https://yoursite.com/book-consultation',
        send_delay_hours: 0,
        position_x: 100,
        position_y: 100,
      },
      {
        type: 'reminder',
        name: 'Booking Reminder',
        subject_line: '⏰ Limited slots left for free consultation',
        preview_text: 'Only 3 spots available this week',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## Quick Reminder About Your Free Strategy Call ⏰\n\nA few of the free consultation slots are still available this week.\n\nIf you\'ve been meaning to get an outside perspective on **[TOPIC / PROBLEM]**, this is a simple way to do it.\n\nYou can pick a time that suits you here: [BOOKING LINK]\n\nIf you\'re unsure whether it\'s a good fit, reply to this email with a sentence or two about your situation and I\'ll let you know honestly.\n\n**[YOUR NAME]**',
        cta_text: '🔒 Secure My Spot',
        cta_url: 'https://yoursite.com/book-consultation',
        send_delay_hours: 72,
        position_x: 450,
        position_y: 100,
      },
      {
        type: 'follow-up',
        name: 'Alternative Resource',
        subject_line: '💡 Can\'t make a call? Here\'s an alternative',
        preview_text: 'Free video training on [TOPIC]',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## No Time for a Call? Here\'s Another Option 🎥\n\nI know not everyone has space in their calendar for a live call.\n\nIf that\'s you, I\'ve put together a **free training** that covers the core framework I walk through on strategy calls:\n\n- [KEY TOPIC 1]\n- [KEY TOPIC 2]\n- [KEY TOPIC 3]\n\nYou can watch it here whenever it suits you: [VIDEO_LINK]\n\nIf you have questions after watching, just reply to this email and I\'ll personally answer.\n\n**[YOUR NAME]**',
        cta_text: '🎥 Watch Training',
        cta_url: 'https://yoursite.com/free-training',
        send_delay_hours: 168,
        position_x: 800,
        position_y: 100,
      }
    ],
    connections: [
      { source_index: 0, target_index: 1, condition_type: 'not_clicked' },
      { source_index: 1, target_index: 2, condition_type: 'not_clicked' }
    ]
  },
  {
    id: 'demo-request-followup',
    name: 'Demo Request Follow-up',
    description: 'Nurture leads who requested a product demo',
    category: 'sales',
    icon: '🎬',
    color: 'text-purple-700',
    bgColor: 'bg-purple-50',
    borderColor: 'border-purple-200',
    blocks: [
      {
        type: 'welcome',
        name: 'Demo Confirmation',
        subject_line: '✅ Your demo is confirmed!',
        preview_text: 'See you on [DATE] at [TIME]',
        body_copy: 'Hi **[FIRST NAME]**,\n\n# Your [PRODUCT NAME] Demo Is Confirmed ✅\n\nThanks for scheduling a demo with us.\n\nHere are your details:\n\n📅 **Date:** [DATE]\n🕒 **Time:** [TIME]\n🔗 **Join link:** [DEMO_LINK]\n\nDuring the call, we\'ll focus on:\n\n- Your current process and goals\n- The parts of [PRODUCT NAME] that are most relevant to you\n- Questions from you and your team\n\nIf there\'s anything specific you want to make sure we cover, reply to this email and let me know.\n\nLooking forward to speaking,\n**[YOUR NAME]**\n[COMPANY NAME]',
        cta_text: '📅 Add to Calendar',
        cta_url: 'https://yoursite.com/add-demo-calendar',
        send_delay_hours: 0,
        position_x: 100,
        position_y: 100,
      },
      {
        type: 'reminder',
        name: '24h Demo Reminder',
        subject_line: '⏰ Demo tomorrow at [TIME]',
        preview_text: 'Quick reminder about your product demo',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## Reminder: Your Demo Is Tomorrow ⏰\n\nJust a quick reminder about your **[PRODUCT NAME] demo** tomorrow.\n\n📅 **Date:** [DATE]\n🕒 **Time:** [TIME]\n🔗 **Join link:** [DEMO_LINK]\n\nTo get the most from the call, you might:\n\n- List your main questions\n- Think about what a "win" from this tool would look like\n- Share the link with any teammates who should attend\n\nSee you on the call,\n**[YOUR NAME]**',
        cta_text: '🔗 Join Demo',
        cta_url: 'https://yoursite.com/demo-link',
        send_delay_hours: 24,
        position_x: 450,
        position_y: 100,
      },
      {
        type: 'follow-up',
        name: 'Post-Demo Follow-up',
        subject_line: '🙏 Thanks for the demo + next steps',
        preview_text: 'Your custom proposal is ready',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## Thanks for Taking the Time Today 🙏\n\nIt was great speaking with you about how [PRODUCT NAME] could help with **[GOALS_SUMMARY]**.\n\nAs a recap, we looked at:\n\n- The main challenges you\'re facing: [KEY POINTS]\n- The features most relevant to your use case: [FEATURES_LIST]\n- Possible implementation timeline: [IMPLEMENTATION_TIMELINE]\n\nI\'ve attached / included a summary or proposal here: [LINK / ATTACHMENT INFO].\n\nTake a look when you have a moment, and if you\'d like to adjust anything or have follow-up questions, just reply to this email.\n\nThanks again,\n**[YOUR NAME]**',
        cta_text: '📄 View Proposal',
        cta_url: 'https://yoursite.com/proposal',
        send_delay_hours: 48,
        position_x: 800,
        position_y: 100,
      }
    ],
    connections: [
      { source_index: 0, target_index: 1, condition_type: 'default' },
      { source_index: 1, target_index: 2, condition_type: 'default' }
    ]
  },
  {
    id: 'quote-followup',
    name: 'Quote Follow-up Sequence',
    description: 'Convert quotes into closed deals',
    category: 'sales',
    icon: '📋',
    color: 'text-purple-700',
    bgColor: 'bg-purple-50',
    borderColor: 'border-purple-200',
    blocks: [
      {
        type: 'follow-up',
        name: 'Quote Delivery',
        subject_line: '📋 Your custom quote is ready',
        preview_text: 'Tailored pricing for your needs',
        body_copy: 'Hi **[FIRST NAME]**,\n\n# Your Quote for [PRODUCT / SERVICE NAME] 📋\n\nThanks again for your interest in working with us.\n\nBased on what you shared, we\'ve prepared a quote that includes:\n\n- [FEATURE 1 / COMPONENT]\n- [FEATURE 2 / COMPONENT]\n- [FEATURE 3 / COMPONENT]\n\n**Total investment:** $[AMOUNT]\n**Valid until:** [DATE]\n\nI\'ve attached the full details / added a link here: [QUOTE LINK].\n\nIf anything isn\'t clear or you\'d like to adjust the scope, reply to this email and we can fine-tune it together.\n\nBest,\n**[YOUR NAME]**',
        cta_text: '📄 View Quote',
        cta_url: 'https://yoursite.com/view-quote',
        send_delay_hours: 0,
        position_x: 100,
        position_y: 100,
      },
      {
        type: 'follow-up',
        name: 'Check-in',
        subject_line: '💭 Questions about your quote?',
        preview_text: 'I\'m here to help with any questions',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## Any Questions About Your Quote? 💬\n\nI wanted to follow up and see if you had any questions about the quote I sent for **[PRODUCT / SERVICE NAME]**.\n\nIf you\'re still reviewing options, I\'m happy to help with:\n\n- Clarifying what\'s included\n- Adjusting the scope to fit your budget or priorities\n- Sharing examples or case studies from similar clients\n\nJust hit reply and let me know where you are in your decision process.\n\n**[YOUR NAME]**',
        cta_text: '📞 Schedule Call',
        cta_url: 'https://yoursite.com/book-call',
        send_delay_hours: 72,
        position_x: 450,
        position_y: 100,
      },
      {
        type: 'reminder',
        name: 'Quote Expiration',
        subject_line: '⚠️ Your quote expires in 3 days',
        preview_text: 'Lock in your pricing before it\'s gone',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## Quick Note About Your Quote ⏰\n\nJust a reminder that your quote for **[PRODUCT / SERVICE NAME]** is set to expire on **[DATE]**.\n\nAfter that, pricing or availability may change.\n\nIf you\'d like to move forward at the current terms, reply to this email or schedule a quick call and we\'ll get everything set up.\n\nIf now isn\'t the right time, no problem — just let me know and we can revisit it later.\n\nBest,\n**[YOUR NAME]**',
        cta_text: '✅ Accept Quote',
        cta_url: 'https://yoursite.com/accept-quote',
        send_delay_hours: 168,
        position_x: 800,
        position_y: 100,
      }
    ],
    connections: [
      { source_index: 0, target_index: 1, condition_type: 'not_clicked' },
      { source_index: 1, target_index: 2, condition_type: 'not_clicked' }
    ]
  },
  {
    id: 'webinar-promotion-series',
    name: 'Webinar Promotion Series',
    description: '5-email sequence to promote and follow up on webinars',
    category: 'events',
    icon: '🎥',
    color: 'text-blue-700',
    bgColor: 'bg-blue-50',
    borderColor: 'border-blue-200',
    blocks: [
      {
        type: 'welcome',
        name: 'Webinar Announcement',
        subject_line: '🔴 LIVE: Join the exclusive webinar on [DATE]',
        preview_text: 'Learn the secrets to [TOPIC] in this free masterclass',
        body_copy: 'Hi **[FIRST NAME]**,\n\n# You\'re Invited: "[WEBINAR TITLE]" 🎓\n\nI\'m hosting a **free live webinar** on **[DATE] at [TIME]** and I\'d love for you to join.\n\nWe\'ll be covering:\n\n- [KEY LEARNING 1]\n- [KEY LEARNING 2]\n- [KEY LEARNING 3]\n\nIf you want to [DESIRED OUTCOME] without [PAIN], this session will be especially useful.\n\nSave your seat here: [REGISTRATION LINK]\n\n**[YOUR NAME]**',
        cta_text: '🎟️ Reserve My Free Seat',
        cta_url: 'https://webinar.com/register',
        send_delay_hours: 0,
        position_x: 100,
        position_y: 100,
      },
      {
        type: 'reminder',
        name: '48 Hour Reminder',
        subject_line: '⏰ 48 hours left: Webinar on [TOPIC]',
        preview_text: 'Don\'t miss your chance to join this exclusive training',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## 48 Hours Until the Webinar ⏰\n\nA quick reminder that **"[WEBINAR TITLE]"** is happening in two days.\n\n📅 **Date:** [DATE]\n🕒 **Time:** [TIME]\n\nIf you haven\'t registered yet, there\'s still time: [REGISTRATION LINK]\n\nIf you\'re already registered, add it to your calendar so you don\'t miss it.\n\nSee you there,\n**[YOUR NAME]**',
        cta_text: '✨ Secure My Spot',
        cta_url: 'https://webinar.com/register',
        send_delay_hours: 120,
        position_x: 450,
        position_y: 100,
      },
      {
        type: 'reminder',
        name: 'Final Reminder',
        subject_line: '🚨 STARTING SOON: [WEBINAR TITLE] in 2 hours',
        preview_text: 'Last chance to join - going live at [TIME]',
        body_copy: 'Hi **[FIRST NAME]**,\n\n# We Start Soon: "[WEBINAR TITLE]" 🎥\n\nJust a reminder that the webinar starts in about **[X HOURS]**.\n\n🕒 **Time:** [TIME]\n🔗 **Join link:** [WEBINAR_LINK]\n\nBring your questions — we\'ll leave some time at the end for Q&A.\n\nSee you live,\n**[YOUR NAME]**',
        cta_text: '🎥 Join Webinar Now',
        cta_url: 'https://webinar.com/join',
        send_delay_hours: 166,
        position_x: 800,
        position_y: 100,
      },
      {
        type: 'follow-up',
        name: 'Thank You & Replay',
        subject_line: '🙏 Thank you for attending + Exclusive bonus inside',
        preview_text: 'Your recording and special bonus are ready',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## Thanks for Joining the Webinar 🙏\n\nThank you for attending **"[WEBINAR TITLE]"**.\n\nHere are the resources I mentioned:\n\n- Replay: [REPLAY LINK]\n- Slides: [SLIDES LINK]\n- Extra resource: [BONUS LINK]\n\nI encourage you to pick one idea from the session and put it into action this week.\n\nIf you have any follow-up questions, just reply to this email.\n\n**[YOUR NAME]**',
        cta_text: '📦 Access Resources',
        cta_url: 'https://webinar.com/resources',
        send_delay_hours: 170,
        position_x: 1150,
        position_y: 100,
      },
      {
        type: 'offer',
        name: 'Special Offer',
        subject_line: '🎯 Ready to go deeper? Special offer for webinar attendees',
        preview_text: 'Exclusive 50% discount for the next 48 hours',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## A Next Step If You Want More Help 🎁\n\nIf the webinar resonated with you and you\'d like help implementing what we covered, I\'ve put together a special offer for attendees.\n\nFor the next **[X] hours**, you can get **[PRODUCT / COURSE NAME]** at **[DISCOUNT]% off**.\n\nInside, you\'ll get:\n\n- [BENEFIT 1]\n- [BENEFIT 2]\n- [BENEFIT 3]\n\nAll the details are here: [OFFER LINK]\n\nIf you have questions about whether it\'s a good fit, reply and tell me what you\'re working on — I\'ll give you an honest answer.\n\n**[YOUR NAME]**',
        cta_text: '🔥 Get 50% Off',
        cta_url: 'https://checkout.com/special-offer',
        send_delay_hours: 194,
        position_x: 1500,
        position_y: 100,
      }
    ],
    connections: [
      { source_index: 0, target_index: 1, condition_type: 'default' },
      { source_index: 1, target_index: 2, condition_type: 'default' },
      { source_index: 2, target_index: 3, condition_type: 'clicked' },
      { source_index: 3, target_index: 4, condition_type: 'opened' }
    ]
  },
  {
    id: 'workshop-series',
    name: 'Workshop Series Promotion',
    description: 'Promote multi-session workshop or training series',
    category: 'events',
    icon: '🎨',
    color: 'text-cyan-700',
    bgColor: 'bg-cyan-50',
    borderColor: 'border-cyan-200',
    blocks: [
      {
        type: 'welcome',
        name: 'Workshop Announcement',
        subject_line: '🎨 Join our 4-week [TOPIC] workshop',
        preview_text: 'Transform your skills with hands-on training',
        body_copy: 'Hi **[FIRST NAME]**,\n\n# New [TOPIC] Workshop Series 🎓\n\nI\'m running a **[X]-week live workshop** on **[TOPIC]**, designed to help you go from [STARTING POINT] to [DESIRED OUTCOME].\n\nEach week we\'ll focus on a specific area:\n\n- Week 1: [TOPIC 1]\n- Week 2: [TOPIC 2]\n- Week 3: [TOPIC 3]\n- Week 4: [TOPIC 4]\n\nYou\'ll get:\n\n- Live sessions with Q&A\n- Practical exercises\n- Recordings you can rewatch\n- Resources and templates to support implementation\n\nIf you\'d like to join, all the details and early-bird pricing are here: [LINK]\n\n**[YOUR NAME]**',
        cta_text: '🎨 Enroll Now',
        cta_url: 'https://yoursite.com/workshop',
        send_delay_hours: 0,
        position_x: 100,
        position_y: 100,
      },
      {
        type: 'reminder',
        name: 'Early Bird Ending',
        subject_line: '⏰ 48 hours: Early bird pricing ends',
        preview_text: 'Last chance to save on workshop enrollment',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## Early-Bird Pricing Ends Soon ⏰\n\nA quick reminder that early-bird pricing for the **[TOPIC] workshop** ends in **[X] days**.\n\nIf you\'ve been thinking about joining, this is the best price you\'ll see.\n\nDetails and enrollment: [LINK]\n\n**[YOUR NAME]**',
        cta_text: '💎 Save My Spot',
        cta_url: 'https://yoursite.com/workshop',
        send_delay_hours: 120,
        position_x: 450,
        position_y: 100,
      },
      {
        type: 'follow-up',
        name: 'Week 1 Starts',
        subject_line: '🎉 Workshop starts tomorrow!',
        preview_text: 'Get ready for an amazing learning experience',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## We Start Tomorrow 🎉\n\nExcited to have you in the **[TOPIC] Workshop**!\n\n### Tomorrow\'s schedule:\n\n📅 **Date:** [DATE]\n🕒 **Time:** [TIME]\n🔗 **Join link:** [WORKSHOP_LINK]\n\n### What to prepare:\n\n✅ Review the **welcome packet**\n✅ Set up your **workspace**\n✅ Bring **questions** for Q&A\n\n### Week 1 Preview:\n\n🎯 [TOPIC 1]\n✨ [KEY LEARNING POINT]\n💡 [PRACTICAL EXERCISE]\n\n---\n\nSee you tomorrow! 👋\n\n**[YOUR NAME]**',
        cta_text: '🔗 Access Workshop',
        cta_url: 'https://yoursite.com/workshop-portal',
        send_delay_hours: 168,
        position_x: 800,
        position_y: 100,
      }
    ],
    connections: [
      { source_index: 0, target_index: 1, condition_type: 'not_clicked' },
      { source_index: 1, target_index: 2, condition_type: 'clicked' }
    ]
  },
  {
    id: 'course-launch-campaign',
    name: 'Online Course Launch Campaign',
    description: '6-email pre-launch and sales sequence for online courses',
    category: 'education',
    icon: '🎓',
    color: 'text-purple-700',
    bgColor: 'bg-purple-50',
    borderColor: 'border-purple-200',
    blocks: [
      {
        type: 'welcome',
        name: 'Course Announcement',
        subject_line: '📚 Exciting news: [COURSE NAME] is coming!',
        preview_text: 'Get ready to master [SKILL] in just [TIMEFRAME]',
        body_copy: 'Hi **[FIRST NAME]**,\n\n# New Course Coming Soon 🎓\n\nI\'ve been working on a new course called **[COURSE NAME]**, designed to help you **[MAIN OUTCOME]**.\n\nOver **[DURATION]**, we\'ll cover:\n\n- [MAIN OUTCOME 1]\n- [MAIN OUTCOME 2]\n- [MAIN OUTCOME 3]\n\nThis will be a step-by-step program with lessons, exercises, and support.\n\nEnrollment opens on **[DATE]**. I\'ll share more details and a full breakdown soon.\n\n**[YOUR NAME]**',
        cta_text: '👀 Learn More',
        cta_url: 'https://course.com/preview',
        send_delay_hours: 0,
        position_x: 100,
        position_y: 100,
      },
      {
        type: 'follow-up',
        name: 'Behind the Scenes',
        subject_line: '💭 The story behind [COURSE NAME] (personal)',
        preview_text: 'Why I created this course and what makes it different',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## Why I Created [COURSE NAME] 💬\n\nA quick story:\n\n[Share a short, honest story about the problem you had, what you tried, and what finally worked.]\n\n[COURSE NAME] takes that process and turns it into a clear, repeatable system you can follow.\n\nTomorrow I\'ll send you a module breakdown so you can see exactly what\'s inside.\n\n**[YOUR NAME]**',
        cta_text: '🔔 Get Notified',
        cta_url: 'https://course.com/notify',
        send_delay_hours: 72,
        position_x: 450,
        position_y: 100,
      },
      {
        type: 'offer',
        name: 'Course Launch',
        subject_line: '🎉 [COURSE NAME] is NOW OPEN for enrollment!',
        preview_text: 'Early bird pricing: Save $200 for 48 hours only',
        body_copy: 'Hi **[FIRST NAME]**,\n\n# Enrollment Is Now Open 🎉\n\n[COURSE NAME] is officially open for enrollment.\n\nIf you want to **[MAIN OUTCOME]**, this course will guide you from [START] to [END RESULT].\n\nGet all the details and join here: [SALES PAGE LINK]\n\n**[YOUR NAME]**',
        cta_text: '🔥 Enroll Now - Save $200',
        cta_url: 'https://course.com/enroll',
        send_delay_hours: 96,
        position_x: 800,
        position_y: 100,
      },
      {
        type: 'reminder',
        name: 'Social Proof',
        subject_line: '⭐ [COURSE NAME] student results (see inside)',
        preview_text: 'Real students, real results in just weeks',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## A Few Student Stories 🌟\n\nBefore opening enrollment broadly, I ran [COURSE NAME] with a small group.\n\nHere\'s what a few of them experienced:\n\n- **[STUDENT 1]** – went from [BEFORE] to [AFTER]\n- **[STUDENT 2]** – achieved [RESULT]\n- **[STUDENT 3]** – implemented [STRATEGY] and saw [OUTCOME]\n\nIf you\'d like similar results, you can still join here: [SALES PAGE LINK]\n\n**[YOUR NAME]**',
        cta_text: '✨ Join Them Today',
        cta_url: 'https://course.com/enroll',
        send_delay_hours: 120,
        position_x: 1150,
        position_y: 100,
      },
      {
        type: 'reminder',
        name: 'Final Hours',
        subject_line: '⏰ FINAL HOURS: Early bird ends at midnight',
        preview_text: 'Don\'t miss your chance to save $200',
        body_copy: 'Hi **[FIRST NAME]**,\n\n# Last Chance to Join [COURSE NAME] ⏰\n\nEnrollment closes tonight at **[TIME]**.\n\nAfter that, the doors will be closed while I focus on working with the new group.\n\nIf you\'ve been considering it and don\'t want to wait for a future round, you can enroll here: [SALES PAGE LINK]\n\n**[YOUR NAME]**',
        cta_text: '🔥 Enroll Before Midnight',
        cta_url: 'https://course.com/enroll',
        send_delay_hours: 144,
        position_x: 1500,
        position_y: 100,
      },
      {
        type: 'follow-up',
        name: 'Course Open - Regular Price',
        subject_line: '📚 Course is still open (regular pricing)',
        preview_text: 'Join anytime - payment plans still available',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## [COURSE NAME] Is Still Open (For Now) 💡\n\nEarly-bird pricing has ended, but enrollment is still open for a short time.\n\nIf you\'re ready to work on **[MAIN OUTCOME]**, all the details are here: [SALES PAGE LINK]\n\nIf you have questions before deciding, reply to this email and tell me what you\'re unsure about — I\'ll help you figure out if it\'s a good fit.\n\n**[YOUR NAME]**',
        cta_text: '✨ Enroll Today',
        cta_url: 'https://course.com/enroll',
        send_delay_hours: 168,
        position_x: 1850,
        position_y: 100,
      }
    ],
    connections: [
      { source_index: 0, target_index: 1, condition_type: 'opened' },
      { source_index: 1, target_index: 2, condition_type: 'default' },
      { source_index: 2, target_index: 3, condition_type: 'not_clicked' },
      { source_index: 3, target_index: 4, condition_type: 'not_clicked' },
      { source_index: 4, target_index: 5, condition_type: 'not_clicked' }
    ]
  },
  {
    id: 'certification-program',
    name: 'Certification Program Launch',
    description: 'Promote professional certification courses',
    category: 'education',
    icon: '🏆',
    color: 'text-violet-700',
    bgColor: 'bg-violet-50',
    borderColor: 'border-violet-200',
    blocks: [
      {
        type: 'welcome',
        name: 'Certification Announcement',
        subject_line: '🏆 Become a certified [PROFESSION]',
        preview_text: 'Professional certification program now enrolling',
        body_copy: 'Hi **[FIRST NAME]**,\n\n# Enroll in [CERTIFICATION NAME] 🎓\n\nWe\'re now accepting applications for the next cohort of **[CERTIFICATION NAME]**.\n\nThis program is designed for [TARGET AUDIENCE] who want to:\n\n- Deepen their expertise in [TOPIC]\n- Gain a recognized credential\n- Open up new career or client opportunities\n\nYou can see all program details here: [LINK]\n\n**[INSTITUTION NAME]**',
        cta_text: '🎓 Apply Now',
        cta_url: 'https://yoursite.com/certification',
        send_delay_hours: 0,
        position_x: 100,
        position_y: 100,
      },
      {
        type: 'follow-up',
        name: 'Success Stories',
        subject_line: '💼 How [NAME] landed their dream job after certification',
        preview_text: 'Real career transformations from our graduates',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## What Graduates Are Saying 🌟\n\nHere are a few highlights from past participants in **[CERTIFICATION NAME]**:\n\n- **[GRADUATE 1]** – went from [BEFORE ROLE] to [AFTER ROLE]\n- **[GRADUATE 2]** – leveraged the certification to achieve [RESULT]\n- **[GRADUATE 3]** – used the skills to [OUTCOME]\n\nIf you\'d like to see similar progress in your own career, you can review the curriculum and enrollment details here: [LINK]\n\n**[INSTITUTION NAME]**',
        cta_text: '📚 View Full Program',
        cta_url: 'https://yoursite.com/certification',
        send_delay_hours: 72,
        position_x: 450,
        position_y: 100,
      },
      {
        type: 'reminder',
        name: 'Application Deadline',
        subject_line: '⏰ 7 days left: Certification enrollment closes',
        preview_text: 'Don\'t miss this cohort - next one in 6 months',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## Enrollment Closing Soon ⏰\n\nA quick reminder that applications for **[CERTIFICATION NAME]** close on **[DEADLINE]**.\n\nIf you\'d like to be part of this cohort, now is the time to apply.\n\nLearn more and submit your application here: [LINK]\n\n**[INSTITUTION NAME]**',
        cta_text: '🏃 Enroll Before It Closes',
        cta_url: 'https://yoursite.com/certification',
        send_delay_hours: 168,
        position_x: 800,
        position_y: 100,
      }
    ],
    connections: [
      { source_index: 0, target_index: 1, condition_type: 'not_clicked' },
      { source_index: 1, target_index: 2, condition_type: 'not_clicked' }
    ]
  },
  {
    id: 'student-onboarding',
    name: 'Student Onboarding Series',
    description: 'Welcome and orient new course students',
    category: 'education',
    icon: '📖',
    color: 'text-violet-700',
    bgColor: 'bg-violet-50',
    borderColor: 'border-violet-200',
    blocks: [
      {
        type: 'welcome',
        name: 'Welcome Email',
        subject_line: '🎉 Welcome to [COURSE NAME]!',
        preview_text: 'Your learning journey starts now',
        body_copy: 'Hi **[FIRST NAME]**,\n\n# Welcome! 🎉\n\nWelcome to **[COURSE NAME]**! We\'re thrilled to have you.\n\n### Your course starts:\n\n📅 **[START DATE]**\n🔗 **Access:** [COURSE_PORTAL_LINK]\n📧 **Login:** [EMAIL]\n\n### What to do now:\n\n**1.** Complete your **profile setup**\n**2.** Download the **course guide**\n**3.** Join the **student community**\n**4.** Review **Week 1 overview**\n\n### Course structure:\n\n📚 **[X] modules** over [X] weeks\n🎥 **Video lessons** + downloadable resources\n💬 **Weekly Q&A** sessions\n📝 **Practical assignments**\n\n---\n\nExcited to start learning? 🚀\n\n**Your Instructor,**\n**[INSTRUCTOR NAME]**',
        cta_text: '🎓 Access Course',
        cta_url: 'https://course.com/login',
        send_delay_hours: 0,
        position_x: 100,
        position_y: 100,
      },
      {
        type: 'follow-up',
        name: 'Week 1 Check-in',
        subject_line: '📚 How\'s Week 1 going?',
        preview_text: 'Tips to help you succeed',
        body_copy: 'Hi **[FIRST NAME]**,\n\n## Week 1 Check-in! 📚\n\nHow\'s your first week going?\n\n### Success tips:\n\n⏰ **Set a schedule** - [X] hours/week recommended\n✅ **Complete assignments** before moving on\n💬 **Ask questions** in the community\n🎯 **Focus on application**, not perfection\n\n### This week\'s focus:\n\n📖 [WEEK_1_TOPIC]\n🎯 [KEY_LEARNING_GOAL]\n📝 [ASSIGNMENT_OVERVIEW]\n\n### Need help?\n\n💬 **Community forum:** [LINK]\n📞 **Office hours:** [SCHEDULE]\n📧 **Email support:** [EMAIL]\n\n---\n\nYou\'re doing great! Keep going! 💪\n\n**[INSTRUCTOR NAME]**',
        cta_text: '📖 Continue Learning',
        cta_url: 'https://course.com/week-1',
        send_delay_hours: 168,
        position_x: 450,
        position_y: 100,
      },
      {
        type: 'follow-up',
        name: 'Midpoint Motivation',
        subject_line: '💪 You\'re halfway there!',
        preview_text: 'Keep up the amazing progress',
        body_copy: 'Hi **[FIRST NAME]**,\n\n# You\'re Halfway! 💪\n\nCongratulations on making it **halfway through [COURSE NAME]**!\n\n### Your progress:\n\n✅ **[X]%** complete\n🎯 **[X]** assignments submitted\n⭐ **[X]** modules mastered\n\n### What students say at this point:\n\n*"I can already see the difference in my [SKILL]!"*\n\n*"The practical exercises are game-changers!"*\n\n### Coming up:\n\n📚 **Weeks [X-X]:** Advanced techniques\n🎯 **Final project:** Apply everything you\'ve learned\n🏆 **Certification:** Upon completion\n\n---\n\nKeep pushing forward! 🚀\n\n**[INSTRUCTOR NAME]**',
        cta_text: '🎯 Continue Course',
        cta_url: 'https://course.com/dashboard',
        send_delay_hours: 504,
        position_x: 800,
        position_y: 100,
      }
    ],
    connections: [
      { source_index: 0, target_index: 1, condition_type: 'default' },
      { source_index: 1, target_index: 2, condition_type: 'default' }
    ]
  }
];
