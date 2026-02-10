# Shankar's Galaxy Portfolio

Shankar Adhikary's Personal Portfolio Website

A futuristic, space-exploration themed portfolio showcasing skills in Cybersecurity (Red Teaming), Full-stack Development, and AI/ML.

![Theme](https://img.shields.io/badge/Theme-Grok%20Galaxy-6A0DAD)
![Status](https://img.shields.io/badge/Status-Active-39FF14)

## Features

- **Interactive 3D Starfield** - Three.js powered cosmic background with mouse parallax
- **Glassmorphism Design** - Modern frosted glass card effects
- **Smooth Animations** - Float effects, glow pulses, and scroll animations
- **Fully Responsive** - Works seamlessly on all devices
- **Dark Theme** - True black (#050505) with purple-blue gradients
- **SEO Optimized** - Proper meta tags for search engines

## 🎨 Design System

### Colors
| Name | Hex | Usage |
|------|-----|-------|
| Cosmic Purple | `#6A0DAD` | Primary accent |
| Nebula Blue | `#1E90FF` | Secondary accent |
| Cyber Lime | `#39FF14` | Highlight/Success |
| True Black | `#050505` | Background |
| Neon White | `#F0F0F0` | Text highlights |

### Typography
- **Headings**: Space Grotesk, JetBrains Mono
- **Body**: Inter
- **Code**: JetBrains Mono

## 🏗️ Structure

```
portfolio/
├── index.html          # Main portfolio page
├── README.md           # Documentation
└── assets/            # (Add your images here)
    ├── profile.jpg    # Your profile photo
    └── projects/      # Project screenshots
```

## 📑 Sections

1. **The Event Horizon (Hero)** - Introduction with animated tagline
2. **The Origin (About)** - Bio and quick stats
3. **Experience** - Career timeline with glassmorphism cards
4. **The Toolkit (Skills)** - Animated skill bars and categories
5. **The Constellations (Projects)** - Featured work gallery
6. **The Uplink (Contact)** - Secure contact form

## 🚀 Quick Start

### Option 1: Direct Open
Simply open `index.html` in your browser.

### Option 2: Live Server (Recommended)
```bash
# Install Live Server extension in VS Code
# Right-click index.html → "Open with Live Server"
```

### Option 3: Python Server
```bash
cd portfolio
python -m http.server 8000
# Open http://localhost:8000
```

## 🔧 Customization

### Update Personal Info
1. Edit name and tagline in the Hero section
2. Update the About section with your bio
3. Replace placeholder email and social links
4. Add your profile photo

### Add Projects
Add new project cards in the Work section following the existing template:

```html
<div class="project-card glass-card rounded-2xl overflow-hidden...">
    <!-- Your project content -->
</div>
```

### Change Colors
Modify the Tailwind config in the `<script>` tag:

```javascript
tailwind.config = {
    theme: {
        extend: {
            colors: {
                'cosmic-purple': '#YOUR_COLOR',
                // ...
            }
        }
    }
}
```

## 🌐 Deployment

### GitHub Pages
1. Push to GitHub repository
2. Go to Settings → Pages
3. Select main branch and save

### Vercel
1. Connect your GitHub repository
2. Deploy automatically

### Netlify
1. Drag and drop the portfolio folder
2. Get instant deployment

## 📱 Browser Support

- Chrome (recommended)
- Firefox
- Safari
- Edge
- Mobile browsers

## 📄 License

MIT License - Feel free to use and modify!

---

**Built with ♥ in the Shankar's Galaxy**

*Shankar Adhikary | Cybersecurity • Full Stack • AI/ML*
