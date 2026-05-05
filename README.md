# 🚀 Portfolio Website | Cosmic Edition

Welcome to the source code for my personal portfolio. This isn't just a static site; it’s a high-performance, interactive hub designed to showcase my journey across **Cybersecurity**, **Full-Stack Development**, and **AI/ML**. 

Built with a "Security-First" mindset and a "Cosmic-Glass" aesthetic, this repo houses everything from a custom-built Linux terminal emulator to a Three.js powered starfield.

**[🌐 Live Demo](https://portfolio-main-adhikaryshankar04-1527s-projects.vercel.app/)**

---

## 🛠 Tech Stack

| Layer | Tools |
| :--- | :--- |
| **Frontend** | HTML5, Modern CSS (Tailwind via CDN), ES6+ JavaScript |
| **Graphics** | Three.js (3D Starfield & Skills Globe), CSS Keyframes |
| **Backend/API** | Formspree (Contact Logic), Service Workers (PWA) |
| **Icons** | Lucide Icons |
| **Deployment** | Vercel / GitHub Pages |

---

## ⚡ Engineering Highlights

*   **Interactive Terminal Simulation:** A custom `terminal.js` engine that emulates a Kali Linux environment with 50+ functional commands, providing an immersive "hacking" experience.
*   **3D Visualization:** Leveraged **Three.js** to create a responsive, mouse-parallax starfield and a rotating 3D skills tag cloud.
*   **PWA Ready:** Fully compliant Progressive Web App. It’s installable on desktop/mobile and uses a service worker for aggressive offline caching.
*   **Glassmorphism UI:** Implemented a sophisticated cosmic theme using backdrop-filters and semi-transparent layers for a modern, high-end feel.
*   **SEO & Meta:** Rigged with Open Graph tags and structured data to ensure high visibility and clean previews on social platforms.

---

## 📂 Project Architecture

```bash
portfolio/
├── assets/
│   ├── certificates/    # 25+ Industry-standard certs
│   ├── icon.svg         # Scalable vector branding
│   ├── profile.png      # Profile photography
│   └── resume.pdf       # Professional CV
├── .well-known/         # Security & policy configs
├── sw.js                # Service Worker logic (PWA)
├── manifest.json        # Web App Manifest
├── terminal.js          # The "brain" behind the terminal sim
├── index.html           # Main DOM structure
└── README.md            # You are here
```

---

## 🚀 Quick Start (Local Development)

To get this environment running locally:

### 1. Clone the Lab
```bash
git clone https://github.com/ShankarAdhikary/portfolio.git
cd portfolio
```

### 2. Launch
Since the project uses ES6 modules and PWA features, it’s best viewed through a local server rather than opening the file directly.

**Using Python:**
```bash
python -m http.server 8000
```
Then hit `http://localhost:8000` in your browser.

---

## 🌌 The Roadmap (Sections)

1.  **The Event Horizon (Hero):** Smooth typing animations with dynamic taglines.
2.  **The Origin (About):** Core stats and professional narrative.
3.  **The Toolkit (Skills):** Visualizing the stack through 3D interaction.
4.  **The Constellations (Projects):** A curated gallery of full-stack and security builds.
5.  **The Uplink (Contact):** Secure, filtered contact form for networking.

---

## ⚖️ License

Distributed under the **MIT License**. Feel free to fork and build your own galaxy.

---

**Developed with precision by Shankar Adhikary**  
*Cybersecurity Researcher • Full-Stack Dev • AI Enthusiast*  
*राष्ट्रीय सुरक्षा सर्वोपरि — National Security is Supreme*
