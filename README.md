# My Portfolio

**[Live site →](https://portfolio-main-adhikaryshankar04-1527s-projects.vercel.app/)**

Hey, I'm Shankar — a BTech Cybersecurity student at Rashtriya Raksha University (batch 2025–29). This repo is the source code for my personal portfolio. I built it from scratch to be something more than a static page — it has a working terminal, a 3D skills globe, and it works offline as a PWA.

---

## What's inside

The whole thing is plain HTML/CSS/JS — no build step, no frameworks. I used Tailwind via CDN to keep the styling sane and Three.js for the background starfield. The most interesting file is probably `terminal.js`, which simulates a Kali Linux shell with 50+ commands you can actually run in the browser.

```
portfolio/
├── assets/
│   ├── certificates/    # certs I've collected over time
│   ├── icon.svg
│   ├── profile.png
│   └── resume.pdf
├── .well-known/         # security.txt and policy configs
├── sw.js                # service worker for offline support
├── manifest.json        # makes it installable as a PWA
├── terminal.js          # browser terminal emulator
├── index.html           # everything lives here
└── README.md
```

**Stack:**
- HTML5 + Tailwind CSS (CDN) + vanilla JS
- Three.js for the starfield and TagCloud for the 3D skills globe
- Formspree for the contact form
- Deployed on Vercel

---

## Running it locally

You can't just open `index.html` directly because of how ES6 modules and the service worker behave — you need a local server. The easiest way:

```bash
git clone https://github.com/ShankarAdhikary/portfolio.git
cd portfolio
python -m http.server 8000
```

Then open `http://localhost:8000`.

---

## A few things I'm proud of

- The terminal emulator feels pretty real. Try typing `help` or `hack` in it.
- The site scores well on Lighthouse and I've added proper CSP headers, X-Frame-Options, and a `security.txt` — security is kind of my thing.
- It's a fully installable PWA, so you can add it to your home screen and it'll work without a connection.

---

## License

MIT — take whatever you want from it.

---

*Shankar Adhikary — Cybersecurity & Full-Stack Dev, RRU*  
*राष्ट्रीय सुरक्षा सर्वोपरि*
