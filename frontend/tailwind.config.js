/* Tailwind CSS v4 scans files automatically, but we can verify this later. 
   If using the PostCSS plugin, it respects this config but v4 puts content in CSS @theme usually.
   However, let's keep it minimal or remove it if not needed. 
   Actually, v4 PostCSS plugin still uses content array from config if present?
   No, v4 detects content from CSS @import "tailwindcss" source roots?
   Let's keep the config simple but consistent with v4 if possible.
   Actually, with v4, we can just export an empty object or use the CSS configuration.
   But to be safe, I'll keep the exported content array as legacy support or just in case.
   Wait, if I use @import "tailwindcss", the content is determined by the input file location?
   Let's try to remove tailwind.config.js content array and see if it works, or keep it.
   Safest is to keep it. */

export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}
