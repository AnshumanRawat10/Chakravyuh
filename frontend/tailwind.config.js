/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        military: {
          olive: '#4B5320', // standard military olive
          lightOlive: '#6B762F',
          glowing: '#4E804E', // glowing green
          neon: '#22C55E', // high vis neon green
          gold: '#D4AF37', // brass/gold
          cyber: '#06B6D4', // cyan cyber glow
          dark: '#0B131A', // deep army slate
          black: '#030708', // ultra dark
          red: '#EF4444' // red warning alerts
        }
      },
      fontFamily: {
        orbitron: ['Orbitron', 'sans-serif'],
        inter: ['Inter', 'sans-serif'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      }
    },
  },
  plugins: [],
}
