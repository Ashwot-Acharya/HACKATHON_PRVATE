import { Config } from 'tailwindcss';

const config: Config = {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        background: {
          primary: '#F9FAFB', // gray-50
          secondary: '#FFFFFF',
          panel: '#FFFFFF',
          elevated: '#F3F4F6', // gray-100
          border: '#E5E7EB', // gray-200
          darker: '#E5E7EB',
        },
        text: {
          primary: '#111827', // gray-900
          secondary: '#4B5563', // gray-600
          muted: '#9CA3AF' // gray-400
        },
        accent: {
          DEFAULT: '#11D9C5',
          teal: '#027373',
          glow: '#11D9C5',
        },
        challenge: {
          c1: '#11D9C5',
          c2: '#F59E0B',
          c3: '#8B5CF6',
          c4: '#027373'
        },
        severity: {
          critical: '#EF4444',
          high: '#F97316',
          medium: '#EAB308',
          low: '#22C55E',
          info: '#6B7280'
        },
        state: {
          safe: '#0a3060',
          suspicious: '#B45309',
          compromised: '#991B1B',
          isolated: '#011C40'
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace']
      },
      animation: {
        'fade-up': 'fade-up 0.4s ease-out both',
        'slide-right': 'slide-in-right 0.3s ease-out both',
        'slide-left': 'slide-in-left 0.3s ease-out both',
        'scale-in': 'scale-in 0.3s ease-out both',
        'count-up': 'count-up 0.5s ease-out both',
        'pulse-glow': 'pulse-glow 2s ease-in-out infinite',
        'threat-pulse': 'threat-pulse 1.5s ease-in-out infinite',
        'shimmer': 'shimmer 1.5s ease-in-out infinite',
      },
      backdropBlur: {
        xs: '2px',
      },
      boxShadow: {
        'glow-teal': '0 0 20px rgba(17, 217, 197, 0.15)',
        'glow-accent': '0 0 20px rgba(2, 115, 115, 0.2)',
        'glow-purple': '0 0 20px rgba(139, 92, 246, 0.15)',
        'glow-amber': '0 0 20px rgba(245, 158, 11, 0.15)',
        'glow-red': '0 0 20px rgba(239, 68, 68, 0.2)',
        'glow-cyan': '0 0 30px rgba(17, 217, 197, 0.25)',
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(ellipse at center, var(--tw-gradient-stops))',
        'grid-pattern': 'linear-gradient(rgba(10,48,96,0.3) 1px, transparent 1px), linear-gradient(to right, rgba(10,48,96,0.3) 1px, transparent 1px)',
      },
      backgroundSize: {
        'grid': '40px 40px',
      },
    }
  },
  plugins: []
};

export default config;
