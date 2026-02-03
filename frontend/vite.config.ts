import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 3000,
    proxy: {
      '/v1': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      // Proxy admin API calls to backend
      // Use bypass to let GET requests for page navigation go to React Router
      '/admin': {
        target: 'http://localhost:8080',
        changeOrigin: true,
        bypass: (req) => {
          // Only proxy API calls (POST, PUT, DELETE, PATCH)
          // Let GET requests through to React Router for page navigation
          if (req.method === 'GET' && req.headers.accept?.includes('text/html')) {
            return req.url;
          }
          // Proxy all other requests to backend
          return null;
        },
      },
    },
  },
})
