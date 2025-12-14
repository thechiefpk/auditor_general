import { defineConfig } from 'vite'

// Basic Vite config without @vitejs/plugin-react to avoid ESM loading issues in some Node environments.
export default defineConfig({
    server: { port: 5173 }
})
