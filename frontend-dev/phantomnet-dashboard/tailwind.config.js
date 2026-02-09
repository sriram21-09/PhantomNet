/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                // Cyberpunk Palette
                cyber: {
                    black: "#020617",
                    dark: "#0f172a",
                    gray: "#1e293b",
                    primary: "#2563eb",  // vibrant blue
                    accent: "#06b6d4",   // cyan
                    neon: "#38bdf8",     // bright blue
                }
            }
        },
    },
    plugins: [],
}
