import { useState, useEffect } from "react";
import { ThemeContext } from "./ThemeContext";

const ThemeProvider = ({ children }) => {
  // Default to dark theme, but check localStorage for saved preference
  const [theme, setTheme] = useState(() => {
    const saved = localStorage.getItem("phantomnet-theme");
    return saved || "dark"; // Default to dark if no saved preference
  });

  const toggleTheme = () => {
    setTheme((prev) => {
      const newTheme = prev === "dark" ? "light" : "dark";
      localStorage.setItem("phantomnet-theme", newTheme);
      return newTheme;
    });
  };

  // Sync theme with CSS variables
  useEffect(() => {
    document.body.setAttribute("data-theme", theme);
  }, [theme]);

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
};

export default ThemeProvider;
