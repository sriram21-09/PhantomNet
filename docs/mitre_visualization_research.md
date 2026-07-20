# MITRE ATT&CK Matrix Visualization Research

## 1. Rendering Methods Comparison

Evaluating front-end options for rendering the 12-tactic MITRE ATT&CK matrix in a responsive and performant dashboard widget.

| Method | Layout Complexity | Performance | Pros | Cons |
| :--- | :--- | :--- | :--- | :--- |
| **HTML Table** | Low. Natural fit for tabular data. | High for simple data, but degrades with highly interactive elements or massive datasets. | Semantic structure, excellent accessibility, built-in row/column relationships. | Difficult to make fully responsive (horizontal scrolling is often required). Hard to style complex spanning cells dynamically. |
| **CSS Grid** | Medium. Requires careful planning for 12 columns. | High. Native browser rendering is extremely fast. | True two-dimensional layout control. Easily handles responsive design via media queries. Clean DOM structure. | Requires modern browser support. Complex nested grids can become difficult to manage without a framework. |
| **SVG / D3.js**| High. Requires custom drawing logic and math for positioning. | Medium-High. Great for complex interactive visualizations, but heavy DOM (many SVG nodes) can impact performance. | Pixel-perfect control, advanced animations, complex data binding, highly interactive (zoom, pan). | Steep learning curve, over-engineered for standard matrix layouts, accessibility requires manual effort. |

**Recommendation:** **CSS Grid** is the optimal choice. It provides the right balance of performance, responsive control, and maintainability for a 12-column matrix layout, avoiding the rigidity of HTML tables and the complexity of D3.js.

## 2. Browser Compatibility and Responsiveness (12-Column Layout)

### Browser Compatibility
CSS Grid is supported by all modern browsers (Chrome, Firefox, Safari, Edge). For legacy browser support (e.g., IE11), CSS Grid features fall back gracefully if auto-placement is not used heavily, though modern dashboard widgets typically target evergreen browsers.

### Responsiveness Considerations
A 12-tactic matrix requires 12 columns, which is challenging on smaller screens.
*   **Desktop (>1200px):** Display all 12 columns side-by-side.
*   **Tablet (768px - 1199px):** Reduce to 6 columns (2 rows of tactics) or implement horizontal scrolling with a sticky header.
*   **Mobile (<768px):** Stack tactics vertically (1 column) using an accordion or card-based layout to prevent excessive zooming or scrolling.

## 3. Dark Mode Dynamic Styling & Utility Components

### Draft CSS Rules (Custom Properties)

Using CSS variables (Custom Properties) allows for seamless switching between light and dark modes.

```css
/* Base Theme (Light) */
:root {
  --bg-primary: #ffffff;
  --bg-secondary: #f4f4f5;
  --text-primary: #18181b;
  --text-secondary: #52525b;
  --border-color: #e4e4e7;
  --matrix-header-bg: #3b82f6;
  --matrix-header-text: #ffffff;
  --technique-bg: #ffffff;
  --technique-hover: #eff6ff;
}

/* Dark Mode Theme */
[data-theme='dark'] {
  --bg-primary: #18181b;
  --bg-secondary: #27272a;
  --text-primary: #f4f4f5;
  --text-secondary: #a1a1aa;
  --border-color: #3f3f46;
  --matrix-header-bg: #1d4ed8;
  --matrix-header-text: #ffffff;
  --technique-bg: #27272a;
  --technique-hover: #3f3f46;
}

/* Matrix Layout (CSS Grid) */
.mitre-matrix {
  display: grid;
  grid-template-columns: repeat(12, 1fr);
  gap: 8px;
  background-color: var(--bg-primary);
  color: var(--text-primary);
  padding: 16px;
  overflow-x: auto; /* Fallback for smaller screens */
}

.tactic-column {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.tactic-header {
  background-color: var(--matrix-header-bg);
  color: var(--matrix-header-text);
  padding: 8px;
  font-weight: bold;
  text-align: center;
  border-radius: 4px;
}

.technique-card {
  background-color: var(--technique-bg);
  border: 1px solid var(--border-color);
  padding: 8px;
  border-radius: 4px;
  font-size: 0.875rem;
  transition: background-color 0.2s ease;
  cursor: pointer;
}

.technique-card:hover {
  background-color: var(--technique-hover);
}

/* Responsive Media Queries */
@media (max-width: 1200px) {
  .mitre-matrix {
    grid-template-columns: repeat(6, 1fr); /* Break into 2 rows for medium screens */
  }
}

@media (max-width: 768px) {
  .mitre-matrix {
    grid-template-columns: 1fr; /* Stack vertically for small screens */
  }
}
```
