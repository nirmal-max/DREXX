import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";

const container = document.getElementById("root")!;

// Reuse the existing root on HMR re-execution instead of calling createRoot twice
const root = (container as any)._reactRoot ?? ReactDOM.createRoot(container);
(container as any)._reactRoot = root;

root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
