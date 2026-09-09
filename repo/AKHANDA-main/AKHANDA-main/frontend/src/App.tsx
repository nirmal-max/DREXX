import { useState } from "react";
import Landing from "./components/Landing";
import Console from "./components/Console";
import Certificate from "./components/Certificate";
import TamperDemo from "./components/TamperDemo";
import NavShell from "./components/NavShell";

export default function App() {
  const [page, setPage] = useState<string>("landing");

  const renderPage = () => {
    if (page === "console") return <Console />;
    if (page === "certificate") return <Certificate />;
    if (page === "tamperdemo") return <TamperDemo />;
    return <Landing onNavigate={setPage} />;
  };

  return (
    <div style={{ minHeight: "100vh", background: "#060c18", color: "#e2e8f0" }}>
      <NavShell page={page} onNavigate={setPage}>
        {renderPage()}
      </NavShell>
    </div>
  );
}
