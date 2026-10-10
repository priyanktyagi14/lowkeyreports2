import React, { useState } from "react";
import { Header } from "./components/Header";
import { UploadView } from "./components/UploadView";
import { ProcessingView } from "./components/ProcessingView";
import { DashboardView } from "./components/DashboardView";
import { Footer } from "./components/Footer";
import { DEFAULT_VULNERABILITIES } from "./data/telemetryData";

export default function App() {
  const [currentView, setCurrentView] = useState("upload");
  const [parsedData, setParsedData] = useState(null);
  const [vulnerabilities, setVulnerabilities] = useState(DEFAULT_VULNERABILITIES);
  const [companyName, setCompanyName] = useState("Acme Global Enterprise");

  const handleStartProcessing = (data) => {
    setParsedData(data);
    if (data.companyName) {
      setCompanyName(data.companyName);
    }
    setCurrentView("processing");
  };

  const handleProcessingComplete = (completedData) => {
    const finalData = completedData || parsedData;
    if (finalData && finalData.vulnerabilities) {
      setVulnerabilities(finalData.vulnerabilities);
      setParsedData(finalData);
    }
    setCurrentView("dashboard");
  };

  const handleReset = () => {
    setParsedData(null);
    setCurrentView("upload");
  };

  return (
    <div className="app-container">
      <Header currentView={currentView} onReset={handleReset} />

      {currentView === "upload" && (
        <UploadView
          onStartProcessing={handleStartProcessing}
          companyName={companyName}
          setCompanyName={setCompanyName}
        />
      )}

      {currentView === "processing" && (
        <ProcessingView
          parsedData={parsedData || {}}
          onComplete={handleProcessingComplete}
        />
      )}

      {currentView === "dashboard" && (
        <DashboardView
          vulnerabilities={vulnerabilities}
          telemetrySummary={parsedData}
          companyName={companyName}
          setCompanyName={setCompanyName}
        />
      )}

      <Footer />
    </div>
  );
}
