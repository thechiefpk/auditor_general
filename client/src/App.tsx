import React, { useState } from 'react';
import './App.css';
import ScanForm from './components/ScanForm';
import ScanResults from './components/ScanResults';

interface Violation {
  filePath: string;
  lineNumber: number;
  lineContent: string;
  ruleName: string;
}

interface ScanSummary {
  filesScanned: number;
  violationsFound: number;
  violations: Violation[];
}

function App() {
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async (path: string) => {
    
    try {
      const response = await fetch('http://localhost:5059/api/scan/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ path }),
      });

      if (!response.ok) {
        throw new Error('Failed to fetch scan results');
      }

      const data = await response.json();
      setSummary(data);
      setError(null);

    } catch (error: any) {

      setError(error.message);
      setSummary(null);
    }
  };

  return (
    <div className="App">
      <header className="App-header">
        <h1>Compliance Auditor</h1>
      </header>
      <main>
        <ScanForm onScan={handleScan} />
        {error && <p className="error">{error}</p>}
        <ScanResults summary={summary} />
      </main>
    </div>
  );
}

export default App;