
import React from 'react';

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

interface ScanResultsProps {
  summary: ScanSummary | null;
}

const ScanResults: React.FC<ScanResultsProps> = ({ summary }) => {
  if (!summary) {
    return null;
  }

  return (
    <div>
      <h2>Scan Results</h2>
      <p>Files Scanned: {summary.filesScanned}</p>
      <p>Violations Found: {summary.violationsFound}</p>
      {summary.violations.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>File Path</th>
              <th>Line Number</th>
              <th>Line Content</th>
              <th>Rule Name</th>
            </tr>
          </thead>
          <tbody>
            {summary.violations.map((violation, index) => (
              <tr key={index}>
                <td>{violation.filePath}</td>
                <td>{violation.lineNumber}</td>
                <td>{violation.lineContent}</td>
                <td>{violation.ruleName}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
};

export default ScanResults;
