
import React, { useState } from 'react';

interface ScanFormProps {
  onScan: (path: string) => void;
}

const ScanForm: React.FC<ScanFormProps> = ({ onScan }) => {
  const [path, setPath] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onScan(path);
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="text"
        value={path}
        onChange={(e) => setPath(e.target.value)}
        placeholder="Enter directory path"
      />
      <button type="submit">Scan</button>
    </form>
  );
};

export default ScanForm;
