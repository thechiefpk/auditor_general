'use client';

interface ConsentModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  scanType: 'local' | 'git' | 'advanced' | 'sql';
}

export default function ConsentModal({ isOpen, onClose, onConfirm, scanType }: ConsentModalProps) {
  if (!isOpen) return null;

  const isAdvanced = scanType === 'advanced';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl max-w-md w-full p-6 shadow-2xl animate-in fade-in zoom-in-95 duration-200">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-full bg-blue-500/10 flex items-center justify-center">
            <svg className="w-6 h-6 text-blue-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <h2 className="text-xl font-bold text-white">Code Access Consent</h2>
        </div>

        <div className="space-y-4 text-zinc-300 text-sm leading-relaxed">
          <p>
            By proceeding, you agree to share the codebase with us for scanning purposes only.
          </p>
          <ul className="list-disc pl-5 space-y-2 text-zinc-400">
            <li>Your code will <strong>not</strong> be stored permanently or shared further.</li>
            <li>Codebase files are destroyed immediately after scanning.</li>
            <li>Only scan findings (metadata) will be stored in our database.</li>
          </ul>

          {isAdvanced && (
            <div className="p-3 bg-amber-500/10 border border-amber-500/20 rounded-lg">
              <p className="text-amber-200 text-xs font-medium flex items-start gap-2">
                <svg className="w-4 h-4 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                   <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
                Note: This advanced scan involves processing by a 3rd party analysis engine for deep data flow inspection.
              </p>
            </div>
          )}
        </div>

        <div className="flex justify-end gap-3 mt-8">
          <button
            onClick={onClose}
            className="px-4 py-2 text-zinc-400 hover:text-white font-medium transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className="px-6 py-2 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-lg shadow-lg shadow-blue-500/20 transition-all"
          >
            I Agree, Start Scan
          </button>
        </div>
      </div>
    </div>
  );
}
