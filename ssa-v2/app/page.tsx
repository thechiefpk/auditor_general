'use client'; // This page still needs to be a client component for the hero buttons

import Link from 'next/link';
import { useAuth } from './context/AuthContext';
import Header from './components/Header'; // Import the header

export default function Home() {
  const { user } = useAuth(); // Get the current user state

  // --- NEW THEMATIC ICONS ---
  // 1. Secure Earth Icon
  const GlobeAltIcon = () => (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" className="h-6 w-6 text-green-600">
      <path fillRule="evenodd" d="M12 2.25c-5.385 0-9.75 4.365-9.75 9.75s4.365 9.75 9.75 9.75 9.75-4.365 9.75-9.75S17.385 2.25 12 2.25zM12.75 6a.75.75 0 00-1.5 0v.012c.312.023.62.057.928.102.348.05.682.112 1.002.185.32.073.627.155.918.246.29.09.563.19.82.3a.75.75 0 00.582-1.37c-.276-.118-.566-.226-.87-.323a12.01 12.01 0 00-1.141-.21 12.01 12.01 0 00-1.127-.088H12.75V6zM11.25 7.5v-.012c-.312.023-.62.057-.928.102a11.848 11.848 0 00-1.002.185 11.82 11.82 0 00-.918.246c-.29.09-.563.19-.82.3a.75.75 0 00.582 1.37c.276-.118.566-.226.87-.323.348-.096.71-.182 1.08-.255.37-.073.746-.135 1.127-.184V7.5z" clipRule="evenodd" />
      <path d="M12.75 9.385v.006c.044.003.088.006.133.009.431.03.858.076 1.278.138.419.062.827.14 1.218.23a.75.75 0 10.582-1.37c-.39-.09-.79-.17-1.18-.232a13.34 13.34 0 00-1.26-.145 13.29 13.29 0 00-.135-.009V9.385zm-1.5 0v.006c-.044.003-.088.006-.133.009a13.27 13.27 0 00-1.278.138 13.4 13.4 0 00-1.218.23.75.75 0 10.582 1.37c.39-.09.79-.17 1.18-.232.41-.06.837-.107 1.26-.145.046-.003.09-.006.135-.009V9.385z" />
      <path d="M13.5 11.25v.006c.044.003.088.006.133.009.431.03.858.076 1.278.138.419.062.827.14 1.218.23a.75.75 0 10.582-1.37c-.39-.09-.79-.17-1.18-.232a13.34 13.34 0 00-1.26-.145 13.29 13.29 0 00-.135-.009V11.25zm-3 0v.006c-.044.003-.088.006-.133.009a13.27 13.27 0 00-1.278.138 13.4 13.4 0 00-1.218.23.75.75 0 10.582 1.37c.39-.09.79-.17 1.18-.232.41-.06.837-.107 1.26-.145.046-.003.09-.006.135-.009V11.25z" />
      <path d="M13.5 13.115v.006c.044.003.088.006.133.009.431.03.858.076 1.278.138.419.062.827.14 1.218.23a.75.75 0 10.582-1.37c-.39-.09-.79-.17-1.18-.232a13.34 13.34 0 00-1.26-.145 13.29 13.29 0 00-.135-.009V13.115zm-3 0v.006c-.044.003-.088.006-.133.009a13.27 13.27 0 00-1.278.138 13.4 13.4 0 00-1.218.23.75.75 0 10.582 1.37c.39-.09.79-.17 1.18-.232.41-.06.837-.107 1.26-.145.046-.003.09-.006.135-.009V13.115z" />
      <path d="M13.5 15v.006c.044.003.088.006.133.009.431.03.858.076 1.278.138.419.062.827.14 1.218.23a.75.75 0 10.582-1.37c-.39-.09-.79-.17-1.18-.232a13.34 13.34 0 00-1.26-.145 13.29 13.29 0 00-.135-.009V15zm-3 0v.006c-.044.003-.088.006-.133.009a13.27 13.27 0 00-1.278.138 13.4 13.4 0 00-1.218.23.75.75 0 10.582 1.37c.39-.09.79-.17 1.18-.232.41-.06.837-.107 1.26-.145.046-.003.09-.006.135-.009V15z" />
      <path d="M13.5 16.885v.006c.044.003.088.006.133.009.431.03.858.076 1.278.138.419.062.827.14 1.218.23a.75.75 0 10.582-1.37c-.39-.09-.79-.17-1.18-.232a13.34 13.34 0 00-1.26-.145 13.29 13.29 0 00-.135-.009V16.885zm-3 0v.006c-.044.003-.088.006-.133.009a13.27 13.27 0 00-1.278.138 13.4 13.4 0 00-1.218.23.75.75 0 10.582 1.37c.39-.09.79-.17 1.18-.232.41-.06.837-.107 1.26-.145.046-.003.09-.006.135-.009V16.885z" />
      <path d="M12 18.75a.75.75 0 00-.75.75v.012c-.312-.023-.62-.057-.928-.102a11.848 11.848 0 00-1.002-.185 11.82 11.82 0 00-.918-.246c-.29-.09-.563-.19-.82-.3a.75.75 0 00-.582 1.37c.276.118.566.226.87.323.348.096.71.182 1.08.255.37.073.746.135 1.127.184V19.5a.75.75 0 00.75-.75v-.012c.312-.023.62-.057.928-.102.348-.05.682-.112 1.002-.185.32-.073.627-.155.918-.246.29-.09.563-.19.82-.3a.75.75 0 00-.582-1.37c-.276.118-.566.226-.87.323a12.01 12.01 0 00-1.141.21 12.01 12.01 0 00-1.127.088V18.75z" />
    </svg>
  );

  // 2. API / Automation Icon
  const CpuChipIcon = () => (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" className="h-6 w-6 text-green-600">
      <path fillRule="evenodd" d="M14.25 2.25c.53 0 1.03.2 1.41.59l4.5 4.5c.39.39.59.88.59 1.41v10.5c0 1.24-1.01 2.25-2.25 2.25H5.25c-1.24 0-2.25-1.01-2.25-2.25V3c0-1.24 1.01-2.25 2.25-2.25h9zM13.5 3.75h-8.25a.75.75 0 00-.75.75v15c0 .41.34.75.75.75h13.5a.75.75 0 00.75-.75V8.25l-4.5-4.5z" clipRule="evenodd" />
      <path d="M9 10.5a.75.75 0 000 1.5h6a.75.75 0 000-1.5H9zM9 13.5a.75.75 0 000 1.5h6a.75.75 0 000-1.5H9zM9 16.5a.75.75 0 000 1.5h3a.75.75 0 000-1.5H9z" />
      <path fillRule="evenodd" d="M13.5 3.75c0-1.03.84-1.875 1.875-1.875h.375c.62 0 1.12.51 1.12 1.12V7.5h-3.37c-.3 0-.58-.1-.79-.29L13.5 6.4v-2.65z" clipRule="evenodd" />
    </svg>
  );
  
  // 3. Dashboard / Report Icon
  const ChartBarIcon = () => (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" className="h-6 w-6 text-green-600">
      <path d="M3.375 3C2.339 3 1.5 3.84 1.5 4.875v14.25C1.5 20.16 2.34 21 3.375 21h17.25c1.035 0 1.875-.84 1.875-1.875V4.875C22.5 3.839 21.66 3 20.625 3H3.375zM9 6h1.5v9H9V6zm3 2.25h1.5v6.75H12V8.25zm3 2.25h1.5v4.5H15V10.5z" />
    </svg>
  );
  // --- END OF ICONS ---


  return (
    <div className="flex min-h-screen flex-col bg-white dark:bg-black">
      <Header />

      <main className="flex-grow">
        {/* --- Hero Section --- */}
        <section className="flex flex-col items-center justify-center pt-32 pb-24 text-center">
          <div className="mx-auto max-w-3xl px-6">
            <div className="mb-4 flex items-center justify-center gap-2 rounded-full border border-gray-200 p-1 px-3 text-sm text-gray-600 dark:border-gray-700 dark:text-gray-300">
              <span className="rounded-full bg-green-200 p-1">
                {/* Updated Icon */}
                <GlobeAltIcon /> 
              </span>
              Authentication & Security
            </div>
            <h1 className="text-5xl font-bold tracking-tight text-gray-900 dark:text-white sm:text-6xl">
              Premium auth template that you can trust.
            </h1>
            <p className="mt-6 text-lg leading-8 text-gray-600 dark:text-gray-300">
              This project delivers an automated and expert-led foundation for
              authentication. Log in, sign up, and view protected routes in
              minutes, not months.
            </p>
            <div className="mt-10 flex items-center justify-center gap-x-6">
              {user ? (
                // --- Logged In Hero Button ---
                <Link
                  href="/dashboard"
                  className="rounded-lg bg-green-600 px-5 py-3 text-base font-semibold text-white shadow-lg hover:bg-green-700 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-green-600"
                >
                  Go to Dashboard
                </Link>
              ) : (
                // --- Logged Out Hero Buttons ---
                <>
                  <Link
                    href="/signup"
                    className="rounded-lg bg-green-600 px-5 py-3 text-base font-semibold text-white shadow-lg hover:bg-green-700 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-green-600"
                  >
                    Get started
                  </Link>
                  <Link
                    href="/login"
                    className="text-base font-semibold leading-6 text-gray-900 dark:text-white"
                  >
                    Sign in <span aria-hidden="true">→</span>
                  </Link>
                </>
              )}
            </div>
          </div>
        </section>

        {/* --- Features Section --- */}
        <section className="bg-white py-24 dark:bg-black">
          <div className="mx-auto max-w-7xl px-6">
            <h2 className="text-center text-3xl font-bold leading-10 text-gray-900 dark:text-white">
              All-in-one authentication engine
            </h2>
            <div className="mt-16 grid grid-cols-1 gap-8 md:grid-cols-3">
              
              {/* Feature 1 */}
              <div className="rounded-lg border border-gray-200 bg-white p-6 shadow-sm dark:border-gray-700 dark:bg-black">
                <div className="flex items-center gap-3">
                  {/* Updated Icon */}
                  <GlobeAltIcon />
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                    Secure & Protected
                  </h3>
                </div>
                <p className="mt-4 text-gray-600 dark:text-gray-300">
                  Pre-built controls, policy templates, and login/signup flows.
                </p>
                <ul className="mt-4 space-y-2 text-sm text-gray-700 dark:text-gray-200">
                  <li>✔ Mapped to service criteria</li>
                  <li>✔ Continuous control monitoring</li>
                  <li>✔ Gap-to-control mapping</li>
                </ul>
              </div>

              {/* Feature 2 */}
              <div className="rounded-lg border border-gray-200 bg-white p-6 shadow-sm dark:border-gray-700 dark:bg-black">
                <div className="flex items-center gap-3">
                  {/* Updated Icon */}
                  <CpuChipIcon />
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                    API-first Automation
                  </h3>
                </div>
                <p className="mt-4 text-gray-600 dark:text-gray-300">
                  Connect cloud, identity, and code to collect and normalize data.
                </p>
                <ul className="mt-4 space-y-2 text-sm text-gray-700 dark:text-gray-200">
                  <li>✔ Your API, Auth0, etc.</li>
                  <li>✔ Least-privilege connectors</li>
                  <li>✔ Encrypted at rest and in transit</li>
                </ul>
              </div>

              {/* Feature 3 */}
              <div className="rounded-lg border border-gray-200 bg-white p-6 shadow-sm dark:border-gray-700 dark:bg-black">
                <div className="flex items-center gap-3">
                  {/* Updated Icon */}
                  <ChartBarIcon />
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                    Dashboard-ready Reports
                  </h3>
                </div>
                <p className="mt-4 text-gray-600 dark:text-gray-300">
                  Board-grade data with clear status and residual risk summaries.
                </p>
                <ul className="mt-4 space-y-2 text-sm text-gray-700 dark:text-gray-200">
                  <li>✔ Coverage, gaps, remediation</li>
                  <li>✔ Share securely with dashboard</li>
                  <li>✔ Attestation-ready output</li>
                </ul>
              </div>
            </div>
          </div>
        </section>
      </main>

      {/* --- Footer --- */}
      <footer className="bg-white dark:bg-black">
        <div className="mx-auto max-w-7xl px-6 py-12">
          <p className="text-center text-xs leading-5 text-gray-500 dark:text-gray-400">
            &copy; 2025 Your Company, Inc. All rights reserved.
          </p>
        </div>
      </footer>
    </div>
  );
}
