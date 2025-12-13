import Link from 'next/link';
import Image from 'next/image';
import { useAuth } from './context/AuthContext';
import Header from './components/Header';

export default function Home() {
  const { user } = useAuth();

  const CpuChipIcon = () => (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" className="h-8 w-8 text-green-600">
      <path d="M16.5 7.5h-9v9h9v-9z" />
      <path fillRule="evenodd" d="M8.25 2.25A.75.75 0 019 3v1.5h2.25V3a.75.75 0 011.5 0v1.5H15V3a.75.75 0 011.5 0v1.5h1.5A2.25 2.25 0 0120.25 6.75v1.5H21a.75.75 0 010 1.5h-.75v2.25H21a.75.75 0 010 1.5h-.75v2.25H21a.75.75 0 010 1.5h-.75v1.5a2.25 2.25 0 01-2.25 2.25h-1.5V21a.75.75 0 01-1.5 0v-.75h-2.25V21a.75.75 0 01-1.5 0v-.75H9V21a.75.75 0 01-1.5 0v-.75h-1.5a2.25 2.25 0 01-2.25-2.25v-1.5H3a.75.75 0 010-1.5h.75v-2.25H3a.75.75 0 010-1.5h.75v-2.25H3a.75.75 0 010-1.5h.75v-1.5A2.25 2.25 0 016 4.5h1.5V3a.75.75 0 01.75-.75zM6 6v12a.75.75 0 00.75.75h10.5A.75.75 0 0018 18V6a.75.75 0 00-.75-.75H6.75A.75.75 0 006 6z" clipRule="evenodd" />
    </svg>
  );
  
  const ChartBarIcon = () => (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" className="h-8 w-8 text-green-600">
      <path d="M18.375 2.25c-1.035 0-1.875.84-1.875 1.875v15.75c0 1.035.84 1.875 1.875 1.875h.75c1.035 0 1.875-.84 1.875-1.875V4.125c0-1.036-.84-1.875-1.875-1.875h-.75zM9.75 8.625c0-1.036.84-1.875 1.875-1.875h.75c1.036 0 1.875.84 1.875 1.875v11.25c0 1.035-.84 1.875-1.875 1.875h-.75a1.875 1.875 0 01-1.875-1.875V8.625zM3 13.125c0-1.036.84-1.875 1.875-1.875h.75c1.036 0 1.875.84 1.875 1.875v6.75c0 1.035-.84 1.875-1.875 1.875h-.75A1.875 1.875 0 013 19.875v-6.75z" />
    </svg>
  );

  return (
    <div className="flex min-h-screen flex-col bg-gradient-to-b from-gray-50 to-white dark:from-gray-950 dark:to-black">
      <Header />

      <main className="flex-grow">
        {/* Hero Section */}
        <section className="flex flex-col items-center justify-center px-6 pt-24 pb-32 sm:pt-32">
          <div className="mx-auto max-w-4xl text-center">
            
            {/* Secure Globe Image with Badge */}
            <div className="mb-8 flex flex-col items-center justify-center gap-4">
              <div className="relative">
                {/* Secure Globe Image */}
                <Image 
                  src="/secure-earth.png"
                  alt="Secure Global Authentication"
                  width={192}
                  height={192}
                  className="h-48 w-48 rounded-full object-cover sm:h-56 sm:w-56"
                />
              </div>
              <span className="text-base font-semibold text-gray-500 dark:text-gray-400">
                application and security
              </span>
            </div>

            {/* Hero Title */}
            <h1 className="mb-6 text-5xl font-bold tracking-tight text-gray-900 dark:text-white sm:text-6xl lg:text-7xl">
              Premium auth template
              <span className="block bg-gradient-to-r from-green-600 to-emerald-600 bg-clip-text text-transparent">
                you can trust
              </span>
            </h1>

            {/* Hero Description */}
            <p className="mx-auto mb-10 max-w-2xl text-lg leading-relaxed text-gray-600 dark:text-gray-300 sm:text-xl">
              An automated and expert-led foundation for authentication. Log in, sign up, 
              and view protected routes in minutes, not months.
            </p>

            {/* CTA Buttons */}
            <div className="flex flex-col items-center justify-center gap-4 sm:flex-row sm:gap-6">
              {user ? (
                <Link
                  href="/dashboard"
                  className="group inline-flex items-center gap-2 rounded-xl bg-green-600 px-8 py-4 text-base font-semibold text-white shadow-lg transition-all hover:bg-green-700 hover:shadow-xl focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-green-600"
                >
                  Go to Dashboard
                  <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={2.5} stroke="currentColor" className="h-5 w-5 transition-transform group-hover:translate-x-1">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
                  </svg>
                </Link>
              ) : (
                <>
                  <Link
                    href="/signup"
                    className="group inline-flex items-center gap-2 rounded-xl bg-green-600 px-8 py-4 text-base font-semibold text-white shadow-lg transition-all hover:bg-green-700 hover:shadow-xl focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-green-600"
                  >
                    Get started
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={2.5} stroke="currentColor" className="h-5 w-5 transition-transform group-hover:translate-x-1">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
                    </svg>
                  </Link>
                  <Link
                    href="/login"
                    className="group inline-flex items-center gap-2 rounded-xl border-2 border-gray-300 bg-white px-8 py-4 text-base font-semibold text-gray-900 transition-all hover:border-gray-400 hover:bg-gray-50 dark:border-gray-700 dark:bg-gray-900 dark:text-white dark:hover:border-gray-600 dark:hover:bg-gray-800"
                  >
                    Sign in
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={2.5} stroke="currentColor" className="h-5 w-5 transition-transform group-hover:translate-x-1">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
                    </svg>
                  </Link>
                </>
              )}
            </div>
          </div>
        </section>

        {/* Features Section */}
        <section className="bg-white py-24 dark:bg-black sm:py-32">
          <div className="mx-auto max-w-7xl px-6">
            
            {/* Section Header */}
            <div className="mb-16 text-center">
              <h2 className="mb-4 text-3xl font-bold text-gray-900 dark:text-white sm:text-4xl">
                All-in-one authentication engine
              </h2>
              <p className="mx-auto max-w-2xl text-lg text-gray-600 dark:text-gray-300">
                Everything you need to build secure, scalable authentication systems
              </p>
            </div>

            {/* Feature Cards */}
            <div className="grid grid-cols-1 gap-8 md:grid-cols-3">
              
              {/* Feature 1 */}
              <div className="group rounded-2xl border border-gray-200 bg-white p-8 shadow-sm transition-all hover:shadow-lg dark:border-gray-800 dark:bg-gray-900">
                <div className="mb-4 inline-flex rounded-xl bg-green-50 p-3 dark:bg-green-950">
                  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" className="h-8 w-8 text-green-600">
                    <path fillRule="evenodd" d="M12.516 2.17a.75.75 0 00-1.032 0 11.209 11.209 0 01-7.877 3.08.75.75 0 00-.722.515A12.74 12.74 0 002.25 9.75c0 5.942 4.064 10.933 9.563 12.348a.749.749 0 00.374 0c5.499-1.415 9.563-6.406 9.563-12.348 0-1.39-.223-2.73-.635-3.985a.75.75 0 00-.722-.516l-.143.001c-2.996 0-5.717-1.17-7.734-3.08zm3.094 8.016a.75.75 0 10-1.22-.872l-3.236 4.53L9.53 12.22a.75.75 0 00-1.06 1.06l2.25 2.25a.75.75 0 001.14-.094l3.75-5.25z" clipRule="evenodd" />
                  </svg>
                </div>
                <h3 className="mb-3 text-xl font-semibold text-gray-900 dark:text-white">
                  Secure & Protected
                </h3>
                <p className="mb-4 text-gray-600 dark:text-gray-300">
                  Pre-built controls, policy templates, and login/signup flows.
                </p>
                <ul className="space-y-2 text-sm text-gray-700 dark:text-gray-200">
                  <li className="flex items-center gap-2">
                    <span className="text-green-600">✓</span>
                    Mapped to service criteria
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-green-600">✓</span>
                    Continuous control monitoring
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-green-600">✓</span>
                    Gap-to-control mapping
                  </li>
                </ul>
              </div>

              {/* Feature 2 */}
              <div className="group rounded-2xl border border-gray-200 bg-white p-8 shadow-sm transition-all hover:shadow-lg dark:border-gray-800 dark:bg-gray-900">
                <div className="mb-4 inline-flex rounded-xl bg-green-50 p-3 dark:bg-green-950">
                  <CpuChipIcon />
                </div>
                <h3 className="mb-3 text-xl font-semibold text-gray-900 dark:text-white">
                  API-first Automation
                </h3>
                <p className="mb-4 text-gray-600 dark:text-gray-300">
                  Connect cloud, identity, and code to collect and normalize data.
                </p>
                <ul className="space-y-2 text-sm text-gray-700 dark:text-gray-200">
                  <li className="flex items-center gap-2">
                    <span className="text-green-600">✓</span>
                    Your API, Auth0, etc.
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-green-600">✓</span>
                    Least-privilege connectors
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-green-600">✓</span>
                    Encrypted at rest and in transit
                  </li>
                </ul>
              </div>

              {/* Feature 3 */}
              <div className="group rounded-2xl border border-gray-200 bg-white p-8 shadow-sm transition-all hover:shadow-lg dark:border-gray-800 dark:bg-gray-900">
                <div className="mb-4 inline-flex rounded-xl bg-green-50 p-3 dark:bg-green-950">
                  <ChartBarIcon />
                </div>
                <h3 className="mb-3 text-xl font-semibold text-gray-900 dark:text-white">
                  Dashboard-ready Reports
                </h3>
                <p className="mb-4 text-gray-600 dark:text-gray-300">
                  Board-grade data with clear status and residual risk summaries.
                </p>
                <ul className="space-y-2 text-sm text-gray-700 dark:text-gray-200">
                  <li className="flex items-center gap-2">
                    <span className="text-green-600">✓</span>
                    Coverage, gaps, remediation
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-green-600">✓</span>
                    Share securely with dashboard
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-green-600">✓</span>
                    Attestation-ready output
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-200 bg-white dark:border-gray-800 dark:bg-black">
        <div className="mx-auto max-w-7xl px-6 py-12">
          <p className="text-center text-sm text-gray-500 dark:text-gray-400">
            &copy; 2025 Your Company, Inc. All rights reserved.
          </p>
        </div>
      </footer>
    </div>
  );
}