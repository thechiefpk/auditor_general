import './globals.css';
import { AuthProvider } from './context/AuthContext'; // This import is correct
import { Toaster } from 'react-hot-toast';

export const metadata = {
  title: 'Secure Soft',
  description: 'Secure Software',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode; // Add type for children
}) {
  return (
    <html lang="en">
      <body>
        <AuthProvider> {/* This is already set up! */}
          {children}
        </AuthProvider>
        <Toaster position="top-right" />
      </body>
    </html>
  );
}