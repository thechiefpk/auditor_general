export default function DashboardLoading() {
  return (
    <div className="flex h-screen items-center justify-center bg-slate-900">
      <div className="text-center">
        <div className="animate-spin h-16 w-16 border-4 border-blue-600 border-t-transparent rounded-full mx-auto mb-4"></div>
        <p className="text-slate-400 text-lg">Loading dashboard...</p>
      </div>
    </div>
  );
}
