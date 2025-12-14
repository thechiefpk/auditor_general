export function LoadingSkeleton() {
  return (
    <div className="animate-pulse space-y-4">
      <div className="h-4 bg-slate-800 rounded w-3/4"></div>
      <div className="h-4 bg-slate-800 rounded w-1/2"></div>
      <div className="h-4 bg-slate-800 rounded w-5/6"></div>
    </div>
  );
}

export function CardSkeleton() {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg animate-pulse">
      <div className="h-8 bg-slate-800 rounded w-1/4 mb-4"></div>
      <div className="space-y-3">
        <div className="h-4 bg-slate-800 rounded"></div>
        <div className="h-4 bg-slate-800 rounded w-5/6"></div>
      </div>
    </div>
  );
}

export function TableSkeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="h-12 bg-slate-800 rounded animate-pulse"></div>
      ))}
    </div>
  );
}
