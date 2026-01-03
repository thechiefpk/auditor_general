'use client';

import React from 'react';

interface SecurityMeterProps {
  score: number;
}

export default function SecurityMeter({ score }: SecurityMeterProps) {
  // Map score to percentage and color
  const getScoreDetails = (s: number) => {
    if (s >= 90) return { percent: s, color: '#10B981', label: 'Excellent' }; // Emerald-500
    if (s >= 80) return { percent: s, color: '#34D399', label: 'Good' }; // Emerald-400
    if (s >= 60) return { percent: s, color: '#FBBF24', label: 'Fair' }; // Amber-400
    if (s >= 40) return { percent: s, color: '#F87171', label: 'Poor' }; // Red-400
    return { percent: s, color: '#EF4444', label: 'Critical' }; // Red-500
  };

  const { percent, color, label } = getScoreDetails(score);
  
  // Calculate needle rotation (-90deg to 90deg)
  // 0% -> -90deg, 100% -> 90deg
  const rotation = (percent / 100) * 180 - 90;

  return (
    <div className="flex flex-col items-center justify-center p-4 bg-zinc-900/50 rounded-xl border border-zinc-800">
      <div className="relative w-48 h-24 overflow-hidden">
        {/* Gauge Background */}
        <div className="absolute top-0 left-0 w-48 h-48 rounded-full border-[12px] border-zinc-700 box-border" style={{ clipPath: 'polygon(0 0, 100% 0, 100% 50%, 0 50%)' }}></div>
        
        {/* Active Arc (Simple CSS hack or SVG is better, let's use SVG for precision) */}
        <svg viewBox="0 0 100 50" className="absolute top-0 left-0 w-full h-full">
            <path d="M 10 50 A 40 40 0 0 1 90 50" fill="none" stroke="#3f3f46" strokeWidth="10" />
            <path 
                d="M 10 50 A 40 40 0 0 1 90 50" 
                fill="none" 
                stroke={color} 
                strokeWidth="10" 
                strokeDasharray="126" // approx length of arc
                strokeDashoffset={126 - (126 * percent / 100)}
                className="transition-all duration-1000 ease-out"
            />
        </svg>

        {/* Needle */}
        <div 
            className="absolute bottom-0 left-1/2 w-1 h-20 bg-white origin-bottom transition-transform duration-1000 ease-out"
            style={{ 
                transform: `translateX(-50%) rotate(${rotation}deg)`,
                height: '40px',
                bottom: '0px'
            }}
        >
             <div className="w-3 h-3 bg-white rounded-full absolute -bottom-1.5 -left-1"></div>
        </div>
      </div>
      
      <div className="mt-4 text-center">
        <div className="text-3xl font-bold" style={{ color }}>{score}</div>
        <div className="text-zinc-400 text-sm uppercase tracking-wider font-medium">{label}</div>
      </div>
    </div>
  );
}
