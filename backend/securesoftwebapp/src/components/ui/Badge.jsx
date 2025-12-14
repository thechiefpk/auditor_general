import React from 'react';

export default function Badge({ children, color = 'indigo', className = '' }){
 const colors = {
 indigo: 'bg-indigo-100 text-indigo-800',
 green: 'bg-green-100 text-green-800',
 red: 'bg-red-100 text-red-800',
 yellow: 'bg-yellow-100 text-yellow-800'
 };
 return <span className={`inline-block px-2 py-1 text-xs rounded ${colors[color] || colors.indigo} ${className}`}>{children}</span>;
}
