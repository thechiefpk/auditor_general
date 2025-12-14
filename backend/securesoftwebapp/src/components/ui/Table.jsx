import React from 'react';

export default function Table({ children, className = '' }){
 return (
 <div className={`overflow-auto rounded-md border ${className}`}>
 <table className="w-full table-auto border-collapse">{children}</table>
 </div>
 );
}
