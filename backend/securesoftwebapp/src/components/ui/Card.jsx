import React from 'react';

export default React.forwardRef(function Card({ children, className = '', ariaLabel }, ref) {
    return (
        <div ref={ref} role={ariaLabel ? 'region' : undefined} aria-label={ariaLabel} className={`bg-white rounded-lg shadow p-4 ${className}`}>
            {children}
        </div>
    );
});
