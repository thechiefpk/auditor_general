import React from 'react';

const Input = React.forwardRef(function Input({ className = '', invalid = false, ...props }, ref) {
    return (
        <input
            ref={ref}
            className={`w-full border rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-500 ${invalid ? 'border-red-500' : ''} ${className}`}
            aria-invalid={invalid ? 'true' : 'false'}
            {...props}
        />
    );
});

export default Input;
