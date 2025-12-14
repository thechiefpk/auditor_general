import React from 'react';

const Button = React.forwardRef(function Button({ children, variant = 'primary', className = '', size = 'md', type = 'button', ...props }, ref) {
    const base = 'inline-flex items-center gap-2 rounded-md font-medium focus:outline-none focus:ring-2 focus:ring-offset-2 justify-center';
    const sizes = {
        sm: 'px-2 py-1 text-sm',
        md: 'px-4 py-2 text-sm',
        lg: 'px-6 py-3 text-base',
    };
    const variants = {
        primary: 'bg-indigo-600 text-white hover:bg-indigo-700 focus:ring-indigo-500',
        secondary: 'bg-white text-gray-700 border hover:bg-gray-50 focus:ring-indigo-500',
        ghost: 'bg-transparent text-gray-700 hover:bg-gray-100'
    };
    const disabled = props.disabled;
    const disabledCls = disabled ? 'opacity-50 cursor-not-allowed' : '';

    return (
        <button
            ref={ref}
            type={type}
            className={`${base} ${sizes[size] || sizes.md} ${variants[variant] || variants.primary} ${disabledCls} ${className}`}
            aria-disabled={disabled ? 'true' : 'false'}
            disabled={disabled}
            {...props}
        >
            {children}
        </button>
    );
});

export default Button;
