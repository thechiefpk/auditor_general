import React from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Button from './Button';

describe('Button', () => {
    test('renders children and handles click', async () => {
        const user = userEvent.setup();
        const handle = vi.fn();
        render(<Button onClick={handle}>Click me</Button>);
        const btn = screen.getByRole('button', { name: /click me/i });
        expect(btn).toBeInTheDocument();
        await user.click(btn);
        expect(handle).toHaveBeenCalled();
    });
});
