import React from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Input from './Input';

describe('Input', () => {
    test('renders and updates value', async () => {
        const user = userEvent.setup();
        render(<Input placeholder="Enter" />);
        const input = screen.getByPlaceholderText(/enter/i);
        expect(input).toBeInTheDocument();
        await user.type(input, 'abc');
        expect(input).toHaveValue('abc');
    });
});
