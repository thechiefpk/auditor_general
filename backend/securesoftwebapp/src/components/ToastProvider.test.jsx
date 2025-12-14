import React from 'react';
import { render, screen, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ToastProvider, { useToast } from './ToastProvider';

function Trigger() {
    const { push } = useToast();
    return <button onClick={() => push('hello', 'success')}>Trigger</button>;
}

describe('ToastProvider', () => {
    test('push shows toast', async () => {
        const user = userEvent.setup();
        render(<ToastProvider><Trigger /></ToastProvider>);
        const btn = screen.getByRole('button', { name: /trigger/i });
        await user.click(btn);
        // wait for toast to appear
        const t = await screen.findByText(/hello/i);
        expect(t).toBeInTheDocument();
        // toasts auto-remove after6s; advance timers if needed (not used here)
    });
});
