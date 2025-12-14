import React from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { IoClose } from 'react-icons/io5';

export default function Modal({ open, onClose, title, children }) {
    return (
        <Dialog.Root open={open} onOpenChange={(v) => { if (!v) onClose(); }}>
            <Dialog.Portal>
                <Dialog.Overlay className="fixed inset-0 bg-black/40 backdrop-blur-sm" />
                <Dialog.Content className="fixed top-1/2 left-1/2 w-full max-w-2xl -translate-x-1/2 -translate-y-1/2 bg-white rounded p-4 shadow-lg animate-in fade-in-80">
                    <div className="flex justify-between items-center mb-2">
                        <Dialog.Title className="font-semibold">{title}</Dialog.Title>
                        <button onClick={onClose} className="text-gray-500" aria-label="Close modal"><IoClose /></button>
                    </div>
                    <div>
                        {children}
                    </div>
                    <Dialog.Close asChild>
                        <button className="sr-only">Close</button>
                    </Dialog.Close>
                </Dialog.Content>
            </Dialog.Portal>
        </Dialog.Root>
    )
}
