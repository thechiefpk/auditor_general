import React, { createContext, useContext, useState } from 'react';
import Toast from './ui/Toast';

const ToastContext = createContext(null);

export function useToast(){ return useContext(ToastContext); }

export default function ToastProvider({ children }){
 const [toasts, setToasts] = useState([]);
 const push = (msg, type='info')=>{
 const id = Date.now();
 setToasts(t=>[...t, { id, msg, type }]);
 setTimeout(()=> setToasts(t=>t.filter(x=>x.id!==id)),6000);
 };
 const remove = (id)=> setToasts(t=>t.filter(x=>x.id!==id));
 return (
 <ToastContext.Provider value={{ push }}>
 {children}
 <div className="fixed bottom-6 right-6 flex flex-col gap-2">
 {toasts.map(t=> <Toast key={t.id} message={t.msg} type={t.type} onClose={()=>remove(t.id)} />)}
 </div>
 </ToastContext.Provider>
 );
}
