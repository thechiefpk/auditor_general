import { useState, useEffect, useCallback } from 'react';

// useFetch accepts an async function that returns data. deps is dependency array for re-run.
export default function useFetch(fn, deps = []) {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    const execute = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const res = await fn();
            setData(res);
            setLoading(false);
            return res;
        } catch (err) {
            setError(err);
            setLoading(false);
            throw err;
        }
    }, deps); // eslint-disable-line react-hooks/exhaustive-deps

    useEffect(() => {
        execute();
    }, [execute]);

    return { data, loading, error, reload: execute };
}
