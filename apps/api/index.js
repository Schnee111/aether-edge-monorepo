export function createApp() { return { get: (path, handler) => ({ path, status: 200 }) }; }
