socket.on('error', (err: Error | NodeJS.ErrnoException) => {
  if (err.message.includes('ECONNREFUSED')) {
    resolve('Port is closed');
  } else {
    // ... existing code ...
  }
}); 