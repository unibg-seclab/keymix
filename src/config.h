#ifndef CONFIG_H
#define CONFIG_H

// Set global log level
#define LOG_LEVEL LOG_INFO

// Use if you want to disable logging altogether, will remove code if compiled
// with optimizations, only setting the log level doesn't remove the function
// call.
// Useful for testing.
#define DISABLE_LOG 0

// Use to enable debug-time checks (e.g., some assertions)
#define DEBUG 0

#endif // CONFIG_H
