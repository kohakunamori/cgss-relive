'use strict';

(() => {
  const NEEDLES = [
    'cacert',
    '/system/etc/security',
    '/apex/com.android.conscrypt',
    '.pem',
    '.crt',
  ];

  function interesting(path) {
    if (!path) return false;
    const lower = path.toLowerCase();
    return NEEDLES.some((needle) => lower.includes(needle));
  }

  function readPath(pointer) {
    try {
      if (pointer.isNull()) return null;
      return pointer.readUtf8String();
    } catch (_) {
      return null;
    }
  }

  let backtraceEmitted = false;

  function emit(api, path, context) {
    const record = {
      schema: 1,
      event: 'ca_store_file_access',
      source: 'ca-store-trace',
      api,
      path,
      thread_id: Process.getCurrentThreadId(),
    };
    if (!backtraceEmitted && path && path.includes('/apex/com.android.conscrypt/cacerts/')) {
      backtraceEmitted = true;
      try {
        record.backtrace = Thread.backtrace(context, Backtracer.ACCURATE)
          .slice(0, 16)
          .map(DebugSymbol.fromAddress)
          .map(String);
      } catch (_) {
        record.backtrace = [];
      }
    }
    send(record);
  }

  function attach(name, pathArgIndex) {
    let address = null;
    try {
      address = Module.getGlobalExportByName(name);
    } catch (_) {
      return;
    }
    Interceptor.attach(address, {
      onEnter(args) {
        const path = readPath(args[pathArgIndex]);
        if (interesting(path)) emit(name, path, this.context);
      },
    });
  }

  attach('open', 0);
  attach('open64', 0);
  attach('openat', 1);
  attach('fopen', 0);
  attach('fopen64', 0);

  send({
    schema: 1,
    event: 'ca_store_trace_ready',
    source: 'ca-store-trace',
    thread_id: Process.getCurrentThreadId(),
  });
})();
