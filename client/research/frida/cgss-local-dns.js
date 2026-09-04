'use strict';

(() => {

// Research-only environment shim for the exact CGSS app process.
// It changes DNS resolution only for the two preservation endpoints so the
// existing UID-scoped 127.0.0.1:443 -> :8445 redirect can reach the local TLS mux.
// No request/response payload, protocol field, result code, or parser behavior is modified.

const TARGETS = new Set([
  'apis.game.starlight-stage.jp',
  'storages.game.starlight-stage.jp',
]);

const LOOPBACK = Memory.allocUtf8String('127.0.0.1');

function emit(event, fields) {
  send(Object.assign({
    schema: 1,
    event: event,
    thread_id: Process.getCurrentThreadId(),
  }, fields || {}));
}

function install() {
  let libc;
  let getaddrinfo;
  try {
    libc = Process.getModuleByName('libc.so');
    getaddrinfo = libc.getExportByName('getaddrinfo');
  } catch (error) {
    emit('local_dns_error', { message: String(error) });
    return;
  }

  Interceptor.attach(getaddrinfo, {
    onEnter(args) {
      let host = null;
      try {
        if (!args[0].isNull()) host = args[0].readUtf8String();
      } catch (_) {}
      if (!host || !TARGETS.has(host.toLowerCase())) return;
      this.rewritten = true;
      this.originalHost = host.toLowerCase();
      args[0] = LOOPBACK;
      emit('local_dns_rewrite', {
        host: this.originalHost,
        replacement: '127.0.0.1',
      });
    },
    onLeave(retval) {
      if (!this.rewritten) return;
      emit('local_dns_result', {
        host: this.originalHost,
        result: retval.toInt32(),
      });
    },
  });

  emit('local_dns_ready', { target_count: TARGETS.size });
}

setImmediate(install);
})();
