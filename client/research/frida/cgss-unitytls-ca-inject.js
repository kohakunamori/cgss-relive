'use strict';

(() => {
  const SPEC = {
    module: 'libunity.so',
    expectedSha256: 'b6ec9b930e48898d0b3dd292e8d1468c94d825058f2253f9980f6e5d559ac257',
    defaultVerifyAppendPointRva: 0x00bb5b68,
    x509listAppendPemRva: 0x00bb1808,
  };

  function emit(event, fields) {
    send(Object.assign({
      schema: 1,
      event,
      source: 'unitytls-ca-inject',
      thread_id: Process.getCurrentThreadId(),
    }, fields || {}));
  }

  const pem = globalThis.CGSS_PRESERVATION_CA_PEM;
  if (typeof pem !== 'string' || !pem.includes('-----BEGIN CERTIFICATE-----')) {
    emit('unitytls_ca_inject_disabled', { reason: 'missing generated CA PEM prelude' });
    return;
  }

  const pemLength = pem.length;
  const pemBuffer = Memory.allocUtf8String(pem);
  const injectedLists = new Set();

  function install(module) {
    const base = module.base;
    const appendPem = new NativeFunction(
      base.add(SPEC.x509listAppendPemRva),
      'uint64',
      ['pointer', 'pointer', 'uint64', 'pointer']
    );

    emit('unitytls_ca_inject_ready', {
      module: module.name,
      module_base: base.toString(),
      expected_file_sha256: SPEC.expectedSha256,
      append_point_rva: '0x' + SPEC.defaultVerifyAppendPointRva.toString(16),
      append_pem_rva: '0x' + SPEC.x509listAppendPemRva.toString(16),
      pem_length: pemLength,
    });

    Interceptor.attach(base.add(SPEC.defaultVerifyAppendPointRva), {
      onEnter() {
        const list = this.context.x25;
        const errorState = this.context.x19;
        if (list.isNull() || errorState.isNull()) {
          emit('unitytls_ca_inject_skip', {
            reason: 'null list or error state',
            list: list.toString(),
            error_state: errorState.toString(),
          });
          return;
        }

        const key = list.toString();
        if (injectedLists.has(key)) {
          return;
        }

        let count = null;
        try {
          count = appendPem(list, pemBuffer, pemLength, errorState).toString();
          injectedLists.add(key);
          emit('unitytls_ca_inject_append', {
            list: key,
            error_state: errorState.toString(),
            appended_count: count,
          });
        } catch (error) {
          emit('unitytls_ca_inject_error', {
            list: key,
            error: String(error),
          });
        }
      },
    });
  }

  function waitForModule() {
    const module = Process.findModuleByName(SPEC.module);
    if (!module) {
      setTimeout(waitForModule, 50);
      return;
    }
    install(module);
  }

  setImmediate(waitForModule);
})();
