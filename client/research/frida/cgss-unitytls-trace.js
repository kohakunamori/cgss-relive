'use strict';

(() => {
  const SPEC = {
    module: 'libunity.so',
    sha256: 'b6ec9b930e48898d0b3dd292e8d1468c94d825058f2253f9980f6e5d559ac257',
    defaultDispatchRva: 0x00bb0d98,
    explicitVerifyReturnRva: 0x00bb5b9c,
    defaultVerifyReturnRva: 0x0166c790,
    verifyFailureRva: 0x0166c2ec,
  };

  function emit(event, fields) {
    send(Object.assign({
      schema: 1,
      event,
      source: 'unitytls-trace',
      thread_id: Process.getCurrentThreadId(),
    }, fields || {}));
  }

  function u32(value) {
    try { return value.toUInt32(); } catch (_) { return null; }
  }

  function install(module) {
    const base = module.base;
    emit('unitytls_instrumentation_ready', {
      module: module.name,
      module_base: base.toString(),
      module_size: module.size,
      expected_file_sha256: SPEC.sha256,
    });

    Interceptor.attach(base.add(SPEC.defaultDispatchRva), {
      onEnter() {
        emit('unitytls_default_ca_path', {
          rva: '0x' + SPEC.defaultDispatchRva.toString(16),
        });
      },
    });

    Interceptor.attach(base.add(SPEC.explicitVerifyReturnRva), {
      onEnter() {
        emit('unitytls_explicit_verify_return', {
          rva: '0x' + SPEC.explicitVerifyReturnRva.toString(16),
          result_u32: u32(this.context.x0),
        });
      },
    });

    Interceptor.attach(base.add(SPEC.defaultVerifyReturnRva), {
      onEnter() {
        emit('unitytls_default_verify_return', {
          rva: '0x' + SPEC.defaultVerifyReturnRva.toString(16),
          result_u32: u32(this.context.x0),
        });
      },
    });

    Interceptor.attach(base.add(SPEC.verifyFailureRva), {
      onEnter() {
        emit('unitytls_verify_failure_path', {
          rva: '0x' + SPEC.verifyFailureRva.toString(16),
          verify_mask_u32: u32(this.context.x22),
        });
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
