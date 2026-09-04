'use strict';

const BASELINE = {
  module: 'libil2cpp.so',
  libil2cppSha256: '2d950f3bab72c73adef62a3e312c64e4e42ae0287cb2454cdec008eb9ed699c5',
  points: [
    ['network.prepare_headers', 0x050c9f90],
    ['network.prepare_post_data', 0x050cae4c],
    ['network.create_body', 0x050cb93c],
    ['network.add_header_session_id', 0x050ca1c8],
    ['network.add_header_param', 0x050ca264],
    ['network.add_header_version', 0x050ca64c],
    ['crypto.encrypt_rj256', 0x050c1c9c],
    ['crypto.decrypt_rj256', 0x050c2438],
    ['boot.version_check_exec', 0x050bde1c],
    ['boot.version_check_set_parameter', 0x050bf6b8],
    ['boot.setup_network_certification', 0x050c7208],
    ['load.parse', 0x04850a94],
  ],
};

let installed = false;
let timer = null;

function emit(event, fields) {
  send(Object.assign({
    schema: 1,
    event: event,
    monotonic_ms: Math.floor(Process.getCurrentThreadId() >= 0 ? Date.now() : Date.now()),
  }, fields || {}));
}

function installPoint(module, id, rva) {
  const address = module.base.add(rva);
  Interceptor.attach(address, {
    onEnter(args) {
      this.reliveThreadId = Process.getCurrentThreadId();
      emit('enter', {
        id: id,
        rva: '0x' + rva.toString(16),
        address: address.toString(),
        thread_id: this.reliveThreadId,
      });
    },
    onLeave(retval) {
      emit('leave', {
        id: id,
        rva: '0x' + rva.toString(16),
        address: address.toString(),
        thread_id: this.reliveThreadId,
      });
    },
  });
}

function tryInstall() {
  if (installed) {
    return;
  }

  const module = Process.findModuleByName(BASELINE.module);
  if (module === null) {
    return;
  }

  installed = true;
  if (timer !== null) {
    clearInterval(timer);
    timer = null;
  }

  emit('module', {
    module: module.name,
    base: module.base.toString(),
    size: module.size,
    expected_sha256: BASELINE.libil2cppSha256,
    note: 'The Frida runtime cannot hash the loaded module here; verify the baseline before launch.',
  });

  BASELINE.points.forEach(function (point) {
    installPoint(module, point[0], point[1]);
  });

  emit('ready', {
    point_count: BASELINE.points.length,
  });
}

tryInstall();
if (!installed) {
  timer = setInterval(tryInstall, 250);
}
