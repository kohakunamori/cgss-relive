'use strict';

// Read-only runtime discovery probe for the exact frozen CGSS Android 11.6.3
// arm64 specimen. This is not the production localization delivery mechanism.
// Static anchor: UnityEngine.UI.Text.set_text @ libil2cpp.so + 0x7dc036c.

const SET_TEXT_RVA = 0x7dc036c;
const MAX_STRING_LENGTH = 16384;
const seen = new Set();
let installed = false;

function readIl2CppString(value) {
    if (value.isNull()) {
        return null;
    }

    // arm64 Il2CppString:
    //   +0x00 Il2CppClass*
    //   +0x08 monitor*
    //   +0x10 int32 length
    //   +0x14 UTF-16 chars[]
    const length = value.add(0x10).readS32();
    if (length < 0 || length > MAX_STRING_LENGTH) {
        return null;
    }
    return value.add(0x14).readUtf16String(length);
}

function installProbe() {
    if (installed) {
        return true;
    }

    const module = Process.findModuleByName('libil2cpp.so');
    if (module === null) {
        return false;
    }

    const target = module.base.add(SET_TEXT_RVA);
    console.log(
        '[cgss-localization] probing UnityEngine.UI.Text.set_text at ' + target
    );

    Interceptor.attach(target, {
        onEnter(args) {
            let text;
            try {
                // IL2CPP instance call on arm64: x0=this, x1=System.String* value.
                text = readIl2CppString(args[1]);
            } catch (error) {
                send({
                    kind: 'cgss-localization-probe-error',
                    error: String(error),
                });
                return;
            }

            if (text === null || text.length === 0 || seen.has(text)) {
                return;
            }
            seen.add(text);
            send({
                kind: 'cgss-ui-text',
                text: text,
                instance: args[0].toString(),
            });
        },
    });

    installed = true;
    return true;
}

if (!installProbe()) {
    const timer = setInterval(function () {
        if (installProbe()) {
            clearInterval(timer);
        }
    }, 100);
}
