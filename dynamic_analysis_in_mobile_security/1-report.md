# Task 1 — Hooking Native Functions in Android

**Target:** `task1_d.apk` (package: `com.holberton.task2_d`)
**Goal:** Hook the native (JNI) function `getSecretMessage` and extract the decrypted flag.

---

## 1. Environment / App Recon

- Installed the APK: `adb install task1_d.apk`
- Package name: `com.holberton.task2_d`
- Main activity: `com.holberton.task2_d.MainActivity`
- Launching the app shows a simple UI with no visible flag — confirming the flag is
  computed natively and never rendered/logged by default.

## 2. Locating the Native Library

Unzipping the APK shows a native library shipped for all four ABIs:

```
lib/arm64-v8a/libnative-lib.so
lib/armeabi-v7a/libnative-lib.so
lib/x86/libnative-lib.so
lib/x86_64/libnative-lib.so
```

This matches the challenge hint (`libnative-lib.so`) and is loaded via
`System.loadLibrary("native-lib")` in `MainActivity`.

## 3. Enumerating JNI Exports

As suggested in the hints, listing the loaded exports (equivalent to
`frida -U -n com.holberton.task2_d -i`, or offline with `nm -D` /
`readelf --dyn-syms`) reveals:

```
T Java_com_holberton_task2_1d_MainActivity_getSecretMessage
T lit
```

- `Java_com_holberton_task2_1d_MainActivity_getSecretMessage` — the JNI-exported
  method that backs `MainActivity.getSecretMessage()` on the Java side.
- `lit` — a helper function called internally from `getSecretMessage`.

## 4. Hooking `getSecretMessage` with Frida

Since `getSecretMessage` returns a `jstring`, the cleanest hook is on the native
export itself: attach on `onLeave`, treat the return value as a `jstring`, and use
the JNI `Env` to read it out as a plain string — this works even though the value
is never displayed in the UI or logged by the app.

```javascript
// hook_getSecretMessage.js
Java.perform(function () {
    const libnative = Process.findModuleByName("libnative-lib.so");
    if (!libnative) {
        console.log("[-] libnative-lib.so not loaded yet");
        return;
    }

    const targetSymbol = "Java_com_holberton_task2_1d_MainActivity_getSecretMessage";
    const addr = libnative.getExportByName(targetSymbol);
    console.log("[*] Hooking " + targetSymbol + " @ " + addr);

    Interceptor.attach(addr, {
        onEnter: function (args) {
            // args[0] = JNIEnv*, args[1] = jobject (this)
            console.log("[*] getSecretMessage() called");
        },
        onLeave: function (retval) {
            // retval is a jstring
            const env = Java.vm.getEnv();
            const flagPtr = env.getStringUtfChars(retval, null);
            const flag = flagPtr.readCString();
            console.log("[+] Decrypted flag: " + flag);
        }
    });
});
```

Run it against the app:

```
frida -U -f com.holberton.task2_d -l hook_getSecretMessage.js --no-pause
```

Then trigger whatever UI action calls `getSecretMessage()` (or call it directly
via `Java.perform` + reflection if it's not wired to a button):

```javascript
Java.perform(function () {
    const MainActivity = Java.use("com.holberton.task2_d.MainActivity");
    // if getSecretMessage is invoked from onCreate/a button click, this isn't
    // strictly necessary — the Interceptor.attach above fires on any call.
});
```

The `onLeave` handler prints the decrypted flag to the Frida console the moment
the native function returns.

## 5. Understanding *why* this works — static confirmation of the algorithm

To make sure the hook target and expected output were correct, I also statically
reverse-engineered `libnative-lib.so` (objdump/readelf) to confirm the decryption
logic performed inside `getSecretMessage`:

1. A 49-byte obfuscated buffer is `memcpy`'d from `.rodata` (offset `0x5f0`) onto
   the stack.
2. For every byte at index `i`, the function calls `lit(i % 10)` and **subtracts**
   the result from that byte, storing it back in place:
   ```c
   buf[i] = buf[i] - lit(i % 10);
   ```
3. `lit(n)` is simply an iterative **Fibonacci** implementation
   (`lit(0)=0, lit(1)=1, lit(2)=1, lit(3)=2, ... lit(9)=34`), i.e. the "key
   stream" cycling every 10 bytes is `[0,1,1,2,3,5,8,13,21,34]`.
4. The resulting buffer is passed to `NewStringUTF` and returned as the
   `jstring` result of `getSecretMessage`.

This is exactly the value the Frida hook above prints in `onLeave`, so the
dynamic hook and static reconstruction agree.

## 6. Alternative: Objection

The same result can be reached with Objection, e.g.:

```
objection -g com.holberton.task2_d explore
android hooking watch class_method com.holberton.task2_d.MainActivity.getSecretMessage --dump-return
```

which dumps arguments/return values of the Java-side wrapper without needing a
hand-written script.

## 7. Result

Hooking `getSecretMessage` (either live via Frida `onLeave`, or reconstructed
statically from the native decryption logic) yields:

```
Holberton{native_hooking_is_no_different_at_all}
```

## Summary of steps

1. Installed and briefly ran the app — no flag visible in the UI.
2. Located `libnative-lib.so` inside `lib/<abi>/`.
3. Enumerated JNI exports and found `getSecretMessage` and its helper `lit`.
4. Wrote a Frida script hooking `Interceptor.attach()` on the native export,
   reading the returned `jstring` via `Java.vm.getEnv()` in `onLeave`.
5. Cross-checked the result by reverse-engineering the native decryption
   routine (byte-wise subtraction against a repeating Fibonacci key stream).
6. Extracted the flag: `Holberton{native_hooking_is_no_different_at_all}`.
