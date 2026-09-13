# Android Security Challenge — Revealing Hidden Functions — Report

**Target:** `task3_d.apk`
**Package:** `com.holberton.task4_d`
**Tools used:** `jadx` (static decompilation), Python (reimplementing the hidden transform)

## 1. Decompiling the APK

The APK was decompiled with jadx to recover readable Java/Kotlin source:

```
jadx -d decompiled task3_d.apk
```

The `AndroidManifest.xml` gave the package name `com.holberton.task4_d`. The
app-specific sources live under `sources/com/holberton/task4_d/`:

- `MainActivity.java`
- `MainActivity$retrieveEncryptedData$1.java`
- `MainActivityKt.java`
- `ui/theme/*`

## 2. Identifying the Hidden Function

`MainActivity.java` defines a `decodedFlag` state property that is
initialized to an **empty string** and is displayed by the `Greeting`
composable, but nothing in `onCreate()` ever populates it — `setDecodedFlag`
is declared but never invoked from the visible control flow.
`retrieveEncryptedData()` is also defined on `MainActivity` but is likewise
never called from `onCreate()`; when called it would just invoke an
`onComplete` callback and do no decoding itself — a decoy.

The actual payload sits in `MainActivityKt.java`, in a `private static final`
top-level function with a deliberately camouflaged name that mimics a
Base64/alphabet constant so it doesn't stand out under a quick manual review
or a naive string search:

```kotlin
private static final void aBcDeFgHiJkLmNoPqRsTuVwXyZ123456(Function1<? super String, Unit> function1)
```

A `grep` across the whole decompiled source tree confirmed this function has
**exactly one occurrence — its own definition** — meaning it is never
referenced or invoked anywhere in the app's reachable code paths, matching
the challenge's description of a function that is "not called during the
app's normal execution."

In a full dynamic-analysis setup this is exactly the kind of function you'd
target with Frida:

```javascript
Java.perform(function () {
    var MainActivityKt = Java.use('com.holberton.task4_d.MainActivityKt');
    MainActivityKt.aBcDeFgHiJkLmNoPqRsTuVwXyZ123456.implementation = function (callback) {
        console.log('[*] Hidden function invoked');
        return this.aBcDeFgHiJkLmNoPqRsTuVwXyZ123456(callback);
    };
    // or invoke it directly:
    MainActivityKt.aBcDeFgHiJkLmNoPqRsTuVwXyZ123456(
        Java.use('kotlin.jvm.functions.Function1').$new(...)  // supply a sink for the result
    );
});
```

(Objection's `android hooking watch class_method` /
`android heap execute` workflow would achieve the same result interactively.)

Because the function's entire behavior is a **pure, deterministic
transformation of a hardcoded string literal with no dependency on device,
user, or runtime state**, hooking it at runtime and reimplementing its byte
transformation statically produce identical output — so the logic below was
verified both by tracing the decompiled bytecode and by re-executing the
same arithmetic in Python.

## 3. Understanding the Encoding Mechanism

```kotlin
private static final void aBcDeFgHiJkLmNoPqRsTuVwXyZ123456(Function1<? super String, Unit> function1) {
    byte[] decodedBytes = Base64.decode(
        "8CP4zSyn62t78lwwc383rxcgtv/UiMv3Pw+Mfw12LzXvorIpBypNK/oB7XvWNV0oWfoX", 0)
    for ((index, byteVal) in decodedBytes.withIndex()) {
        val value  = byteVal.toInt() and 0xFF
        val temp   = value xor 19
        val shifted = ((temp shr 2) or (temp shl 6)) and 255
        var temp2  = (shifted - index * 3) % 256
        if (temp2 < 0) temp2 += 256
        val charCode = (temp2 * 183) % 256
        flagChars.add(charCode.toChar())
    }
    function1.invoke(flagChars.joinToString(""))
}
```

Per-byte pipeline (index `i`, starting at 0):

1. Base64-decode the hardcoded string → raw bytes.
2. Treat each byte as unsigned (`& 0xFF`).
3. XOR with constant key byte `19`.
4. Rotate-left-ish mix: `((temp >> 2) | (temp << 6)) & 0xFF` — an 8-bit
   rotate-right by 2 bits (equivalently rotate-left by 6), masked back to a
   byte.
5. Subtract `index * 3` (a position-dependent offset) and reduce mod 256,
   normalizing negative results back into `[0, 255]`.
6. Multiply by `183` and reduce mod 256 — `183` is coprime with `256`
   (`gcd(183,256)=1`), so this step is an invertible affine "multiplicative
   XOR-style" mixing that maps distinct byte values to distinct outputs.
7. Cast the resulting byte to a `char` and append it to the output string.

This is a custom, non-standard multi-stage cipher (XOR → bit rotate →
position-dependent subtraction → modular multiplication) rather than a
textbook algorithm like AES/RSA — its security relies entirely on the logic
being hidden/unreachable, which is defeated once the function is located and
either invoked via Frida or its arithmetic is reimplemented outside the app.

## 4. Reversing the Encoding / Retrieving the Flag

Reimplemented in Python, replicating Java's integer/modulo semantics exactly
(cross-checked with an explicit Java-style `%`, which differs from Python's
`%` in sign handling for negative operands):

```python
import base64

encoded = "8CP4zSyn62t78lwwc383rxcgtv/UiMv3Pw+Mfw12LzXvorIpBypNK/oB7XvWNV0oWfoX"
decoded_bytes = base64.b64decode(encoded)

flag_chars = []
for index, b in enumerate(decoded_bytes):
    value = b & 0xFF
    temp = value ^ 19
    shifted = ((temp >> 2) | (temp << 6)) & 255
    temp2 = (shifted - index * 3) % 256
    if temp2 < 0:
        temp2 += 256
    char_code = (temp2 * 183) % 256
    flag_chars.append(chr(char_code))

flag = "".join(flag_chars)
print(flag)
```

**Output:**

```
Holberton{calling_uncalled_functions_is_now_known!}
```

The result was verified twice — once using Python's native `%` (which
already returns a non-negative result for a positive modulus, matching the
compensated Java behavior) and once using an explicit Java-style modulo
helper that preserves sign-of-dividend semantics before the compensation
step — both produced an identical, readable flag string, giving high
confidence the transform was reproduced correctly.

## 5. Challenges Faced

- The dead/unused `retrieveEncryptedData()` and `decodedFlag` state on
  `MainActivity` were a deliberate decoy — they look like the natural place
  to find flag-retrieval logic but do no actual decoding, so following them
  alone would be a dead end without also grepping the full class for other
  unreferenced private functions.
- The real hidden function's name (`aBcDeFgHiJkLmNoPqRsTuVwXyZ123456`) is
  designed to visually resemble a Base64 alphabet constant, making it easy to
  skim past during manual code review; a systematic search for
  **unreferenced private/top-level functions** (rather than just reading
  top-to-bottom) was what surfaced it.
- The custom bit-rotate + position-dependent modular arithmetic isn't a
  named standard cipher, so it had to be transcribed instruction-by-instruction
  from the decompiled bytecode rather than recognized and short-circuited;
  getting Java's negative-modulo behavior exactly right mattered for
  correctness and was independently verified with a second implementation.

## 6. Flag

```
Holberton{calling_uncalled_functions_is_now_known!}
```
