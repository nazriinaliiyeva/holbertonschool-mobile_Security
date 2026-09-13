# Android Cryptography Challenge — Analysis Report

**Target:** `app-release-task2.apk`
**Package:** `com.holberton.task3`
**Tools used:** `jadx` (static decompilation), `java`/`python3` (reimplementing the crypto logic)

## 1. Environment Setup

The APK was copied into an isolated working directory. Rather than relying on a
live device/emulator + Burp/mitmproxy from the start, I first performed static
analysis to understand *what* the app actually does, since dynamic interception
is only useful once you know which network calls (if any) matter.

```
mkdir analysis && cp app-release-task2.apk analysis/
```

## 2. Decompiling the APK

`jadx` v1.5.0 was used to decompile the DEX bytecode back to readable Java:

```
jadx -d decompiled app-release-task2.apk
```

The `AndroidManifest.xml` confirmed the package name (`com.holberton.task3`),
and the app-specific sources were isolated under
`sources/com/holberton/task3/`:

- `MainActivity.java`
- `MainActivityKt.java`
- `MainActivityKt$FibonacciDecryptionScreen$1.java`
- `MainActivityKt$FibonacciDecryptionScreen$1$1$result$1.java`

## 3. Intercepting Traffic — Finding: No Live Server Call

Standard practice for this challenge type is to proxy the app's traffic
through Burp Suite / mitmproxy to capture the encrypted payload from the
server. However, static analysis of the decompiled Kotlin/Compose code showed
that **this particular build performs the "decryption" entirely on-device** —
there is no HTTP client, no `OkHttp`/`Retrofit`/`HttpURLConnection` usage, and
no network permission is exercised in the relevant code path. The encrypted
flag ships **hardcoded inside the APK** as a Base64 string, and the "server
round-trip" is simulated by a deliberately slow local computation.

This is confirmed by `MainActivityKt.FibonacciDecryptionScreen`, a Jetpack
Compose screen that:

1. Shows a placeholder message: *"performing heavy computation and decrypting
   the flag..."*
2. Launches a coroutine (`FibonacciDecryptionScreen$1` →
   `AnonymousClass1` → `$result$1`) on `Dispatchers.Default` that calls
   `performslowDecryption()`.
3. Sets the returned string as the on-screen message once the computation
   finishes.

So instead of intercepting/modifying an HTTP response, the "interception"
step for this variant of the challenge is: **extract the hardcoded
ciphertext and key-derivation logic from the decompiled bytecode.**

## 4. Cryptographic Analysis

The relevant logic lives in `MainActivityKt.java`:

```java
public static final String performslowDecryption() {
    byte[] decode = Base64.getDecoder().decode(
        "cVZaW1dDQllZTFdRW1xeUlBbX21CWFtHalRZXUJFRFhNX1ZcbllGQ15cUUNSRFpcVks=");
    return xorDecrypt(new String(decode, Charsets.UTF_8),
                       String.valueOf(slowRecursive(150)));
}

public static final long slowRecursive(int i) {
    return i <= 1 ? i : slowRecursive(i - 1) + slowRecursive(i - 2);
}

public static final String xorDecrypt(String encryptedFlag, String key) {
    // single-byte XOR, key repeated/cycled per character
    ...
}
```

**Scheme summary:**

| Step | Detail |
|---|---|
| Encoding | Base64 (standard) |
| Cipher | Repeating-key XOR (Vigenère-style, byte/char level) |
| Key | Decimal string representation of `fib(150)`, computed via naive recursive Fibonacci (`slowRecursive`) — the recursion is the "heavy computation" the UI warns about, and it is what an attacker is meant to avoid re-implementing brute-force |
| Ciphertext | `cVZaW1dDQllZTFdRW1xeUlBbX21CWFtHalRZXUJFRFhNX1ZcbllGQ15cUUNSRFpcVks=` (Base64) |

**Weakness identified:** The encryption key is not stored securely — it is
*derived deterministically from a public constant* (`n = 150`) using a pure
function with no secret input. Anyone who decompiles the app can read
`slowRecursive(150)` directly out of the bytecode and compute it in O(n) time
with memoization, completely sidestepping the intended O(2^n) "slow"
recursion. XOR itself is also trivially reversible once the key is known,
since XOR is its own inverse.

## 5. Decryption

Reimplemented the exact algorithm in Python for verification:

```python
import base64

def fib(n, memo={}):
    if n <= 1:
        return n
    if n in memo:
        return memo[n]
    memo[n] = fib(n-1, memo) + fib(n-2, memo)
    return memo[n]

key = str(fib(150))                     # "9969216677189303386214405760200"

encoded = "cVZaW1dDQllZTFdRW1xeUlBbX21CWFtHalRZXUJFRFhNX1ZcbllGQ15cUUNSRFpcVks="
decoded_str = base64.b64decode(encoded).decode('utf-8')

flag = "".join(
    chr(ord(key[i % len(key)]) ^ ord(ch))
    for i, ch in enumerate(decoded_str)
)
print(flag)
```

**Output:**

```
Holberton{fibonacci_slow_computation_optimization}
```

## 6. Challenges Faced

- The task template assumes a client-server model requiring live traffic
  interception (Burp/mitmproxy), but this build of the challenge computes
  everything locally and hardcodes the ciphertext in the APK — so the
  "interception" step became extracting constants from decompiled bytecode
  rather than manipulating HTTP requests/responses.
- `jadx` produced 24 minor errors while decompiling unrelated
  AndroidX/Compose library classes; these did not affect the app's own
  package (`com.holberton.task3`), which decompiled cleanly.
- Correctly matching the recursive `slowRecursive` semantics (base case
  `n <= 1 → n`, i.e., standard `fib(0)=0, fib(1)=1`) was necessary to get the
  exact same key string the app itself computes at runtime.

## 7. Flag

```
Holberton{fibonacci_slow_computation_optimization}
```
