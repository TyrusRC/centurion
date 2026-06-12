// Centurion — iOS TLS pinning bypass. AUTHORIZED TESTING ONLY.
// Neutralises SecTrustEvaluate-based pinning by forcing the trust result to proceed.
if (ObjC.available) {
  try {
    var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
    if (SecTrustEvaluate) {
      Interceptor.replace(SecTrustEvaluate, new NativeCallback(function (trust, result) {
        if (!result.isNull()) { result.writeU32(1); }  // kSecTrustResultProceed
        return 0;  // errSecSuccess
      }, 'int', ['pointer', 'pointer']));
      console.log('[centurion] SecTrustEvaluate forced to proceed');
    }
  } catch (e) { console.log('[centurion] ios_ssl_unpin skipped: ' + e); }
} else {
  console.log('[centurion] Objective-C runtime unavailable');
}
