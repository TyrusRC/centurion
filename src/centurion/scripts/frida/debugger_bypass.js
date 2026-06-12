// Centurion — anti-debug bypass (Android). AUTHORIZED TESTING ONLY.
Java.perform(function () {
  try {
    var Debug = Java.use('android.os.Debug');
    Debug.isDebuggerConnected.implementation = function () {
      console.log('[centurion] isDebuggerConnected -> false');
      return false;
    };
    console.log('[centurion] Debug.isDebuggerConnected hooked');
  } catch (e) { console.log('[centurion] debugger_bypass skipped: ' + e); }
});
