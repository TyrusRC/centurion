// Centurion — iOS jailbreak-detection bypass. AUTHORIZED TESTING ONLY.
// Hides common JB artifacts from fileExistsAtPath: checks.
if (ObjC.available) {
  try {
    var NSFileManager = ObjC.classes.NSFileManager;
    var blocked = ['/Applications/Cydia.app', '/bin/bash', '/usr/sbin/sshd', '/etc/apt', '/private/var/lib/apt/'];
    var orig = NSFileManager['- fileExistsAtPath:'];
    Interceptor.attach(orig.implementation, {
      onEnter: function (args) { this.path = new ObjC.Object(args[2]).toString(); },
      onLeave: function (retval) {
        if (blocked.indexOf(this.path) !== -1) {
          console.log('[centurion] hiding JB path: ' + this.path);
          retval.replace(0x0);
        }
      }
    });
    console.log('[centurion] fileExistsAtPath: JB checks hooked');
  } catch (e) { console.log('[centurion] ios_jailbreak_bypass skipped: ' + e); }
} else {
  console.log('[centurion] Objective-C runtime unavailable');
}
