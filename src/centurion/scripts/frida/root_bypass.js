// Centurion — root-detection bypass (Android). AUTHORIZED TESTING ONLY.
Java.perform(function () {
  try {
    var File = Java.use('java.io.File');
    var blocked = ['/system/bin/su', '/system/xbin/su', '/sbin/su', '/su/bin/su'];
    File.exists.implementation = function () {
      var p = this.getAbsolutePath();
      if (blocked.indexOf(p) !== -1) {
        console.log('[centurion] hiding root path: ' + p);
        return false;
      }
      return File.exists.call(this);
    };
    console.log('[centurion] File.exists root checks hooked');
  } catch (e) { console.log('[centurion] root_bypass skipped: ' + e); }
});
