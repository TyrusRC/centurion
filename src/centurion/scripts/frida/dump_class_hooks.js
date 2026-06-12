// Centurion — enumerate methods of a target class. AUTHORIZED TESTING ONLY.
// Set CENTURION_CLASS in the spawned env, or edit the constant below.
Java.perform(function () {
  var target = 'java.lang.String';
  try {
    var clazz = Java.use(target);
    var methods = clazz.class.getDeclaredMethods();
    console.log('[centurion] methods of ' + target + ':');
    methods.forEach(function (m) { console.log('  ' + m.toString()); });
  } catch (e) { console.log('[centurion] dump_class_hooks skipped: ' + e); }
});
