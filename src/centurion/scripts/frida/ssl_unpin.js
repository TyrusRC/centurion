// Centurion — TLS pinning bypass (Android). AUTHORIZED TESTING ONLY.
// Neutralises common pinning paths: custom TrustManager + OkHttp CertificatePinner.
Java.perform(function () {
  try {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustManager = Java.registerClass({
      name: 'com.centurion.TrustAll',
      implements: [X509TrustManager],
      methods: {
        checkClientTrusted: function () {},
        checkServerTrusted: function () {},
        getAcceptedIssuers: function () { return []; }
      }
    });
    var init = SSLContext.init.overload(
      '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;',
      'java.security.SecureRandom');
    init.implementation = function (km, tm, sr) {
      init.call(this, km, [TrustManager.$new()], sr);
    };
    console.log('[centurion] SSLContext TrustManager neutralised');
  } catch (e) { console.log('[centurion] TrustManager hook skipped: ' + e); }
  try {
    var Pinner = Java.use('okhttp3.CertificatePinner');
    Pinner.check.overload('java.lang.String', 'java.util.List').implementation = function () {
      console.log('[centurion] OkHttp CertificatePinner.check bypassed');
    };
  } catch (e) { console.log('[centurion] OkHttp pinner not present: ' + e); }
});
