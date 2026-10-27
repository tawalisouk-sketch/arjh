/* Pointage DRONEGROUPE — installation de l'application sur téléphone / tablette / ordinateur
 * - enregistre le service worker (nécessaire à l'installation)
 * - affiche une pilule « Installer l'application » quand le navigateur le permet
 * - sur iPhone / iPad : explique la marche à suivre (Partager > Sur l'écran d'accueil)
 * - dans les navigateurs intégrés (Facebook, Instagram…) : invite à ouvrir le lien dans Chrome ou Safari
 */
(function () {
  'use strict';
  if ('serviceWorker' in navigator && window.isSecureContext) {
    window.addEventListener('load', function () { navigator.serviceWorker.register('/sw.js').catch(function () {}); });
  }

  var ua = navigator.userAgent || '';
  var standalone = (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) || navigator.standalone === true;
  var ios = /iphone|ipad|ipod/i.test(ua) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  var inApp = /FBAN|FBAV|FB_IAB|Instagram|Line\/|Snapchat|TikTok/i.test(ua);
  var KEY = 'pwa_plus_tard_' + location.pathname;

  window.PWA = { standalone: standalone, ios: ios, install: null };
  if (standalone) return;

  function later() { try { return Number(localStorage.getItem(KEY) || 0) > Date.now(); } catch (e) { return false; } }
  function setLater() { try { localStorage.setItem(KEY, String(Date.now() + 3 * 24 * 3600 * 1000)); } catch (e) {} }

  var css = document.createElement('style');
  css.textContent =
    '.pwa-bar{position:fixed;left:50%;bottom:16px;transform:translate(-50%,140%);z-index:400;width:calc(100% - 24px);max-width:460px;' +
    'background:#fff;color:#0B1640;border-radius:24px;box-shadow:0 10px 34px rgba(8,26,92,.35);padding:14px 16px;transition:transform .3s;' +
    'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;text-align:left;}' +
    '.pwa-bar.on{transform:translate(-50%,0);}' +
    '.pwa-t{font-weight:800;font-size:15px;color:#081A5C;}' +
    '.pwa-s{font-size:13px;color:#4E5A7A;margin-top:4px;line-height:1.45;}' +
    '.pwa-row{display:flex;gap:8px;margin-top:12px;}' +
    '.pwa-row button{flex:1;border:none;border-radius:999px;padding:12px 10px;font-weight:800;font-size:14px;cursor:pointer;font-family:inherit;}' +
    '.pwa-go{background:#D35400;color:#fff;}.pwa-no{background:#DCEFE4;color:#0B5E3B;}';
  document.head.appendChild(css);

  var bar = null, deferred = null;
  function show(mode) {
    if (later() || bar) return;
    bar = document.createElement('div');
    bar.className = 'pwa-bar';
    var t, s, go = '';
    if (mode === 'inapp') {
      t = 'Ouvrez ce lien dans votre navigateur';
      s = 'Pour installer l\'application, touchez le menu en haut puis « Ouvrir dans Chrome » ou « Ouvrir dans Safari ».';
    } else if (mode === 'ios') {
      t = 'Installer l\'application';
      s = 'Touchez le bouton Partager de Safari, puis « Sur l\'écran d\'accueil », puis « Ajouter ».';
    } else {
      t = 'Installer l\'application';
      s = 'Ajoutez-la à votre écran d\'accueil pour l\'ouvrir en un geste, comme une vraie application.';
      go = '<button class="pwa-go" type="button">Installer</button>';
    }
    bar.innerHTML = '<div class="pwa-t">' + t + '</div><div class="pwa-s">' + s + '</div><div class="pwa-row">' + go +
      '<button class="pwa-no" type="button">' + (go ? 'Plus tard' : 'Compris') + '</button></div>';
    document.body.appendChild(bar);
    requestAnimationFrame(function () { requestAnimationFrame(function () { bar.classList.add('on'); }); });
    var b = bar.querySelector('.pwa-go');
    if (b) b.onclick = install;
    bar.querySelector('.pwa-no').onclick = function () { setLater(); hide(); };
  }
  function hide() { if (!bar) return; bar.classList.remove('on'); var b = bar; bar = null; setTimeout(function () { b.remove(); }, 400); }

  function install() {
    if (!deferred) return false;
    deferred.prompt();
    deferred.userChoice.then(function () { deferred = null; hide(); }).catch(function () {});
    return true;
  }
  window.PWA.install = install;

  window.addEventListener('beforeinstallprompt', function (e) {
    e.preventDefault();
    deferred = e;
    if (document.body) show('android'); else document.addEventListener('DOMContentLoaded', function () { show('android'); });
  });
  window.addEventListener('appinstalled', function () { deferred = null; hide(); });

  document.addEventListener('DOMContentLoaded', function () {
    if (inApp) setTimeout(function () { show('inapp'); }, 800);
    else if (ios) setTimeout(function () { show('ios'); }, 1200);
  });
})();
