// LocalStorage.js
// ------------------------------------------------------------------

/* jshint esversion:9, node:true, strict:implied */
/* global window, console */

function AppScopedStoreManager(appid) {
  this.appid = appid;
}

AppScopedStoreManager.prototype.get = (key) =>
 window.localStorage.getItem(this.appid + '.datamodel.' + key);

AppScopedStoreManager.prototype.remove = (key) =>
 window.localStorage.removeItem(this.appid + '.datamodel.' + key);

AppScopedStoreManager.prototype.store = (key, value) =>
 window.localStorage.setItem(this.appid + '.datamodel.' + key, value);

const init = (id) => new AppScopedStoreManager(id);

module.exports = {
  init
};
