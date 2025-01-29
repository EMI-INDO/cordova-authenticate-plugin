var exec = require('cordova/exec');

exports.startSignInWithApple = function (success, error) {
    exec(success, error, 'AuthenticateCordovaPlugin', 'startSignInWithApple', []);
};
exports.getCurrentUser = function (success, error) {
    exec(success, error, 'AuthenticateCordovaPlugin', 'getCurrentUser', []);
};
exports.signOut = function (success, error) {
    exec(success, error, 'AuthenticateCordovaPlugin', 'signOut', []);
};
