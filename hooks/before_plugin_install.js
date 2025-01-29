module.exports = function(context) {
    const fs = require('fs');
    const path = require('path');
    const platform = context.opts.cordova.platforms[0]; 

    if (platform === 'android') {
        const sourceFile = 'www/google-services.json'; 
        const targetFile = 'platforms/android/app/google-services.json'; 

        if (fs.existsSync(sourceFile)) {
            fs.copyFileSync(sourceFile, targetFile);
            console.log(`Adding google-services.json to the ${targetFile}`);
        } else {
            console.log('The google-services.json file was not found in the www directory');
        }
    }

    if (platform === 'ios') {
        const sourceFile = 'GoogleService-Info.plist'; 
        const targetDir = 'platforms/ios/'; 

        if (fs.existsSync(sourceFile)) {
            const targetFile = path.join(targetDir, sourceFile); 
            fs.copyFileSync(sourceFile, targetFile);
            console.log(`Adding GoogleService-Info.plist to the ${targetFile}`);
        } else {
            console.log('GoogleService-Info.plist file not found');
        }
    }
};