#import "AuthenticateCordovaPlugin.h"
#import <Firebase/Firebase.h>
#import <CommonCrypto/CommonDigest.h>

@implementation AuthenticateCordovaPlugin

- (NSString *)randomNonce:(NSInteger)length {
    NSAssert(length > 0, @"Nonce harus memiliki panjang positif");
    NSString *characterSet = @"0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz-._";
    NSMutableString *result = [NSMutableString string];
    NSInteger remainingLength = length;

    while (remainingLength > 0) {
        uint8_t randomBytes[16];
        int errorCode = SecRandomCopyBytes(kSecRandomDefault, sizeof(randomBytes), randomBytes);
        NSAssert(errorCode == errSecSuccess, @"Tidak dapat membuat nonce: OSStatus %i", errorCode);

        for (int i = 0; i < sizeof(randomBytes) && remainingLength > 0; i++) {
            uint8_t random = randomBytes[i];
            if (random < characterSet.length) {
                unichar character = [characterSet characterAtIndex:random];
                [result appendFormat:@"%C", character];
                remainingLength--;
            }
        }
    }

    return result;
}

- (NSString *)stringBySha256HashingString:(NSString *)input {
    const char *string = [input UTF8String];
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(string, (CC_LONG)strlen(string), result);

    NSMutableString *hashed = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSInteger i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hashed appendFormat:@"%02x", result[i]];
    }
    return hashed;
}

- (void)startSignInWithApple:(CDVInvokedUrlCommand *)command {
    self.callbackId = command.callbackId;
    self.currentNonce = [self randomNonce:32];
    NSString *hashedNonce = [self stringBySha256HashingString:self.currentNonce];

    ASAuthorizationAppleIDProvider *appleIDProvider = [[ASAuthorizationAppleIDProvider alloc] init];
    ASAuthorizationAppleIDRequest *request = [appleIDProvider createRequest];
    request.requestedScopes = @[ASAuthorizationScopeFullName, ASAuthorizationScopeEmail];
    request.nonce = hashedNonce;

    ASAuthorizationController *authorizationController = [[ASAuthorizationController alloc] initWithAuthorizationRequests:@[request]];
    authorizationController.delegate = self;
    authorizationController.presentationContextProvider = self;
    [authorizationController performRequests];
}

- (void)authorizationController:(ASAuthorizationController *)controller didCompleteWithAuthorization:(ASAuthorization *)authorization {
    if ([authorization.credential isKindOfClass:[ASAuthorizationAppleIDCredential class]]) {
        ASAuthorizationAppleIDCredential *appleIDCredential = authorization.credential;
        NSString *rawNonce = self.currentNonce;
        NSAssert(rawNonce != nil, @"State tidak valid: Callback login diterima, tetapi tidak ada permintaan login yang dikirim.");

        if (appleIDCredential.identityToken == nil) {
            CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"Token identitas tidak ditemukan."];
            [self.commandDelegate sendPluginResult:pluginResult callbackId:self.callbackId];
            return;
        }

        NSString *idToken = [[NSString alloc] initWithData:appleIDCredential.identityToken encoding:NSUTF8StringEncoding];
        if (idToken == nil) {
            CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"Gagal memproses token identitas."];
            [self.commandDelegate sendPluginResult:pluginResult callbackId:self.callbackId];
            return;
        }

        FIROAuthCredential *credential = [FIROAuthProvider credentialWithProviderID:@"apple.com" IDToken:idToken rawNonce:rawNonce];
        [[FIRAuth auth] signInWithCredential:credential completion:^(FIRAuthDataResult * _Nullable authResult, NSError * _Nullable error) {
            if (error) {
                CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:error.localizedDescription];
                [self.commandDelegate sendPluginResult:pluginResult callbackId:self.callbackId];
                return;
            }

            NSDictionary *result = @{
                @"uid": authResult.user.uid,
                @"displayName": authResult.user.displayName ?: @"",
                @"email": authResult.user.email ?: @"",
                @"providerId": authResult.user.providerID
            };
            CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:result];
            [self.commandDelegate sendPluginResult:pluginResult callbackId:self.callbackId];
        }];
    }
}

- (void)authorizationController:(ASAuthorizationController *)controller didCompleteWithError:(NSError *)error {
    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:[NSString stringWithFormat:@"Sign in dengan Apple gagal: %@", error.localizedDescription]];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:self.callbackId];
}

- (ASPresentationAnchor)presentationAnchorForAuthorizationController:(ASAuthorizationController *)controller {
    return self.viewController.view.window;
}

- (void)getCurrentUser:(CDVInvokedUrlCommand *)command {
    FIRUser *currentUser = [FIRAuth auth].currentUser;
    if (currentUser) {
        NSDictionary *result = @{
            @"uid": currentUser.uid,
            @"displayName": currentUser.displayName ?: @"",
            @"email": currentUser.email ?: @"",
            @"providerId": currentUser.providerID
        };
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:result];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    } else {
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"Tidak ada pengguna yang sedang masuk."];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
}

- (void)signOut:(CDVInvokedUrlCommand *)command {
    NSError *signOutError;
    BOOL status = [[FIRAuth auth] signOut:&signOutError];
    if (status) {
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:@"Berhasil keluar."];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    } else {
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:signOutError.localizedDescription];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
}

@end
