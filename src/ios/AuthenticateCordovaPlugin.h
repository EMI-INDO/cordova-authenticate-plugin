#import <Cordova/CDV.h>
#import <AuthenticationServices/AuthenticationServices.h>

@interface AuthenticateCordovaPlugin : CDVPlugin <ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding>

@property (nonatomic, strong) NSString *callbackId;
@property (nonatomic, strong) NSString *currentNonce;

- (void)startSignInWithApple:(CDVInvokedUrlCommand *)command;
- (void)getCurrentUser:(CDVInvokedUrlCommand *)command;
- (void)signOut:(CDVInvokedUrlCommand *)command;

@end
