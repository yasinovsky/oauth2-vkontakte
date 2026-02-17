# VKontakte OAuth 2.1 Client Provider for The PHP League OAuth2 Client

[![Source Code](https://img.shields.io/badge/source-yasinovsky/oauth2--vkontakte-blue.svg?style=flat-square)](https://github.com/yasinovsky/oauth2-vkontakte)
[![Latest Version](https://img.shields.io/github/release/yasinovsky/oauth2-vkontakte.svg?style=flat-square)](https://github.com/yasinovsky/oauth2-vkontakte/releases)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](https://github.com/yasinovsky/oauth2-vkontakte/blob/master/LICENSE.md)
[![Total Downloads](https://img.shields.io/packagist/dt/yasinovsky/oauth2-vkontakte.svg?style=flat-square)](https://packagist.org/packages/yasinovsky/oauth2-vkontakte) 

This package provides [VKontakte OAuth 2.1](https://vk.com) support for the PHP League's [OAuth 2.0 Client](https://github.com/thephpleague/oauth2-client).

This package is compliant with [PSR-1][], [PSR-2][], [PSR-4][], and [PSR-7][]. If you notice compliance oversights, please send a patch via pull request.

[PSR-1]: https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-1-basic-coding-standard.md
[PSR-2]: https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-2-coding-style-guide.md
[PSR-4]: https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-4-autoloader.md
[PSR-7]: https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-7-http-message.md

## Requirements

We support the following versions of PHP:

* PHP 8.5
* PHP 8.4
* PHP 8.3
* PHP 8.2
* PHP 8.1
* PHP 8.0
* PHP 7.4
* PHP 7.3

## Installation

```sh
composer require yasinovsky/oauth2-vkontakte
```

## Usage

### Configuration

```php
$provider = new Yaseek\OAuth2\Client\Provider\Vkontakte([
    'clientId'     => '1234567',
    'clientSecret' => 's0meRe4lLySEcRetC0De',
    'redirectUri'  => 'https://example.org/oauth-endpoint',
    'scopes'       => 'vkid.personal_info email phone', // Optional
]);
```

### Authorization Code Flow

```php
// A session is required to store some session data for later usage
session_start();

// If we don't have an authorization code then get one
if (!isset($_GET['code'])) {

    // Fetch the authorization URL from the provider; this returns the
    // urlAuthorize option and generates and applies any necessary parameters
    // (e.g. state).
    $authorizationUrl = $provider->getAuthorizationUrl();

    // Get the state generated for you and store it to the session.
    $_SESSION['oauth2state'] = $provider->getState();

    // Redirect the user to the authorization URL.
    header('Location: ' . $authorizationUrl);
    exit;

// Check given state against previously stored one to mitigate CSRF attack
} elseif (empty($_GET['state']) || empty($_SESSION['oauth2state']) || $_GET['state'] !== $_SESSION['oauth2state']) {

    if (isset($_SESSION['oauth2state'])) {
        unset($_SESSION['oauth2state']);
    }

    exit('Invalid state');

} else {

    try {

        // Try to get an access token using the authorization code grant.
        $tokens = $provider->getAccessToken('authorization_code', [
            'code' => $_GET['code']
        ]);

        // We have an access token, which we may use in authenticated
        // requests against the service provider's API.
        echo 'Access Token: ' . $tokens->getToken() . "<br>";
        echo 'Refresh Token: ' . $tokens->getRefreshToken() . "<br>";
        echo 'Expired in: ' . $tokens->getExpires() . "<br>";
        echo 'Already expired? ' . ($tokens->hasExpired() ? 'expired' : 'not expired') . "<br>";

        // Using the access token, we may look up details about the
        // resource owner.
        $resourceOwner = $provider->getResourceOwner($tokens);

        var_export($resourceOwner->toArray());

    } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {

        // Failed to get the access token or user details.
        exit($e->getMessage());

    }

}
```

## Helper methods

### Public
```php
$provider->usersGet([1234, 56789]); // => \Yaseek\OAuth2\Client\Provider\VkontakteUser[]
$provider->friendsGet(23456);       // => \Yaseek\OAuth2\Client\Provider\VkontakteUser[]
```

### With additional data
```php
$providerAccessToken = new \League\OAuth2\Client\Token\AccessToken(['access_token' => 'iAmAccessTokenString']);
$provider->usersGet([1234, 56789], $providerAccessToken); // => \Yaseek\OAuth2\Client\Provider\VkontakteUser[]
$provider->friendsGet(23456, $providerAccessToken);       // => \Yaseek\OAuth2\Client\Provider\VkontakteUser[]
```

## Credits

- [Victor Yasinovsky](https://github.com/yasinovsky)
- [Yury Arlou](https://github.com/zablik)
- [Jack Wall](https://github.com/j4k)
