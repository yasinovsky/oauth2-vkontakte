# Vkontakte OAuth2 client provider

[![Build Status](https://travis-ci.com/yasinovsky/oauth2-vkontakte.svg?branch=master)](https://travis-ci.com/yasinovsky/oauth2-vkontakte)
[![Latest Stable Version](https://img.shields.io/packagist/v/yasinovsky/oauth2-vkontakte.svg)](https://packagist.org/packages/yasinovsky/oauth2-vkontakte)
[![License](https://img.shields.io/packagist/l/yasinovsky/oauth2-vkontakte.svg)](https://packagist.org/packages/yasinovsky/oauth2-vkontakte)

This package provides [Vkontakte](https://vk.com) integration for [OAuth2 Client](https://github.com/thephpleague/oauth2-client) by the League.

## Installation

```sh
composer require yasinovsky/oauth2-vkontakte
```
## Versions

Use `v2.0+` for `"php": "^7.3 || ^8.0"`

Use `v1.2.3` for `"php": "^5.6 || ^7.0"`


## Configuration

```php
$provider = new Yaseek\OAuth2\Client\Provider\Vkontakte([
    'clientId'     => '1234567',
    'clientSecret' => 's0meRe4lLySEcRetC0De',
    'redirectUri'  => 'https://example.org/oauth-endpoint',
    'scopes'       => ['email', 'offline', 'friends'],
]);
```

## Authorization

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
$provider->friendsGet(23456);        // => \Yaseek\OAuth2\Client\Provider\VkontakteUser[]
```

### With additional data
```php
$providerAccessToken = new \League\OAuth2\Client\Token\AccessToken(['access_token' => 'iAmAccessTokenString']);
$provider->usersGet([1234, 56789], $providerAccessToken); // => \Yaseek\OAuth2\Client\Provider\VkontakteUser[]
$provider->friendsGet(23456, $providerAccessToken);        // => \Yaseek\OAuth2\Client\Provider\VkontakteUser[]
```

## Contributions

Contributions are very welcome. Please submit a PR
