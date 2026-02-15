<?php

namespace Yaseek\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\ResponseInterface;

class Vkontakte extends AbstractProvider
{

    const VERSION = '3.0.0';

    protected $baseOAuthUri = 'https://id.vk.com';
    protected $baseUri      = 'https://api.vk.com/method';
    protected $version      = '5.199';
    protected $language     = null;

    /**
     * @type array
     * @see https://vk.com/dev/permissions
     */
    public $scopes = [
        'email',
        'friends',
        'offline',
        //'photos',
        //'wall',
        //'ads',
        //'audio',
        //'docs',
        //'groups',
        //'market',
        //'messages',
        //'nohttps',
        //'notes',
        //'notifications',
        //'notify',
        //'pages',
        //'stats',
        //'status',
        //'video',
    ];
    /**
     * @type array
     * @see https://new.vk.com/dev/fields
     */
    public $userFields = [
        'bdate',
        'city',
        'country',
        'domain',
        'first_name',
        'friend_status',
        'has_photo',
        'home_town',
        'id',
        'is_friend',
        'last_name',
        'maiden_name',
        'nickname',
        'photo_max',
        'photo_max_orig',
        'screen_name',
        'sex',
        //'about',
        //'activities',
        //'blacklisted',
        //'blacklisted_by_me',
        //'books',
        //'can_post',
        //'can_see_all_posts',
        //'can_see_audio',
        //'can_send_friend_request',
        //'can_write_private_message',
        //'career',
        //'common_count',
        //'connections',
        //'contacts',
        //'crop_photo',
        //'counters',
        //'deactivated',
        //'education',
        //'exports',
        //'followers_count',
        //'games',
        //'has_mobile',
        //'hidden',
        //'interests',
        //'is_favorite',
        //'is_hidden_from_feed',
        //'last_seen',
        //'military',
        //'movies',
        //'occupation',
        //'online',
        //'personal',
        //'photo_100',
        //'photo_200',
        //'photo_200_orig',
        //'photo_400_orig',
        //'photo_50',
        //'photo_id',
        //'quotes',
        //'relation',
        //'relatives',
        //'schools',
        //'site',
        //'status',
        //'timezone',
        //'tv',
        //'universities',
        //'verified',
        //'wall_comments',
    ];

    /**
     * @param string $language
     */
    public function setLanguage($language)
    {
        $this->language = (string)$language;

        return $this;
    }

    public function getBaseAuthorizationUrl()
    {
        return "$this->baseOAuthUri/authorize";
    }
    public function getBaseAccessTokenUrl(array $params)
    {
        return $this->baseOAuthUri . '/oauth2/auth';
    }

    /**
     * Returns a randomly generated string, new for each authorization request
     * @param int $length PKCE verifier string length
     * @return string
     * @throws \Exception
     */
    private static function _make_pkce_verifier($length = 64) {
        return bin2hex(random_bytes($length));
    }

    /**
     * Returns the value, converted using sha256 and encoded in base64
     * @param string $verifier PKCE verifier
     * @return string
     */
    private static function _code_challenge($verifier) {
        $hash = hash('sha256', $verifier, true);
        return rtrim(strtr(base64_encode($hash), '+/', '-_'), '=');
    }

    /**
     * Stores or returns PKCE verifier
     * @param string|null $value PKCE verifier
     * @param string $key Key name in $_SESSION variable
     * @return string|null
     */
    private static function _pkce_verifier_storage($value = null, $key = '__pkce') {
        $result = $value;
        switch (true) {
            case is_null($value) && array_key_exists($key, $_SESSION):
                $result = $_SESSION[$key];
                unset($_SESSION[$key]);
                break;
            default:
                $_SESSION[$key] = $value;
                break;
        }
        return $result;
    }

    /**
     * @inheritDoc
     * @link https://id.vk.com/about/business/go/docs/ru/vkid/latest/vk-id/connection/api-description#Zapros-koda-podtverzhdeniya-i-rabota-s-formoj-razresheniya-dostupov-polzovatelya
     */
    protected function getAuthorizationParameters(array $options) {
        $options = parent::getAuthorizationParameters($options);
        // VK OAuth 2.1 PKCE Protocol Challenge
        if (!isset($options['code_challenge'])) {
            $verifier = self::_make_pkce_verifier();
            $options['code_challenge'] = self::_code_challenge($verifier);
            $options['code_challenge_method'] = 'S256';
            self::_pkce_verifier_storage($verifier);
        }
        return $options;
    }

    /**
     * Enriches the parameters for the token request with the device identifier
     * @param string[] $options Token request parameters
     * @param string $key
     */
    private static function _enrich_device_id(array &$options, $key = 'device_id') {
        if (!array_key_exists($key, $options) && array_key_exists($key, $_GET)) {
            $options[$key] = $_GET[$key];
        }
    }

    /**
     * @inheritDoc
     * @link https://id.vk.com/about/business/go/docs/ru/vkid/latest/vk-id/connection/api-description#Poluchenie-cherez-kod-podtverzhdeniya
     */
    public function getAccessToken($grant, array $options = []) {
        self::_enrich_device_id($options);
        $options['code_verifier'] = self::_pkce_verifier_storage();
        return parent::getAccessToken($grant, $options);
    }

    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        $params = [
            'fields'       => $this->userFields,
            'access_token' => $token->getToken(),
            'v'            => $this->version,
            'lang'         => $this->language
        ];
        $query  = $this->buildQueryString($params);
        $url    = "$this->baseUri/users.get?$query";

        return $url;
    }
    protected function getDefaultScopes()
    {
        return $this->scopes;
    }
    protected function checkResponse(ResponseInterface $response, $data)
    {
        // Metadata info
        $contentTypeRaw = $response->getHeader('Content-Type');
        $contentTypeArray = explode(';', reset($contentTypeRaw));
        $contentType = reset($contentTypeArray);
        // Response info
        $responseCode    = $response->getStatusCode();
        $responseMessage = $response->getReasonPhrase();
        // Data info
        $error            = !empty($data['error']) ? $data['error'] : null;
        $errorCode        = !empty($error['error_code']) ? $error['error_code'] : $responseCode;
        $errorDescription = !empty($data['error_description']) ? $data['error_description'] : null;
        $errorMessage     = !empty($error['error_msg']) ? $error['error_msg'] : $errorDescription;
        $message          = $errorMessage ?: $responseMessage;

        // Request/meta validation
        if (399 < $responseCode) {
            throw new IdentityProviderException($message, $responseCode, $data);
        }

        // Content validation
        if ('application/json' != $contentType) {
            throw new IdentityProviderException($message, $responseCode, $data);
        }
        if ($error) {
            throw new IdentityProviderException($errorMessage, $errorCode, $data);
        }
    }
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        $response   = reset($response['response']);
        $additional = $token->getValues();
        if (!empty($additional['email'])) {
            $response['email'] = $additional['email'];
        }
        if (!empty($response['uid']) && 4 === floor($this->version)) {
            $response['id'] = $response['uid'];
        }
        if (!empty($additional['user_id'])) {
            $response['id'] = $additional['user_id'];
        }

        return new VkontakteUser($response);
    }

    /**
     * @see https://vk.com/dev/users.get
     *
     * @param integer[]        $ids
     * @param AccessToken|null $token Current user if empty
     * @param array            $params
     *
     * @return VkontakteUser[]
     */
    public function usersGet(array $ids = [], AccessToken $token = null, array $params = [])
    {
        if (empty($ids) && !$token) {
            throw new \InvalidArgumentException('Some of parameters usersIds OR access_token are required');
        }

        $default = [
            'user_ids'     => implode(',', $ids),
            'fields'       => $this->userFields,
            'access_token' => $token ? $token->getToken() : null,
            'v'            => $this->version,
            'lang'         => $this->language
        ];
        $params  = array_merge($default, $params);
        $query   = $this->buildQueryString($params);
        $url     = "$this->baseUri/users.get?$query";

        $response   = $this->getResponse($this->createRequest(static::METHOD_GET, $url, $token, []))['response'];
        $users      = !empty($response['items']) ? $response['items'] : $response;
        $array2user = function ($userData) {
            return new VkontakteUser($userData);
        };

        return array_map($array2user, $users);
    }
    /**
     * @see https://vk.com/dev/friends.get
     *
     * @param integer          $userId
     * @param AccessToken|null $token
     * @param array            $params
     *
     * @return VkontakteUser[]
     */
    public function friendsGet($userId, AccessToken $token = null, array $params = [])
    {
        $default = [
            'user_id'      => $userId,
            'fields'       => $this->userFields,
            'access_token' => $token ? $token->getToken() : null,
            'v'            => $this->version,
            'lang'         => $this->language
        ];
        $params  = array_merge($default, $params);
        $query   = $this->buildQueryString($params);
        $url     = "$this->baseUri/friends.get?$query";

        $response     = $this->getResponse($this->createRequest(static::METHOD_GET, $url, $token, []))['response'];
        $friends      = !empty($response['items']) ? $response['items'] : $response;
        $array2friend = function ($friendData) {
            if (is_numeric($friendData)) {
                $friendData = ['id' => $friendData];
            }

            return new VkontakteUser($friendData);
        };

        return array_map($array2friend, $friends);
    }
}
