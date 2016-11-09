<?php
namespace Click\Bundle\AppBundle\Api\OpenX\Library;

use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Handler\CurlHandler;
use GuzzleHttp\RequestOptions;
use GuzzleHttp\Subscriber\Oauth\Oauth1;


/**
 * Pubstream.com - OpenX Symfony 2 Library use php-http/guzzle6-adapter Library
 *
 */
class PubstreamOpenX
{
    /**
     * @var Client
     */
    protected $client;

    /**
     * @var Oauth1
     */
    protected $oauth;

    /**
     * @var string
     */
    protected $consumerKey;

    /**
     * @var string
     */
    protected $consumerSecret;

    /**
     * @var string
     */
    protected $baseUrl;

    /**
     * @var array
     */
    protected $config;

    /**
     * @var string
     */
    protected $requestToken;

    /**
     * @var string
     */
    protected $requestTokenSecret;

    /**
     * @var string
     */
    protected $verifier;

    /**
     * @var string
     */
    protected $accessToken;

    /**
     * Constructor
     *
     * @param string $consumerKey    oAuth consumer key
     * @param string $consumerSecret oAuth consumer secret
     * @param string $realm          Realm realm to login with
     * @param string $baseUrl        Full base URL of your OpenX service
     * @param array  $config         Configuration settings for oAuth URLs to use and callback
     */
    public function __construct($consumerKey, $consumerSecret, $realm, $baseUrl, array $config = [])
    {

        $this->consumerKey = $consumerKey;
        $this->consumerSecret = $consumerSecret;
        $this->realm = $realm;
        $this->baseUrl = $baseUrl;

        $handler = new CurlHandler();
        $stack = HandlerStack::create($handler);

        $this->config = array_merge([
            'requestTokenUrl' => 'https://sso.openx.com/api/index/initiate',
            'accessTokenUrl'  => 'https://sso.openx.com/api/index/token',
            'authorizeUrl'    => 'https://sso.openx.com/login/login',
            'loginUrl'        => 'https://sso.openx.com/login/process',
            'callbackUrl'     => 'oob' // oob = "Out of Band" (programmatic login)
        ], $config);

        $middleware = new Oauth1([
            'version'          => '1.0',
            'request_method'   => Oauth1::REQUEST_METHOD_HEADER,//Oauth1::REQUEST_METHOD_HEADER,
            'consumer_key'     => $this->consumerKey,
            'consumer_secret'  => $this->consumerSecret,
            'signature_method' => Oauth1::SIGNATURE_METHOD_HMAC,
            'realm'            => '',
            'token_secret'     => '',
        ]);

        $stack->push($middleware);

        $this->client = new Client([
            'base_uri' => $this->baseUrl,
            'handler' => $stack,

            RequestOptions::AUTH => 'oauth',
            RequestOptions::HTTP_ERRORS => true,
            RequestOptions::HEADERS => ['Content-Type' => 'application/json'],
            RequestOptions::FORM_PARAMS => ['oauth_callback' => 'oob']
        ]);

    }

    /**
     * Get oAuth request token - 1st step
     *
     * @param boolean $refresh Refresh request (retrieve token from webservice again instead of returning cached value)
     *
     * @return string
     */
    public function getRequestToken($refresh = false)
    {
        if (!empty($this->requestToken) && $refresh === false) {
            return $this->requestToken;
        }

        $res = $this->client->post(
            $this->config['requestTokenUrl'],
            [
                'form_params' => [
                    'auth' => 'oauth',
                    'oauth_callback' => $this->config['callbackUrl'],
                ]
            ]
        );

        parse_str((string) $res->getBody()->getContents(), $params);

        $this->requestToken       = $params['oauth_token'];
        $this->requestTokenSecret = $params['oauth_token_secret'];

        return $this->requestToken;
    }

    /**
     * Login with oAuth 1.0a API - 2nd step
     *
     * @param string $email    Email of user to login with
     * @param string $password Password of user to login with
     *
     * @return boolean
     */
    public function login($email, $password)
    {
        if (empty($this->requestToken)) {
            $this->getRequestToken();
        }

        $response = $this->client->post($this->config['loginUrl'], [
            'form_params' => [
                'email'       => $email,
                'password'    => $password,
                'oauth_token' => $this->requestToken
            ]
        ]);

        parse_str(substr((string) $response->getBody()->getContents(), 4), $loginParams);

        $this->requestToken = $loginParams['oauth_token'];
        $this->verifier     = $loginParams['oauth_verifier'];

        return true;
    }

    /**
     * Get access token - 3rd and final step
     *
     * @param boolean $refresh Refresh request (retrieve token from webservice again instead of returning cached value)
     *
     * @return string
     */
    public function getAccessToken($refresh = false)
    {
        if (!empty($this->accessToken) && $refresh === false) {
            return $this->accessToken;
        }

        if (empty($this->requestToken) || empty($this->verifier)) {
            throw new \BadMethodCallException("This method requires a valid requestToken and verifier. Please call \$client->login() first.");
        }

        $handler = new CurlHandler();
        $stack = HandlerStack::create($handler);
        $middleware = new Oauth1([
            'consumer_key'    => $this->consumerKey,
            'consumer_secret' => $this->consumerSecret,
            'token'           => $this->requestToken,
            'token_secret'    => $this->requestTokenSecret,
            'verifier'        => $this->verifier
        ]);
        $stack->push($middleware);
        $this->client = new Client([
            'base_uri' => $this->baseUrl,
            'handler' => $stack,

            RequestOptions::HTTP_ERRORS => true,
            RequestOptions::HEADERS => ['Content-Type' => 'application/json'],
            RequestOptions::FORM_PARAMS => ['oauth_callback' => 'oob']
        ]);

        $res = $this->client->post(
            $this->config['accessTokenUrl'],
            [
                RequestOptions::AUTH => 'oauth',
            ]
        );

        $response = (string) $res->getBody()->getContents();
        parse_str($response, $accessTokenParams);

        // Save and return acccess token
        $this->accessToken = $accessTokenParams['oauth_token'];

        return $this->accessToken;
    }

    /**
     * Return authentication cookie string
     *
     * @return string
     */
    public function getAuthCookie()
    {
        if (empty($this->accessToken)) {
            $this->getAccessToken();
        }

        return 'openx3_access_token=' . $this->accessToken;
    }

    /**
     * Passthrough method to Guzzle's common HTTP methods
     *
     * @param string $method HTTP Method to call
     * @param array  $args   Array of arguments to pass to function
     *
     * @return mixed
     */
    public function __call($method, array $args = [])
    {
        if (!in_array($method, ['get', 'post', 'put', 'delete', 'head', 'options', 'patch'])) {
            throw new \BadMethodCallException("Method $method does not exist on " . __CLASS__);
        }

        // Sort out arguments
        $url = isset($args[0]) ? $args[0] : null;
        $options = isset($args[1]) ? $args[1] : [];

        // Ensure cookie with access token is sent with each request
        $options['headers'] = array_merge([
            'Cookie' => $this->getAuthCookie()
        ], isset($options['headers']) ? $options['headers'] : []);

        // Make request
        return $this->client->$method($url, $options);
    }
}
