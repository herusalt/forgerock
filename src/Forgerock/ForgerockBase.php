<?php
/**
 * Created by PhpStorm.
 * User: SALT
 * Date: 14/10/2019
 * Time: 10:32
 */

namespace App\Forgerock;

use App\Forgerock\Formatter\JsonFormatter;
use App\Forgerock\Formatter\MessageFormatter;
use App\Forgerock\Middleware\Guzzle\GuzzleMiddleware;
use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use Monolog\Logger;


class ForgerockBase
{
    protected $client;

    function __construct()
    {
        $logger = new Logger('FORGEROCK');

        $streamHandler = new \Monolog\Handler\StreamHandler('php://stdout');
        $streamHandler->setFormatter(new JsonFormatter());
        $logger->pushHandler($streamHandler);
        $stack = HandlerStack::create();
        $dataFormatter = ['url', 'req_headers', 'req_body', 'res_body', 'error', 'code'];
        $stack->push(GuzzleMiddleware::log(
            $logger,
            new MessageFormatter($dataFormatter)
        ));
        $guzzleClientOptions = [
            // Base URI is used with relative requests
            'base_uri' => env('FR_DOMAIN'),
            // You can set any number of default request options.
            'timeout' => 15.0,
            'verify' => false,
            "handler" => $stack,
        ];
        $this->client = new Client($guzzleClientOptions);
    }

    protected function getRequest($uri, $queryString = [], $headers = ['Accept' => 'application/json'])
    {
        $response = $this->client->get($uri, [
                'query' => $queryString,
                'headers' => $headers,
            ]
        );
        return \GuzzleHttp\json_decode($response->getBody());
    }

    protected function postRequest($uri, $queryString, $body = [], $headers = ['Accept' => 'application/json'])
    {
        $response = $this->client->post($uri, [
            'json' => $body,
            'query' => $queryString,
            'headers' => $headers
        ]);
        return \GuzzleHttp\json_decode($response->getBody());
    }

    protected function deleteRequest($uri)
    {
        $response = $this->client->delete($uri);
        return \GuzzleHttp\json_decode($response->getBody());
    }

    protected function request($method, $uri, $queryString, $body = [], $headers = ['Accept' => 'application/json'])
    {
        $response = $this->client->request($method, $uri, [
            'json' => $body,
            'headers' => $headers,
            'query' => $queryString,
            'http_errors' => false,
            'allow_redirects' => false,
        ]);
        return $response;
    }
}
