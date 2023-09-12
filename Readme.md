## Installation

```bash
composer require herusalt/forgerock
```
### Modify bootstrap/app.php
add this line
```
 $app->routeMiddleware([
     'auth' => \App\Forgerock\Middlewere\ServiceMiddleware::class
       ...
  ]);
```
or
```
 $app->routeMiddleware([
     'auth' => \App\Forgerock\Middlewere\MemberPimcoreMiddleware::class
       ...
  ]);
```


## Usage: 
add this line on routes/web.php

```
$router->group(['prefix' => 'v1', 'middleware' => ['localization', 'channel','auth']], function () use ($router) {

}
```

## Add Credential
FR_SCOPE= 

FR_REDIRECT_URI=

FR_SECRETKEY=

FR_CLIENTID=

FR_CLIENTID_MOBILE=

FR_DOMAIN=

FR_ALG=

STATUS_FAILED_CODE=01