<?php

namespace KenKoKa\LaraJWT\Facades;

use Illuminate\Support\Facades\Facade;
use KenKoKa\LaraJwt\Services\IJwtAuth;

class JwtAuth extends Facade
{
    protected static function getFacadeAccessor()
    {
        return IJwtAuth::class;
    }
}