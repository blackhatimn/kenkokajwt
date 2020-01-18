<?php

namespace KenKoKa\LaraJwt\Providers;

use Illuminate\Support\ServiceProvider as Provider;
use Lcobucci\JWT\Signer\Hmac\Sha512;
use KenKoKa\LaraJwt\Guards\Jwt as JwtGuard;
use KenKoKa\LaraJwt\Services\JwtAuth;
use KenKoKa\LaraJwt\Services\IJwtAuth;
use KenKoKa\LaraJwt\Services\JwtService;
use KenKoKa\LaraJwt\Services\IJwtService;

class ServiceProvider extends Provider
{
    /**
     * Register
     *
     * @return void
     */
    public function register()
    {
        $this->app->singleton(IJwtService::class, JwtService::class);
        $this->app->singleton(IJwtAuth::class, JwtAuth::class);

        $this->app->bind('kenkokalarajwt.signer', Sha512::class);
    }

    /**
     * Boot
     *
     * @return void
     */
    public function boot()
    {
        // Extend laravel auth to inject jwt guard
        $this->app['auth']->extend('kenkokalarajwt', function ($app, $name, array $config) {
            $guard = new JwtGuard(
                $app['auth']->createUserProvider($config['provider']),
                $app['request']
            );
            $app->refresh('request', $guard, 'setRequest');
            return $guard;
        });

        // Install config on vendor:publish
        $this->publishes([
            __DIR__ . '/../../../../config/kenkokalarajwt.php' => config_path('kenkokalarajwt.php')
        ], 'kenkokalarajwt-config');
    }
}