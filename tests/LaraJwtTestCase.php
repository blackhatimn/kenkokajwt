<?php

namespace KenKoKa\LaraJwtTests;

use Faker\Factory as FakerFactory;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Str;
use KenKoKa\LaraJwt\Providers\ServiceProvider;
use Mockery;
use Orchestra\Testbench\TestCase;

class LaraJwtTestCase extends TestCase
{
    /**
     * @var \Faker\Generator $faker
     */
    protected $faker;

    /**
     * @inheritdoc
     */
    public function setUp() :void
    {
        parent::setUp();

        $_ENV['APP_ENV'] = 'testing';

        $this->faker = FakerFactory::create();
    }

    /**
     * @inheritdoc
     */
    protected function getPackageProviders($app)
    {
        return [ServiceProvider::class];
    }

    /**
     * @inheritdoc
     */
    protected function getEnvironmentSetUp($app)
    {
        // Config
        $app['config']->set('kenkokalarajwt.key', $this->key());
        $app['config']->set('kenkokalarajwt.ttl', 60 * 60 * 24 * 30);
        $app['config']->set('kenkokalarajwt.issuer', 'The Issuer');
        $app['config']->set('kenkokalarajwt.audience', 'The Audience');
        $app['config']->set('kenkokalarajwt.model_safe', false);
    }

    /**
     * Generate JWT Key (Singleton)
     *
     * @return string
     */
    protected function key(): string
    {
        return $_ENV['JWT_KEY'] ?? $_ENV['JWT_KEY'] = Str::random(32);
    }

    /**
     * Generate a brand new user
     *
     * @return User
     */
    protected function generateUser(): User
    {
        $id = $this->faker->numberBetween(1, 1000);

        $user = app(User::class);

        $idFieldName = $user->getAuthIdentifierName();
        $user->setAttribute($idFieldName, $id);

        return $user;
    }

    /**
     * Mock User Provider service
     *
     * @param Authenticatable $user
     * @return Authenticatable
     */
    protected function mockUserProvider(Authenticatable $user): Authenticatable
    {
        $userProviderMock = Mockery::mock(EloquentUserProvider::class)
            ->shouldReceive('retrieveById')->withArgs([$user->getAuthIdentifier()])
            ->andReturn($user)
            ->getMock();

        $this->app[EloquentUserProvider::class] = $userProviderMock;

        return $user;
    }
}