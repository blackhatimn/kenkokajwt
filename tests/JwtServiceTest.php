<?php

namespace KenKoKa\LaraJwtTests;

use Lcobucci\JWT\ValidationData;
use KenKoKa\LaraJwt\Services\IJwtService;
use KenKoKa\LaraJwt\Exceptions\InvalidJwtException;

class JwtServiceTest extends LaraJwtTestCase
{
    /**
     * @test
     */
    public function it_should_generate_a_token_and_parse_it()
    {
        $key = $this->key();
        $claims = $this->generateClaims();

        $jwtService = app(IJwtService::class);
        $jwt = $jwtService->generate($claims, $key);
        $parsedClaims = $jwtService->parse($jwt, $key, new ValidationData());

        $this->assertEquals($claims['iss'], $parsedClaims['iss']);
        $this->assertEquals($claims['sub'], $parsedClaims['sub']);
        $this->assertEquals($claims['aud'], $parsedClaims['aud']);
        $this->assertEquals($claims['nbf'], $parsedClaims['nbf']);
        $this->assertEquals($claims['iat'], $parsedClaims['iat']);
        $this->assertEquals($claims['exp'], $parsedClaims['exp']);
        $this->assertEquals($claims['jti'], $parsedClaims['jti']);
    }

    /**
     * Generate testing claims
     *
     * @return array
     */
    private function generateClaims(): array
    {
        $claims = [];
        $claims['iss'] = 'Issuer';
        $claims['sub'] = 'Subject';
        $claims['aud'] = 'The Audience';
        $claims['nbf'] = (string)time();
        $claims['iat'] = (string)time();
        $claims['exp'] = (string)(time() + 60 * 60 * 24);
        $claims['jti'] = (string)mt_rand(1, 999);

        return $claims;
    }

    /**
     * @test
     * @expectException \KenKoKa\LaraJwt\Exceptions\InvalidJwtException
     */
    public function it_should_raise_an_error_when_token_is_expired()
    {
        $key = $this->key();
        $claims = $this->generateClaims();

        $claims['exp'] = time() - 1;

        $this->expectException(InvalidJwtException::class);

        $jwtService = app(IJwtService::class);
        $jwt = $jwtService->generate($claims, $key);

        $jwtService->parse($jwt, $key, app(ValidationData::class));
    }

    /**
     * @test
     * @expectException \KenKoKa\LaraJwt\Exceptions\InvalidJwtException
     */
    public function it_should_raise_an_error_when_token_is_not_valid()
    {
        $key = $this->key();

        $jwt = 'Invalid Token';

        $this->expectException(InvalidJwtException::class);

        $jwtService = app(IJwtService::class);
        $jwtService->parse($jwt, $key);
    }
}