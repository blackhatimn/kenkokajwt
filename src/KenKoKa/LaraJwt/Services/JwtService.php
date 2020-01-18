<?php

namespace KenKoKa\LaraJwt\Services;

use Exception;
use Lcobucci\JWT\Builder as JwtBuilder;
use Lcobucci\JWT\Claim\EqualsTo;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\BaseSigner;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use KenKoKa\LaraJwt\Exceptions\InvalidJwtException;

class JwtService implements IJwtService
{
    /**
     * @var JwtBuilder
     */
    private $builder;

    /**
     * @var Parser
     */
    private $parser;

    /**
     * @var BaseSigner
     */
    private $signer;

    /**
     * JwtService constructor.
     */
    public function __construct()
    {
        $this->builder = app(JwtBuilder::class);
        $this->parser = app(Parser::class);
        $this->signer = app('kenkokalarajwt.signer');
    }

    /**
     * @inheritdoc
     */
    public function generate(array $claims = [], string $key): string
    {
        $this->builder->unsign();

        foreach ($claims as $name => $value) {
            $this->builder->set($name, $value);
        }

        return $this->builder->sign($this->signer, $key)->getToken();
    }

    /**
     * @inheritdoc
     */
    public function parse(string $jwt, string $key, ValidationData $validationData = null): array
    {
        try {
            /** @var Token $data */
            $data = $this->parser->parse($jwt);
        } catch (Exception $e) {
            throw new InvalidJwtException($e->getMessage(), 0, $e);
        }

        if ($validationData && $data->validate($validationData) == false) {
            throw new InvalidJwtException('Jwt validation failed.');
        }

        if ($data->verify(app('kenkokalarajwt.signer'), $key) == false) {
            throw new InvalidJwtException('Jwt verification failed.');
        }

        $claims = [];

        /** @var EqualsTo $claim */
        foreach ($data->getClaims() as $claim) {
            $claims[$claim->getName()] = $claim->getValue();
        }

        return $claims;
    }
}