<?php

namespace KenKoKa\LaraJwt\Services;

use Lcobucci\JWT\ValidationData;

interface IJwtService
{
    /**
     * Generate jwt from the given array of claims
     *
     * @param array $claims
     * @param string $key
     *
     * @return string
     */
    public function generate(array $claims, string $key): string;

    /**
     * Parse (and validate) jwt to extract claims
     *
     * @param string $jwt
     * @param string $key
     * @param ValidationData|null $validationData
     *
     * @return string[]
     */
    public function parse(string $jwt, string $key, ValidationData $validationData = null): array;
}