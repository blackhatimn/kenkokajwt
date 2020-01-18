<?php

namespace KenKoKa\LaraJwtTests\Classes\Models;

use Illuminate\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

class Person extends Model implements \Illuminate\Contracts\Auth\Authenticatable
{
    use Authenticatable;
}