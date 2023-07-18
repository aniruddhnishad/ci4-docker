<?php

namespace App\Controllers;

use App\Controllers\BaseController;

class Apis extends BaseController
{
    public function index()
    {
        //
    }

    public function hashPassword()
    {

        try {

            $reqBody = $this->request->getJSON(true);

            if ( is_null($reqBody) ) return $this->respond([ 'error' => true, 'data' => 'Please provide password!' ]);
            
            if (!array_key_exists('password', $reqBody)) return $this->respond([ 'error' => true, 'data' => 'Key must be "password"' ]);

            return $this->respond([ 'error' => false, 'data' => $this->utility->HashPassword($reqBody['password']) ]);
            
        } catch (\Throwable $th) {

            return $this->fail([ 'error' => true, 'data' => $th->getMessage() ]);
        }
    }

    public function verifyPassword()
    {

        try {

            $reqBody = $this->request->getJSON(true);

            if ( is_null($reqBody) ) return $this->respond([ 'error' => true, 'data' => 'Please provide password and hashedpassword!' ]);
            
            if (!(array_key_exists('password', $reqBody) && array_key_exists('hashedpassword', $reqBody))) return $this->respond([ 'error' => true, 'data' => 'Key must be "password" and "hashedpassword"' ]);

            return $this->respond([ 'error' => false, 'data' => $this->utility->CheckPassword($reqBody['password'], $reqBody['hashedpassword']) ]);

        } catch (\Throwable $th) {
           
            return $this->fail([ 'error' => true, 'data' => $th->getMessage() ]);
        }
    }

    public function encrypt()
    {
        try {
    
            $reqBody = $this->request->getJSON(true);

            if ( is_null($reqBody) )  return $this->respond([ 'error' => true, 'data' => 'Please provide data!']);
            
            if (!(array_key_exists('data', $reqBody))) return $this->respond([ 'error' => true, 'data' => 'Key must be "data"' ]);
            
            return $this->respond([ 'error' => false,'data' => $this->utility->Encrypt($reqBody['data']) ]);

        } catch (\Throwable $th) {

            return $this->fail([ 'error' => true, 'data' => $th->getMessage() ]);
        }
    }

    public function decrypt()
    {
        try {
    
            $reqBody = $this->request->getJSON(true);

            if ( is_null($reqBody) )  return $this->respond([ 'error' => true, 'data' => 'Please provide data!']);
            
            if (!(array_key_exists('data', $reqBody))) return $this->respond([ 'error' => true, 'data' => 'Key must be "data"' ]);
            
            return $this->respond([ 'error' => false,'data' => $this->utility->Decrypt($reqBody['data']) ]);

        } catch (\Throwable $th) {

            return $this->fail([ 'error' => true, 'data' => $th->getMessage() ]);
        }
    }
}
