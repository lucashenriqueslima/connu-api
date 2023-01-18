<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    public function register(Request $request)
    {

        // $request->validate([
        //     'name' => 'string',
        //     'cpf' => 'string',
        //     'email' => 'required|string|email|unique:users',
        //     'phone' => 'string',
        //     'password' => 'string|confirmed'
        // ]);

        $request->validate([
            'email' => 'required|string|email|unique:users',
            'password' => 'string|confirmed'
        ]);

        $user = User::create([
            'email' => $request->email,
            'password' => bcrypt($request->password)
        ]);

        $token = $user->createToken('auth_token')->plainTextToken;

        $user->token = $token;

        $response = [
            'status' => 'success',
            'user' => $user,
        ];

        return response($response, 201);
    }

    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response([
                'status' => 'error',
                'message' => 'Email ou senha incorreto(s).',


            ], 401);
        }

        $token = $user->createToken('auth_token')->plainTextToken;

        $user->token = $token;

        $response = [
            'status' => 'success',
            'user' => $user,
        ];

        return response($response, 201);
    }

    public function logout(Request $request)
    {
        auth()->user()->tokens()->delete();
        return [
            'message' => 'Loggout realizado com sucesso.'
        ];
    }
}
