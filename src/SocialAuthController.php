<?php

namespace RicLeP\SocialLogin;

use Laravel\Socialite\Facades\Socialite;
use App\Spark;
use Illuminate\Http\Request;

use App\Http\Controllers\Controller;

class SocialAuthController extends Controller
{
    public function redirectToProvider($provider)
    {
        return Socialite::driver($provider)->stateless()->redirect();
    }

    public function handleProviderCallback(SocialAccountService $service, $provider)
    {
        $user = $service->createOrGetUser(Socialite::driver($provider)->stateless());

        auth()->login($user);

        if (Spark::usesTwoFactorAuth() && $user->uses_two_factor_auth) {
            auth()->logout();

            // Before we redirect the user to the two-factor token verification screen we will
            // store this user's ID and "remember me" choice in the session so that we will
            // be able to get it back out and log in the correct user after verification.
            session()->put([
                'spark:auth:id' => $user->id,
            ]);

            return redirect('login/token');
        }

        return redirect()->to('/home');
    }
}
