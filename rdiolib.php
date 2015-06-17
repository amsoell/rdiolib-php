<?php
# Quick and dirty Rdio class implementing OAuth2
#
# Copyright (c) 2015 Ying Zhang
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

class RdioLib
{
	private $client_id              = '';
	private $client_secret          = '';
	private $redirect_uri           = '';
	private $authorization_endpoint = 'https://www.rdio.com/oauth2/authorize';
	private $token_endpoint         = 'https://services.rdio.com/oauth2/token';
	private $api_endpoint           = 'https://services.rdio.com/api/1/';

	/**
	 * Constructor
	 *
	 * @access public
	 * @param $client_id
	 * @param $client_secret
	 * @param $redirect_uri
	 */

	public function __construct($client_id, $client_secret, $redirect_uri)
	{
		$this->client_id = $client_id;
		$this->client_secret = $client_secret;
		$this->redirect_uri = $redirect_uri;
	}

	/**
	 * Returns true if OAuth2 authentication successful
	 *
	 * @access private
	 * @return boolean
	 */
	public function is_authenticated() {
		return isset($_SESSION["rdioOauth2expires"]) && $_SESSION["rdioOauth2expires"] > time();
	}

	/**
	 * Returns true if OAuth2 authenticated, but access token has expired
	 *
	 * @access private
	 * @return boolean
	 */
	private function is_accesstoken_expired() {
		return isset($_SESSION["rdioOauth2expires"]) && $_SESSION["rdioOauth2expires"] <= time();
	}


	/**
	 * Set session variables after successful OAuth handshake
	 *
	 * @access private
	 * @param object $auth
	 */
	private function set_oauth_session($auth)
	{
		unset($_SESSION["rdioOauth2state"]);

		if (!empty(@$auth->access_token))
		{
			$_SESSION["rdioOauth2auth"] = $auth;
			$_SESSION["rdioOauth2expires"] = time() + $auth->expires_in;

		}
		else
		{
			unset($_SESSION["rdioOauth2auth"]);
		}
	}

	/**
	 * Performs OAuth2 authentication handshake, returns true if successful.
	 *
	 * @access public
	 * @return boolean
	 */
	public function authenticate()
	{
		if ($this->is_authenticated())
		{
			return true;

		}
		elseif ($this->is_accesstoken_expired())
		{
			$ch = curl_init($this->token_endpoint);
			curl_setopt($ch, CURLOPT_POST, true);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
			curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
			curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
				'grant_type'    => 'refresh_token',
				'refresh_token' => $_SESSION['oauth2auth']->refresh_token
				]));
			curl_setopt($ch, CURLOPT_HTTPHEADER, [
			  'Content-type: application/x-www-form-urlencoded',
			  'Authorization: Basic '.base64_encode($this->client_id .  ':' . $this->client_secret)
			  ]);
			$result = curl_exec($ch);
			curl_close($ch);
			$result = json_decode($result);
			$this->set_oauth_session($result);

		}
		elseif (isset($_SESSION["rdioOauth2state"]) && !empty($_GET['code']) && !empty($_GET['state']) && $_GET['state'] == $_SESSION['rdioOauth2state'])
		{
			$ch = curl_init($this->token_endpoint);
			curl_setopt($ch, CURLOPT_POST, true);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
			curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
			curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
				'grant_type'   => 'authorization_code',
				'code'         => $_GET['code'],
				'redirect_uri' => $this->redirect_uri
				]));
			curl_setopt($ch, CURLOPT_HTTPHEADER, [
				'Content-type: application/x-www-form-urlencoded',
				'Authorization: Basic '.base64_encode($this->client_id .  ':' . $this->client_secret)
				]);
			$result = curl_exec($ch);
			curl_close($ch);
			$result = json_decode($result);
			$this->set_oauth_session($result);

		}
		else
		{
			$_SESSION['rdioOauth2state'] = md5(uniqid());
			$params = [
				'response_type' => 'code',
				'client_id'     => $this->client_id,
				'redirect_uri'  => $this->redirect_uri,
				'state'         => $_SESSION["rdioOauth2state"]
				];
			$url = $this->authorization_endpoint . '?' . http_build_query($params, null, '&');
			header("Location: $url");
			die;
		}

		return isset($_SESSION["rdioOauth2auth"]);
	}

	/**
	 * Magic function to invoke Rdio Web APIs
	 *
	 * @access public
	 * @param string $method method name
	 * @param array $params method parameters
	 * @return JSON object
	 */
	public function __call($method, $params=array())
	{
		$params['method'] = $method;
		$ch = curl_init($this->api_endpoint);
		curl_setopt($ch, CURLOPT_POST, true);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
		curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
		curl_setopt($ch, CURLOPT_HTTPHEADER, [
			'Content-type: application/x-www-form-urlencoded',
			'Authorization: Bearer '.$_SESSION["rdioOauth2auth"]->access_token
			]);
		$result = curl_exec($ch);
		curl_close($ch);
		return json_decode($result);
	}
}
