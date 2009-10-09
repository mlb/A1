<?php
/**
 * User AUTHENTICATION library. Handles user login and logout, as well as secure
 * password hashing.
 *
 * Based on Kohana's AUTH library and Fred Wu's AuthLite library:
 *
 * @package    Auth
 * @author     Kohana Team
 * @copyright  (c) 2007 Kohana Team
 * @license    http://kohanaphp.com/license.html
 *
 * @package    Layerful
 * @subpackage  Modules
 * @author    Layerful Team <http://layerful.org/>
 * @author    Fred Wu <fred@beyondcoding.com>
 * @copyright  BeyondCoding
 * @license    http://layerful.org/license MIT
 * @since    0.3.0
 */
class A1 {

	protected $_name;
	protected $_config;
	public $_sess;

	/**
	 * Return a static instance of A1.
	 *
	 * @return  object
	 */
	public static function instance($_name = 'a1')
	{
		static $_instances;

		if ( ! isset($_instances[$_name]))
		{
			$_instances[$_name] = new A1($_name);
		}

		return $_instances[$_name];
	}

	/**
	 * Loads Session and configuration options.
	 *
	 * @return  void
	 */
	public function __construct($_name = 'a1')
	{
		$this->_name       = $_name;
		$this->_config     = Kohana::config($_name);
		$this->_sess       = Session::instance( $this->_config['session_type'] );
		
		// Clean up the salt pattern and split it into an array
		$this->_config['salt_pattern'] = preg_split('/,\s*/', $this->_config['salt_pattern']);

		// Generate session key
		$this->_config['session_key'] = 'a1_' . $this->_name;
	}

	/**
	 * Returns TRUE is a user is currently logged in
	 *
	 * @return  boolean
	 */
	public function logged_in()
	{
		return is_object($this->get_user());
	}

	/**
	 * Returns the user - if any
	 *
	 * @return  object / FALSE
	 */
	public function get_user()
	{
		// Get the user from the session
		$user = $this->_sess->get($this->_config['session_key']);

		// User found in session, return
		if(is_object($user))
		{
			return $user;
		}

		// Look for user in cookie
		if( $this->_config['lifetime'])
		{
			if ( ($token = cookie::get('a1_'.$this->_name.'_autologin')) )
			{
				$token = explode('.',$token);

				if (count($token) === 2 AND is_string($token[0]) AND is_numeric($token[1]))
				{
					// Search user on user ID (indexed) and token
					$user = ORM::factory($this->_config['user_model'])->where($this->_config['columns']['token'],'=',$token[0])->find($token[1]);

					/*$user = Mango::factory($this->_config['user_model'],array(
						'_id'   => $token[1],
						'token' => $token[0]
					))->load();*/

					// Found user, complete login and return
					if ($user->loaded())
					{
						$this->complete_login($user,TRUE);
						return $user;
					}
				}
			}
		}

		// No user found, return false
		return FALSE;
	}

	protected function complete_login($user, $remember = FALSE)
	{
		if ($remember === TRUE AND $this->_config['lifetime'])
		{
			// Create token
			$token = text::random('alnum', 32);
			
			$user->{$this->_config['columns']['token']} = $token;
			
			//cookie::set('a1_'.$this->_name.'_autologin', $token . '.' . $user->primary_key_value, $this->_config['lifetime']);
			cookie::set('a1_'.$this->_name.'_autologin', $token . '.' . $user->id, $this->_config['lifetime']);
		}

		if(isset($this->_config['columns']['last_login']))
		{
			$user->{$this->_config['columns']['last_login']} = time();
		}
		
		if(isset($this->_config['columns']['logins']))
		{
			$user->{$this->_config['columns']['logins']}++;
		}

		$user->save();
		//$user->update();

		// Regenerate session (prevents session fixation attacks)
		$this->_sess->regenerate();
		
		$this->_sess->set($this->_config['session_key'], $user);
	}

	/**
	 * Attempt to log in a user by using an ORM object and plain-text password.
	 *
	 * @param   string   username to log in
	 * @param   string   password to check against
	 * @param   boolean  enable auto-login
	 * @return  boolean
	 */
	public function login($username, $password, $remember = FALSE)
	{
		if (empty($password))
		{
			return FALSE;
		}

		$user = is_object($username)
			? $username
			: ORM::factory($this->_config['user_model'], array( $this->_config['columns']['username'] => $username) );

		/*$user = is_object($username)
			? $username
			: Mango::factory($this->_config['user_model'],array(
					$this->_config['columns']['username'] => $username,
					'account_id'                          => Request::$account->_id
				))->load();*/

		if ( $user->loaded())
		{
			$salt = $this->find_salt($user->{$this->_config['columns']['password']});
	
			if($this->hash_password($password, $salt) === $user->{$this->_config['columns']['password']})
			{
				$this->complete_login($user,$remember);
	
				return TRUE;
			}
		}

		return FALSE;
	}

	/**
	 * Log out a user by removing the related session variables.
	 *
	 * @param   boolean  completely destroy the session
	 * @return  boolean
	 */
	public function logout($destroy = FALSE)
	{
		if (cookie::get('a1_'.$this->_name.'_autologin'))
		{
			cookie::delete('a1_'.$this->_name.'_autologin');
		}
		
		if ($destroy === TRUE)
		{
			// Destroy the session completely
			$this->_sess->destroy();
		}
		else
		{
			// Remove the user from the session
			$this->_sess->delete($this->_config['session_key']);

			// Regenerate session_id
			$this->_sess->regenerate();
		}

		return ! $this->logged_in();
	}

	/**
	 * Creates a hashed password from a plaintext password, inserting salt
	 * based on the configured salt pattern.
	 *
	 * @param   string  plaintext password
	 * @return  string  hashed password string
	 */
	public function hash_password($password, $salt = FALSE)
	{
		if ($salt === FALSE)
		{
			// Create a salt seed, same length as the number of offsets in the pattern
			$salt = substr($this->hash(uniqid(NULL, TRUE)), 0, count($this->_config['salt_pattern']));
		}

		// Password hash that the salt will be inserted into
		$hash = $this->hash($salt.$password);

		// Change salt to an array
		$salt = str_split($salt, 1);

		// Returned password
		$password = '';

		// Used to calculate the length of splits
		$last_offset = 0;

		foreach ($this->_config['salt_pattern'] as $offset)
		{
			// Split a new part of the hash off
			$part = substr($hash, 0, $offset - $last_offset);

			// Cut the current part out of the hash
			$hash = substr($hash, $offset - $last_offset);

			// Add the part to the password, appending the salt character
			$password .= $part.array_shift($salt);

			// Set the last offset to the current offset
			$last_offset = $offset;
		}

		// Return the password, with the remaining hash appended
		return $password.$hash;
	}

	/**
	 * Perform a hash, using the configured method.
	 *
	 * @param   string  string to hash
	 * @return  string
	 */
	public function hash($str)
	{
		return hash($this->_config['hash_method'], $str);
	}

	/**
	 * Finds the salt from a password, based on the configured salt pattern.
	 *
	 * @param   string  hashed password
	 * @return  string
	 */
	public function find_salt($password)
	{
		$salt = '';

		foreach ($this->_config['salt_pattern'] as $i => $offset)
		{
			// Find salt characters, take a good long look...
			$salt .= substr($password, $offset + $i, 1);
		}

		return $salt;
	}

} // End A1