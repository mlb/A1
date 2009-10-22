<?php
class A1_Sprig extends A1 {
        /**
         * Return a static instance of A1_Sprig.
         *
         * @return  object
         */
        public static function instance($_name = 'a1')
        {
                static $_instances;

                if ( ! isset($_instances[$_name]))
                {
                        $_instances[$_name] = new A1_Sprig($_name);
                }

                return $_instances[$_name];
        }


	protected function dba_load_user_by_token($user_id, $token) {
		$user = Sprig::factory($this->_config['user_model'], array(
					$this->_config['columns']['token'] => $token,
					$this->pk => $user_id));
		$user->load();

		if($user->loaded()) {
			return $user;
		} else {
			return null;
		}
	}

	protected function dba_load_user_by_username($username) {
		$user = Sprig::factory($this->_config['user_model'], array(
					$this->_config['columns']['username'] => $username));
		$user->load();

		if($user->loaded()) {
			return $user;
		} else {
			return null;
		}
	}

	protected function dba_set_user_token($user, $token) {
		$user->{$this->_config['columns']['token']} = $token;
	}

	protected function dba_set_user_last_login($user, $time) {
		$user->{$this->_config['columns']['last_login']} = $time;
	}

	protected function dba_increment_user_logins($user) {
		$user->{$this->_config['columns']['logins']}++;
	}

	protected function dba_save_user($user) {
		$user->update();
	}

	protected function dba_validate_user_password($user, $password) {
		return ($user->{$this->_config['columns']['password']} == $password);
	}

} // End A1_Sprig
