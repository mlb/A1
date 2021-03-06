<?php
class A1_ORM extends A1 {
        /**
         * Return a static instance of A1_ORM.
         *
         * @return  object
         */
        public static function instance($_name = 'a1')
        {
                static $_instances;

                if ( ! isset($_instances[$_name]))
                {
                        $_instances[$_name] = new A1_ORM($_name);
                }

                return $_instances[$_name];
        }


	protected function dba_load_user_by_token($user_id, $token) {
		$user = ORM::factory($this->_config['user_model'])
			->where($this->_config['columns']['token'],'=',$token)
			->find($user_id);
		if($user->loaded()) {
			return $user;
		} else {
			return null;
		}
	}

	protected function dba_load_user_by_username($username) {
		$user = ORM::factory($this->_config['user_model'])
			->where($this->_config['columns']['username'],'=',$username);
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
		$user->save();
	}

        protected function dba_validate_user_password($user, $password) {
                $password_in_db = $user->{this->_config['columns']['password']};
                $salt = $this->find_salt($password_in_db);
                
                if($this->hash_password($password, $salt) === $password_in_db)
                {       
                        return true;
                }

                return false;
        }
} // End A1_ORM
