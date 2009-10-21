<?php

/* 
 * Abstract A1 Authentication User Model
 * To be extended and completed to user's needs
 * (see a2acldemo/classes/model/user.php for an example implementation)
 */

abstract class Model_A1_Sprig_User extends Sprig {

	// A1 config file name
	protected $_config = 'a1';

	// user model (from config)
	protected $_user_model;

	// user columns (from config)
	protected $_columns;

	public function __construct($id = NULL)
	{
		$this->_columns          = Kohana::config($this->_config)->columns;
		$this->_user_model       = Kohana::config($this->_config)->user_model;

		parent::__construct($id);
	}

	public function update()
	{
		$passcol = $this->_columns['password'];

		if($this->changed($passcol))
		{
			$this->$passcol = A1_Sprig::instance($this->_config)->hash_password($this->$passcol);
		}

		return parent::update();
	}
}
