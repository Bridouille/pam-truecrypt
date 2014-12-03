Plugable Authentication Module
----------------------------------------
This module open a truecrypt volume in the home directory of a user when he login, and close it when he logout.

Installation:
-------------

Clone the repo, then compile the module.

    $ git clone git@github.com:Bridouille/pam-truecrypt.git
    $ cd pam-truecrypt
    $ make

Copy the module with the others PAM.
In a Debian x86_64 architecture :

    $ sudo cp my_module.so /lib/x86_64-linux-gnu/security

Then modify the configuration files to add the module in the sessions.

	$ sudo vi /etc/pam.d/common-session

Add the following line at the end of the file :

    session required my_module.so

That's all !

Configuration file
------------------

You can add a *.my_modulerc* file in your home directory.
You can specify few arguments :

    autocreate=true|false

If the container doesn't exist, you can create it automatically.

    volume_name=your_volume_name

Specify the name of the volume from the home path.


Warning
-------

The Module doesn't work with SSH, the conversation function seems to fail everytime.
