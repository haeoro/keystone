/*
	A program that takes arguments (path),(privilege level) in order to run a program at the users desired level of privilege without having to
	have administrator privileges on the given account I.E, standard user.
*/

#include <iostream>
#include <windows.h>

int main()
{
	SECURITY_DESCRIPTOR secDescriptor{};// we must use a function to manipulate, or set the data in this struct.

	SECURITY_ATTRIBUTES secAttribs // this gets passed as a pointer to this struct as an argument to CreateProcessA() function.
	{
		sizeof(SECURITY_ATTRIBUTES),
		&secDescriptor, // pointer to the SECURITY_DESCRIPTOR struct 
		FALSE // tells us whether the security_attributes is inheritable.
	};



	STARTUPINFOA sInfo{ 0 }; // startup structure initialized to 0 to pass to CreateProcessA() (default)
	PROCESS_INFORMATION pInfo{ 0 }; // proc info initialized to 0 to pass it to the CreateProcessA() structure (default)


	BOOL mainProc = CreateProcessA(
		NULL,
		(LPSTR)"C:\\Windows\\System32\\cmd.exe", // path to application to be run
		&secAttribs, // pointer to SECURITY_ATTRIBUTES struct here (defines descriptor).
		// we haven't done any customizations for anything else up to this point.
		NULL,
		FALSE,
		CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&sInfo,
		&pInfo
	);
}


/*
		what i know.

	when a user logs in, the os collects a set of data on the user that uniquely identifies the said user. 
	It then stores the set in an access token. I think I should try my luck with trying to create a fake security 
	descriptor. 

		to-do

	1. look into windows functions that define struct members for SECURITY_DESCRIPTOR instead of just initializing it with
	default values.

	Note: you need multiple windows functions to set all members of the SECURITY_DESCRIPTOR structure. Strange, but we'll make it work. 

	2. reference that microsoft article that I emailed to myself.
*/
