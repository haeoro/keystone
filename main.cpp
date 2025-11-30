/*
	A program that takes arguments (path),(privilege level) in order to run a program at the users desired level of privilege without having to
	have administrator privileges on the given account I.E, standard user.
*/

#include <iostream>
#include <windows.h>

int main()
{
	SECURITY_DESCRIPTOR secDescriptor{}; // contains info such as, owner, group, Sacl, Dacl, control. (Important)

	// SID structure stuff
	SID_IDENTIFIER_AUTHORITY sia{
		5
	};
	SID si{};

	BOOL sidInit = AllocateAndInitializeSid(
		&sia,
		1,
		1,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		&si
	);
	// END OF
	SECURITY_ATTRIBUTES secAttribs // this gets passed as a pointer to this struct as an argument to CreateProcessA() function.
	{
		sizeof(SECURITY_ATTRIBUTES),
		&secDescriptor, // pointer to the SECURITY_DESCRIPTOR struct.
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

	when a user logs in, the os collect	s a set of data on the user that uniquely identifies the said user. 
	It then stores the set in an access token. I think I should try my luck with trying to create a fake security 
	descriptor. 

		to-do
	
	~ firstly, we need a SID structure to identify the user we want to impersonate (high level user), we need to use the function 
	AllocateAndIntializeSid in order to set the structure members for it. 

	~ first step will satisfy the first structure member of SECURITY_DESCRIPTOR. I will need to check the other members 
	and set them accordingly. 

	Notes: 
	~ complete each step, sequentially. 

	~ look further into SID data structure. 
*/
