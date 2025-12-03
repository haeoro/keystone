/*
	A program that takes arguments (path),(privilege level) in order to run a program at the users desired level of privilege without having to
	have administrator privileges on the given account I.E, standard user.
*/

#include <iostream>
#include <windows.h>

int main()
{
	SECURITY_DESCRIPTOR secObjInfo{}; // contains info such as, owner, group, Sacl, Dacl, control. (Important)

	// SID structure stuff
	SID_IDENTIFIER_AUTHORITY sia
	{
		5
	};
	PSID si{};

	BOOL sid = AllocateAndInitializeSid(
		&sia, 
		1,
		SECURITY_WORLD_RID,
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

	// set owner

	BOOL SetSecurityDescriptorOwner(

	// end 

	SECURITY_ATTRIBUTES procAttribs // this gets passed as a pointer to this struct as an argument to CreateProcessA() function.
	{
		sizeof(SECURITY_ATTRIBUTES),
		&secObjInfo, // pointer to the SECURITY_DESCRIPTOR struct.
		FALSE // tells us whether the security_attributes is inheritable.
	};



	STARTUPINFOA sInfo{ 0 }; // startup structure initialized to 0 to pass to CreateProcessA() (default)
	PROCESS_INFORMATION pInfo{ 0 }; // proc info initialized to 0 to pass it to the CreateProcessA() structure (default)


	BOOL mainProc = CreateProcessA(
		NULL,
		(LPSTR)"C:\\Windows\\System32\\cmd.exe", // path to application to be run
		&procAttribs, // pointer to SECURITY_ATTRIBUTES struct here (defines descriptor).
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
	
	~ initialize all members of SECURITY_DESCRIPTOR except for the first three struct members. 

*/
