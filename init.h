#pragma once
#include <iostream>

class init
{
private:
	SECURITY_DESCRIPTOR secObjInfo{}; // contains info such as, owner, group, Sacl, Dacl, control. (Important)
public:
	void initializeSecurityDescriptor() 
	{
		// SID structure stuff
		SID_IDENTIFIER_AUTHORITY sia
		{
			5
		};
		PSID si{}; // this security identification object determines what level of authority we have. 

		BOOL sid = AllocateAndInitializeSid( // function to initialize our 
			&sia,
			1,
			0x000001F4,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			&si
		);
		// END 

		// set revision level and give default initialization to mostly everything else in the struct (SECURITY_DESCRIPTOR). 

		BOOL setRevision = InitializeSecurityDescriptor(
			&secObjInfo,
			SECURITY_DESCRIPTOR_REVISION
		);

		// end 

		// set owner of SECURITY_DESCRIPTOR

		BOOL secDesOwner = SetSecurityDescriptorOwner(
			&secObjInfo,
			&si,
			1
		);

		// end 

		// set group for SECURITY_DESCRIPTOR
		BOOL secDesGroup = SetSecurityDescriptorGroup(
			&secObjInfo,
			&si,
			1
		);

		//end 
		
		// set sacl for SECURITY_DESCRIPTOR
		BOOL setDesSacl = SetSecurityDescriptorSacl(
			&secObjInfo,
			FALSE, 
			NULL, 
			TRUE
		);

		// end

		// set dacl for SECURITY_DESCRIPTOR
		BOOL setDesDacl = SetSecurityDescriptorDacl(
			&secObjInfo,
			FALSE,
			NULL,
			TRUE
		);

		// end

		// checks validity of the SECURITY_DESCRIPTOR object. 
		BOOL checkValidity = IsValidSecurityDescriptor(
			&secObjInfo
		);
		// end


		std::cout << "init sec descriptor error: " << GetLastError() << "\n";
	}

	SECURITY_DESCRIPTOR getSecurityDescriptor() 
	{
		return secObjInfo;
	}
};

/*
	to-do
	
	~ tidy code up.
	~ ensure the initialization of the SECURITY_DESCRIPTOR STRUCT is correct. Use functions to check if it returns a NON zero value. 

*/
