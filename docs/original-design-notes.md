Client:
1.	Ask him to:
a.	log in: 
1.	will be limited using for loop.
2.	if he enters the right info (user name and password) he will do the things he is authorized to do (The normal client can request only UPLOAD, DOWNLOAD and LIST on their own files. The super client can request any command on any file), the info will be compared with the SQL database. 
3.	we will compare the hashed password with the hash function of the stored salt of that username and the entered password from the client.
4.	the super client is stored manually in the database he just needs to log in.
5.	every time a client log in a session key is generated and stored in the both the client and the server (database) whenever the client try to do something hi should provide his session key to the server and the last should compare that session key with the one in the database.
b.	sign in:
1.	will ask for his username and a password and to confirm his password and generate a salt and using a hash function to generate a hashed password (we will store the salt and the hashed password).
2.	normal client:
1.	-will have its separate class and it will contain only UPLOAD, DOWNLOAD and LIST
3.	Super client:
1.	Can see all the files and modify or delete any of them.







Server:
1.	The server will receive a connection and pass him to a thread 
2.	First will check his username and password (like I said above about salt and hashed password and all of that stuff)
3.	If it’s a super client will handle it differently  with his own class so as the normal client
4.	Will constantly log the activities that have been done by the clients
5.	Handle the errors effeciantly


















Clientmain{
Loop{
	Let user enter an operation 
Send the operation to the server
	If operation is login
		Let the login class handle him
			And let the login class return indicator if it was successful or not
If it wasn’t successful don’t let him try to log in for 5 minutes 
	else If operation is signup
		let the signup class handle him
	else if operation was exit 
		exit
	else 
bad operation
}
}
Login{
	Check the ip address and time{
	Send the IP address and time 
Receive an indicator
}
	If the indicator was fail
		Return fail

	Else if the indicator was success:
{
	Loop for a certain time{
	Let him enter his user name and password
Chick username and password by sending them to server and retrieve the answer back
If the answer was success {
	Receive an indicator for the type of client
	Receive the session key
	If the type of client was normal 
		Let the normal class handle him
		Return success
	
Else if the type of client was admin 
		Let the admin class handle him
		Return success
}
Else {
	A message to tell the user that the entry was wrong pleas try again
If it was the last attempt{
Print a message to tell the user he cant login for 5 minutes
	Return fail
}
		}
}
}
}
Signup{
Loop{
		Let the user enter his username 
		Chick if the username exist 
If exist{
	Ask him to enter it again
}
Else exit
}
	
Ask him to enter his password and to confirm his password
	Send the username and password to the server to store them in the database 
}
Normal{
	Loop{
		
	Let the user choose the operation
	If operation was logout{
	Send operation type and session key 
	break
}
	If operation was list{
		Send operation type and session key to the server
		Receive Session key
		If(server session key==session key){	
Receive the answer by its username
			Print the answer
		}
		Else {
	Receive and discard
}
	}




	Else if the operation was upload{
		Ask the user to enter the file path
		If path exist{
			Send operation type and session key to the server
			Send the file
			Print the transfer was successful
}
Else{
	Change operation type to nothing
	Send the operation type and session key to the server
	Print that the file doesn’t exist
}
}
Else if the operation type was download{
	Send operation type and session key to the server
	session key to the server
if (server session key == session key){
Send the file name 
Receive the file based on his username
Print the receive was successful
}
Else{
	Receive and discard
}
}
Else if the operation type was delete{
	Send operation type and session key to the server
	Send the file name and session key to the server
	Receive session key
	If(server session key==session key){
		Receive the answer based on 
				1-username
				2-if file exist
		If answer was fail Print the deletion was unsuccessful
Else print the deletion was successful
			}
			Else{
Receive and discard
}
}
Else{
	Print bad operation enter it again
}
}
}
Admin{
	Loop{
	Let the user choose the operation
	If operation was logout{
	Send operation type and session key 
	break
}
	else If operation was list{
		Send operation type and session key to the server
		Receive session key
		If(server session key==session key){
			Receive the answer 
			Print the answer
		}
		Else{
Receive and discard
}
	}
	Else if the operation was upload{
		Ask the user to enter the path of the file 
		If path exist{
			Send operation type and session key to the server
			Send the file
			Print the transfer was successful
}
Else{
	Change operation type to nothing
	Send the operation type and session key to the server
	Print that the file doesn’t exist
}
}
Else if the operation type was download{
	Send operation type and session key to the server
	Send the file name and file owner and session key to the server
	Receive the session key
	If(server session key == session key){
Receive the file 
Print the receive was successful
			}
			Else{
	Receive and discard
}
}

Else if the operation type was delete{
	Send operation type and session key to the server
	Send the file name and file owner and session key to the server
	Receive the session key
	If(server session key == session key){
Receive the answer based on if file exist
		If answer was fail Print the deletion was unsuccessful
Else print the deletion was successful
			}
			Else{
	Receive and discard
}

}
Else{
	Print bad operation enter it again
}
}
}









Servermain{
	Loop{
		Listen to the port
		Send the client to the Handleclient class
}
}
Handleclient{
	Receive the connection from Servermain
	Crat new thread{
		Receive the opreration from the client
		If operation was login{
	Let the login class handle him
}
Else If operation was signup{
	Let the signup class handle him
}
}
}
Login{
	Receive the IP address and time
	Chick if the ip exist in the database
	If they exist{
	variable Time = Current time – DBtime
	If Time  < 5 minutes{
	Send  fail
	Return //cut connection
}
If Time  >= 5 minutes{
	send success
}
}
Else{
	Boolean logged = false
	//check user name and password
	Loop for a certain time{
	Receive username
If username exist{
Receive password
		Get the salt from the database
		Get the hashed password from the database
		Hash = hash function(password , salt)
		 If (hashed password == hash){
			Return success
			Logged=true      
//logging		Add time and username and “login” to the logging table
			Break
		}
}
Else{
	Return fail
}
If it is the last time{
	 
	Insert ip and time into the table block
//logging		Add time and IP and “block” to the logging table
}
}
If(logged){
	Type  //get it from the login table
Generate a session key and store it in the session key table along with username
	Send session key
	If type was normal{
	Let the normal class handle him
}
If type was admin{
	Let the admin class handle him
}

}
}
}

Normal{
	Loop{
		Receive the operation
		Receive session key
		Get the session key from the database
If(session key == dbsession key){
			If operation was logout{
				Add time, username and “logged out” to logging table
				Return 		//leave
			}
			Else if operation was list{
				Get the file names from the file table based on user name
				Send session key
				Send the file names
				Add time, username and “listed files” to logging table
}
Else if operation was upload{
	Receive the filename
	Receive the file 
	Keep the file in the database
				Add time, username and “upload”+filename to logging table

} 
Else if operation was download{
	Send the session key 
	Send the file
}
Else if operation was delete{
	Receive filename
	Send session key
	If file exist{
	Delete the file
	Send success
}
If not{
	Send fail
}
	
}

Else if operation was nothing: do nothing
}
		Else{
	return
}
}
}



Admin{
	Loop{
		Receive the operation
		Receive session key
		Get the session key from the database
If(session key == dbsession key){
			If operation was logout{
				Add time, username and “logged out” to logging table
				Return 		//leave
			}
			Else if operation was list{
				Get all the file names from the file table
				Send session key
				Send the file names
}
Else if operation was upload{
	Receive the filename
	Receive the file 
	Keep the file in the database
} 
Else if operation was download{
	Send the session key 
	Send the file
}
Else if operation was delete{
	Receive filename
	Send session key
	If file exist{
	Delete the file
	Send success
}
If not{
	Send fail
}
	
}

Else if operation was nothing: do nothing
}
		Else{
	return
}
}
}




Signup{
	username
	Loop{
	Receive username
	Chick if username is in the database
	If its not in the database
	{
		Send not exist
	break
}
Else{
	Send exist
}
}
Receive the password
Generate salt 
Hashed password = hash function(password, salt )
Add the username and salt and hashed password to the database
}




