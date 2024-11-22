/*----------------------------------------------------------------------------
pa-04_PartTwo:  Intro to Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   amal.c     SKELETON

Written By: 
     1- Kylie Clark 
	 2- Cole Strubhar   (or risk losing points )
Submitted on: 
     Insert the date of Submission here
----------------------------------------------------------------------------*/

#include <linux/random.h>
#include <time.h>
#include <stdlib.h>

#include "../myCrypto.h"

// Generate random nonces for Amal
void  getNonce4Amal( int which , Nonce_t  value )
{
	// Normally we generate random nonces using
	// RAND_bytes( (unsigned char *) value , NONCELEN  );
	// However, for grading purpose, we will use fixed values

	switch ( which ) 
	{
		case 1:		// the first nonce
			value[0] = 0x11223344 ;
			break ;

		case 2:		// the second nonce
			value[0] = 0xaabbccdd ;		
			break ;

		default:	// Invalid agrument. Must be either 1 or 2
			fprintf( stderr , "\n\nAmal trying to create an Invalid nonce\n exiting\n\n");
			exit(-1);
	}
}
	
//*************************************
// The Main Loop
//*************************************
int main ( int argc , char * argv[] )
{
    // Your code from pa-04_PartOne

    int      fd_A2K , fd_K2A , fd_A2B , fd_B2A  ;
    FILE    *log ;

    char *developerName = "Code by Kylie Clark and Cole Strubhar" ;

    fprintf( stdout , "Starting Amal's      %s.\n" , developerName  ) ;
    
    if( argc < 5 )
    {
        printf("\nMissing command-line file descriptors: %s <getFr. KDC> <sendTo KDC> "
               "<getFr. Basim> <sendTo Basim>\n\n" , argv[0]) ;
        exit(-1) ;
    }
    fd_K2A    = atoi(argv[1]) ;  // Read from KDC    File Descriptor
    fd_A2K    = atoi(argv[2]) ;  // Send to   KDC    File Descriptor
    fd_B2A    = atoi(argv[3]) ;  // Read from Basim  File Descriptor
    fd_A2B    = atoi(argv[4]) ;  // Send to   Basim  File Descriptor

    log = fopen("amal/logAmal.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "\nAmal's  %s. Could not create my log file\n" , developerName  ) ;
        exit(-1) ;
    }

    BANNER( log ) ;
    fprintf( log , "Starting Amal\n" ) ;
    BANNER( log ) ;

    fprintf( log , "\n<readFrom KDC> FD=%d , <sendTo KDC> FD=%d , "
                   "<readFrom Basim> FD=%d , <sendTo Basim> FD=%d\n\n" , 
                   fd_K2A , fd_A2K , fd_B2A , fd_A2B );

    // Get Amal's master key with the KDC
    myKey_t  Ka ;  // Amal's master key with the KDC


    // Use  getKeyFromFile( "amal/amalKey.bin" , .... ) )
	// On failure, print "\nCould not get Amal's Masker key & IV.\n" to both  stderr and the Log file
	// and exit(-1)
	// On success, print "Amal has this Master Ka { key , IV }\n" to the Log file
	// BIO_dump the Key IV indented 4 spaces to the righ

    int success = getKeyFromFile("amal/amalKey.bin", &Ka);
    
    if (success < 0) {
        fprintf(stderr, "\nCould not get Amal's Master key & IV.\n");
        fprintf(log, "\nCould not get Amal's Master key & IV.\n");
        exit(-1);
    }

    fprintf(log, "Amal has this Master Ka { key , IV }");
    fprintf( log , "\n" );
	// BIO_dump the IV indented 4 spaces to the righ
    BIO_dump_indent_fp(log, Ka.key, sizeof(Ka.key), 4);
    fprintf(log, "\n");
    BIO_dump_indent_fp(log, Ka.iv, sizeof(Ka.iv), 4);

    // Get Amal's pre-created Nonces: Na and Na2    

	Nonce_t   Na , Na2; 
    getNonce4Amal(1, Na);
    getNonce4Amal(2, Na2);

    fprintf( log , "\nAmal will use these Nonces:  Na  and Na2\n"  ) ;
	// Use getNonce4Amal () to get Amal's 1st and second nonces into Na and Na2, respectively
	// BIO_dump Na indented 4 spaces to the righ
    BIO_dump_indent_fp(log, Na, sizeof(Na), 4);
    fprintf( log , "\n" );
	// BIO_dump Na2 indented 4 spaces to the righ
    BIO_dump_indent_fp(log, Na2, sizeof(Na2), 4);
    fprintf( log , "\n") ; 

    fflush( log ) ;

    //*************************************
    // Construct & Send    Message 1
    //*************************************
    BANNER( log ) ;
    fprintf( log , "         MSG1 New\n");
    BANNER( log ) ;

    char *IDa = "Amal is Hope", *IDb = "Basim is Smiley" ;
    size_t  LenMsg1 ;
    uint8_t  *msg1 ;
    LenMsg1 = MSG1_new( log , &msg1 , IDa , IDb , Na ) ;
    
    // Send MSG1 to KDC via the appropriate pipe
    write(fd_A2K, msg1, LenMsg1);

    fprintf( log , "Amal sent message 1 ( %lu bytes ) to the KDC with:\n    "
                   "IDa ='%s'\n    "
                   "IDb = '%s'\n" , LenMsg1 , IDa , IDb ) ;
    fprintf( log , "    Na ( %lu Bytes ) is:\n" , NONCELEN ) ;
    BIO_dump_indent_fp(log, Na, sizeof(Na), 4);
    fflush( log ) ;

    // Deallocate any memory allocated for msg1
    free(msg1);
    
    
    
    //*************************************
    // Receive   &   Process Message 2
    //*************************************
	// PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG2 Receive\n");
    BANNER( log ) ;

    size_t *lenTktCipher; 
    uint8_t **tktCipher;
    myKey_t Ks;
    
    // Get MSG2 from KDC
    MSG2_receive( log , fd_K2A , &Ka , &Ks, &IDb , &Na , lenTktCipher, tktCipher) ;


    fprintf( log , "\nAmal decrypted message 2 from the KDC into the following:\n") ;
    fprintf( log , "    Ks { Key , IV } (%lu Bytes ) is:\n", sizeof(Ks)) ;
     // BIO_dump the Ks
    BIO_dump_indent_fp(log , &Ks , sizeof(Ks) , 4);
    fprintf( log , "\n    IDb (%lu Bytes):   ..... MATCH\n", strlen(IDb));
    BIO_dump_indent_fp(log , IDb , strlen(IDb) , 4);
    fprintf( log , "\n    Received Copy of Na (%lu bytes):    >>>> VALID\n", NONCELEN);
    BIO_dump_indent_fp(log , Na , sizeof(Na) , 4);
    fprintf( log , "\n    Encrypted Ticket (%lu bytes):\n", *lenTktCipher);
    BIO_dump_indent_fp(log , tktCipher , *lenTktCipher , 4);

    fflush( log ) ;

    //*************************************
    // Construct & Send    Message 3
    //*************************************
	// PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG3 New\n");
    BANNER( log ) ;

    size_t  LenMsg3 ;
    uint8_t  *msg3 ;
    LenMsg3 = MSG3_new( log , &msg3 , *lenTktCipher , *tktCipher , &Na2 ) ;
    
    // Send MSG3 to B via the appropriate pipe
    write(fd_A2B, msg3, LenMsg3);

    fprintf( log , "Amal is sending this to Basim in Message 3:\n") ;
    fprintf( log , "    Na2 in Message 3:\n") ;
    BIO_dump_indent_fp(log, Na2, sizeof(Na), 4);
    fprintf( log , "    The following MSG3 ( %lu bytes ) has been created by MSG3_new ():\n", LenMsg3);
    BIO_dump_indent_fp(log, msg3, LenMsg3, 4);
    fprintf( log , "Amal Sent the Message 3 ( %lu bytes ) to Basim\n", LenMsg3);

    fflush( log ) ;

    // Deallocate any memory allocated for msg1
    free(msg1);

    //*************************************
    // Receive   & Process Message 4
    //*************************************
	// PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG4 Receive\n");
    BANNER( log ) ;

    //*************************************
    // Construct & Send    Message 5
    //*************************************
	// PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG5 New\n");
    BANNER( log ) ;


    //*************************************   
    // Final Clean-Up
    //*************************************  
end_:
    fprintf( log , "\nAmal has terminated normally. Goodbye\n" ) ;  
    fclose( log ) ;
    return 0 ;
}

