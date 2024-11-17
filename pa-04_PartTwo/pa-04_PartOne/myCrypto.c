/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c     SKELETON

Written By: 
     1- Kylie Clark 
	 2- Cole Strubhar   (or risk losing points )
Submitted on: 
    11/06/2024
----------------------------------------------------------------------------*/

#include "myCrypto.h"

//
//  ALL YOUR  CODE FORM  PREVIOUS PAs  and pLABs
//  MUST be Here

//***********************************************************************
// PA-04  Part  One
//***********************************************************************

void exitError( char *errText )
{
    fprintf( stderr , "%s\n" , errText ) ;
    exit(-1) ;
}

//-----------------------------------------------------------------------------
// Utility to read Key/IV from a file
// Return:  1 on success, or 0 on failure

int getKeyFromFile( char *keyF , myKey_t *x )
{
    int   fd_key  ;
    
    fd_key = open( keyF , O_RDONLY )  ;
    if( fd_key == -1 ) 
    { 
        fprintf( stderr , "\nCould not open key file '%s'\n" , keyF ); 
        return 0 ; 
    }

    // first, read the symmetric encryption key
	if( SYMMETRIC_KEY_LEN  != read ( fd_key , x->key , SYMMETRIC_KEY_LEN ) ) 
    { 
        fprintf( stderr , "\nCould not read key from file '%s'\n" , keyF ); 
        return 0 ; 
    }

    // Next, read the Initialialzation Vector
    if ( INITVECTOR_LEN  != read ( fd_key , x->iv , INITVECTOR_LEN ) ) 
    { 
        fprintf( stderr , "\nCould not read the IV from file '%s'\n" , keyF ); 
        return 0 ; 
    }
	
    close( fd_key ) ;
    
    return 1;  //  success
}

//-----------------------------------------------------------------------------
// Allocate & Build a new Message #1 from Amal to the KDC 
// Where Msg1 is:  Len(A)  ||  A  ||  Len(B)  ||  B  ||  Na
// All Len(*) fields are size_t integers
// Set *msg1 to point at the newly built message
// Msg1 is not encrypted
// Returns the size (in bytes) of Message #1 

unsigned MSG1_new ( FILE *log , uint8_t **msg1 , const char *IDa , const char *IDb , const Nonce_t Na )
{

    //  Check agains any NULL pointers in the arguments
    if (log == NULL || msg1 == NULL || *msg1 == NULL || IDa == NULL || IDb == NULL) {
        printf("Null pointer detected!\n");
        exit(-1);
    }


    size_t  LenA    = strlen(IDa) + 1; //  number of bytes in IDa (added one to account for '\0');
    size_t  LenB    = strlen(IDb) + 1; //  number of bytes in IDb (added one to account for '\0');
    size_t  LenMsg1 =  sizeof(LenA) + LenA + sizeof(LenB) + LenB + sizeof(Nonce_t); //  number of bytes in the completed MSG1 ;;
    size_t *lenPtr ; 
    uint8_t  *p ;

    // Allocate memory for msg1. MUST always check malloc() did not fail
    *msg1 = malloc(LenMsg1);

    if (*msg1 == NULL) {
        printf("myCrypto.c, msg1 failed to malloc!\n");
        exit(-1);
    }
    

    // Fill in Msg1:  Len( IDa )  ||  IDa   ||  Len( IDb )  ||  IDb   ||  Na
    p = *msg1;
    memset(p, 0, LenMsg1);
    
	// use the pointer p to traverse through msg1 and fill the successive parts of the msg 

    *((unsigned long *) p) = LenA;
    p += sizeof(size_t);
    
    strcpy(p, IDa);
    p += LenA;

    *((unsigned long *) p) = LenB;
    p += sizeof(size_t);

    strcpy(p, IDb);
    p += LenB;

    *((uint32_t *) p) = *Na;
    

    fprintf( log , "The following new MSG1 ( %lu bytes ) has been created by MSG1_new ():\n" , LenMsg1 ) ;
    // BIO_dumpt the completed MSG1 indented 4 spaces to the right
    BIO_dump_indent_fp(log, *msg1, LenMsg1, 4);

    fprintf( log , "\n" ) ;
    
    return LenMsg1 ;
}

//-----------------------------------------------------------------------------
// Receive Message #1 by the KDC from Amal via the pipe's file descriptor 'fd'
// Parse the incoming msg1 into the values IDa, IDb, and Na

void  MSG1_receive( FILE *log , int fd , char **IDa , char **IDb , Nonce_t Na )
{

    //  Check agains any NULL pointers in the arguments

    if (log == NULL || IDa == NULL || *IDa == NULL || IDb == NULL || *IDb == NULL) {
        printf("myCrypto.c, null pointer detected!\n");
        exit(-1);
    }

    size_t LenMsg1 = 0, LenA , lenB ;
	// Throughout this function, don't forget to update LenMsg1 as you receive its components
 
    // Read in the components of Msg1:  Len(IDa)  ||  IDa  ||  Len(IDb)  ||  IDb  ||  Na

    // 1) Read Len(ID_A)  from the pipe ... But on failure to read Len(IDa):

    if (read(fd, &LenA, sizeof(size_t)) < sizeof(size_t)) 
    {
        fprintf( log , "Unable to receive all %lu bytes of Len(IDA) "
                       "in MSG1_receive() ... EXITING\n" , LENSIZE );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes LenA in MSG1_receive()" );
    }

    LenMsg1 += sizeof(size_t);
    
    // 2) Allocate memory for ID_A ... But on failure to allocate memory:

    if ((*IDa = (char *) (malloc(LenA))) == NULL)
    {
        fprintf( log , "Out of Memory allocating %lu bytes for IDA in MSG1_receive() "
                       "... EXITING\n" , LenA );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDA in MSG1_receive()" );
    }

 	// On failure to read ID_A from the pipe
    if (read(fd, *IDa, LenA) < LenA)
    {
        fprintf( log , "Out of Memory allocating %lu bytes for IDA in MSG1_receive() "
                       "... EXITING\n" , LenA );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDA in MSG1_receive()" );
    }
    LenMsg1 += LenA;

    // 3) Read Len( ID_B )  from the pipe    But on failure to read Len( ID_B ):
    if (read(fd, &lenB, sizeof(size_t)) < sizeof(size_t))
    {
        fprintf( log , "Unable to receive all %lu bytes of Len(IDB) "
                       "in MSG1_receive() ... EXITING\n" , LENSIZE );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes of LenB in MSG1_receive()" );
    }
    LenMsg1 += sizeof(size_t);

    // 4) Allocate memory for ID_B    But on failure to allocate memory:
    if ((*IDb = (char *) malloc(lenB)) == NULL)
    {
        fprintf( log , "Out of Memory allocating %lu bytes for IDB in MSG1_receive() "
                       "... EXITING\n" , lenB );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDB in MSG1_receive()" );
    }

 	// Now, read IDb ... But on failure to read ID_B from the pipe
    if (read(fd, *IDb, lenB) < lenB)
    {
        fprintf( log , "Unable to receive all %lu bytes of IDB in MSG1_receive() "
                       "... EXITING\n" , lenB );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Unable to receive all bytes of IDB in MSG1_receive()" );
    }
    LenMsg1 += lenB;

    // 5) Read Na   But on failure to read Na from the pipe
    if (read(fd, Na, sizeof(Nonce_t)) < sizeof(Nonce_t))
    {
        fprintf( log , "Unable to receive all %lu bytes of Na "
                       "in MSG1_receive() ... EXITING\n" , NONCELEN );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes of Na in MSG1_receive()" );
    }
    LenMsg1 += sizeof(Nonce_t);
 
    fprintf( log , "MSG1 ( %lu bytes ) has been received"
                   " on FD %d by MSG1_receive():\n" ,  LenMsg1 , fd  ) ;   
    fflush( log ) ;

    return ;
}
