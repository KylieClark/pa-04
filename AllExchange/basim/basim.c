/*----------------------------------------------------------------------------
pa-04_PartTwo:  Intro to Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   basim.c     SKELETON

Written By: 
     1- Kylie Clark 
	 2- Cole Strubhar
Submitted on: 
     11/25/2024
----------------------------------------------------------------------------*/

#include <linux/random.h>
#include <time.h>
#include <stdlib.h>

#include "../myCrypto.h"

// Generate random nonces for Basim
void  getNonce4Basim( int which , Nonce_t  value )
{
	// Normally we generate random nonces using
	// RAND_bytes( (unsigned char *) value , NONCELEN  );
	// However, for grading purpose, we will use fixed values

	switch ( which ) 
	{
		case 1:		// the first and Only nonce
			value[0] = 0x66778899 ;
			break ;

		default:	// Invalid agrument. Must be either 1 or 2
			fprintf( stderr , "\n\nBasim trying to create an Invalid nonce\n exiting\n\n");
			exit(-1);
	}
}

//*************************************
// The Main Loop
//*************************************
int main ( int argc , char * argv[] )
{
    // Your code from pa-04_PartOne
    
    int       fd_A2B , fd_B2A   ;
    FILE     *log ;

    char *developerName = "Code by Kylie Clark and Cole Strubhar" ;

    fprintf( stdout , "Starting Basim's     %s\n" , developerName ) ;

    if( argc < 3 )
    {
        printf("\nMissing command-line file descriptors: %s <getFr. Amal> "
               "<sendTo Amal>\n\n", argv[0]) ;
        exit(-1) ;
    }

    fd_A2B    = atoi(argv[1]) ;  // Read from Amal   File Descriptor
    fd_B2A    = atoi(argv[2]) ;  // Send to   Amal   File Descriptor

    log = fopen("basim/logBasim.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "Basim's %s. Could not create log file\n" , developerName ) ;
        exit(-1) ;
    }

    BANNER( log ) ;
    fprintf( log , "Starting Basim\n"  ) ;
    BANNER( log ) ;

    fprintf( log , "\n<readFr. Amal> FD=%d , <sendTo Amal> FD=%d\n\n" , fd_A2B , fd_B2A );

    // Get Basim's master keys with the KDC
    myKey_t   Kb ;    // Basim's master key with the KDC    

    // Use  getKeyFromFile( "basim/basimKey.bin" , .... ) )
	// On failure, print "\nCould not get Basim's Masker key & IV.\n" to both  stderr and the Log file
	// and exit(-1)
	// On success, print "Basim has this Master Ka { key , IV }\n" to the Log file
	// BIO_dump the Key IV indented 4 spaces to the righ

    int success = getKeyFromFile("basim/basimKey.bin", &Kb);

    if (success < 0) {
        fprintf(stderr, "\nCould not get Basim's Master key & IV.\n");
        fprintf(log, "\nCould not get Basim's Master key & IV.\n");
        exit(-1);
    }

    fprintf(log, "Basim has this Master Kb { key , IV }\n");
    BIO_dump_indent_fp(log, Kb.key, sizeof(Kb.key), 4);

    fprintf( log , "\n" );
	// BIO_dump the IV indented 4 spaces to the righ

    BIO_dump_indent_fp(log, Kb.iv, sizeof(Kb.iv), 4);

    // Get Basim's pre-created Nonces: Nb
	Nonce_t   Nb;  

	// Use getNonce4Basim () to get Basim's 1st and only nonce into Nb
    getNonce4Basim(1, Nb);

    fprintf( log , "\nBasim will use this Nonce:  Nb\n"  ) ;
	// BIO_dump Nb indented 4 spaces to the righ
    BIO_dump_indent_fp(log, Nb, sizeof(Nb), 4);

    fprintf( log , "\n" );

    fflush( log ) ;
    
    //*************************************
    // Receive  & Process   Message 3
    //*************************************
    // PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG3 Receive\n");
    BANNER( log ) ;

    char *IDa ;
    Nonce_t  Na2 ;
    myKey_t Ks;
    
    // Get MSG3 from Amal
    MSG3_receive( log , fd_A2B , &Kb , &Ks , &IDa , &Na2) ;

    fprintf( log , "Basim received Message 3 from Amal with the following content:\n") ;
    fprintf( log , "    Ks { Key , IV } (%lu Bytes ) is:\n" , KEYSIZE) ;
    BIO_dump_indent_fp(log, &Ks, KEYSIZE, 4);
    fprintf( log , "\n    IDa = '%s'\n", IDa);
    fprintf( log , "    Na2 ( %lu Bytes ) is:\n", NONCELEN);
    BIO_dump_indent_fp(log, Na2, sizeof(Na2), 4);
    fprintf ( log, "\n");

    fflush( log ) ;

    //*************************************
    // Construct & Send    Message 4
    //*************************************
    // PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG4 New\n");
    BANNER( log ) ;
    uint8_t *msg4;
    Nonce_t adj_nonce;
    fNonce(adj_nonce, Na2);

    fprintf(log, "Basim is sending this f( Na2 ) in MSG4:\n");
    BIO_dump_indent_fp(log, &adj_nonce, sizeof(adj_nonce), 4);

    fprintf(log, "\nBasim is sending this nonce Nb in MSG4:\n");
    BIO_dump_indent_fp(log, &Nb, sizeof(Nb), 4);
    fprintf(log, "\n");

    size_t msg4_sz = MSG4_new(log, &msg4, &Ks, &adj_nonce, &Nb);
    ssize_t write_test = 0;

    write_test = write(fd_B2A, &msg4_sz, sizeof(msg4_sz));

    if (write_test < sizeof(msg4_sz)) {
        fprintf(log, "Msg4: Failed to send MSG4 over B to A pipe.\n");
        fclose(log);
        exit(-1);
    }

    write_test = write(fd_B2A, msg4, msg4_sz);

    if (write_test < msg4_sz) {
        fprintf(log, "Msg4: Failed to send MSG4 over B to A pipe.\n");
        fclose(log);
        exit(-1);
    }

    //*************************************
    // Receive   & Process Message 5
    //*************************************
    // PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG5 Receive\n");
    BANNER( log ) ;

    Nonce_t expected;
    fNonce(expected, Nb);
    fprintf(log, "Basim is expecting back this f( Nb ) in MSG5:\n");
    BIO_dump_indent_fp(log, expected, sizeof(*expected), 4);

    MSG5_receive(log, fd_A2B, &Ks, &Nb);


    if (*Nb == *expected)
        fprintf(log, "\nBasim received Message 5 from Amal with this f( Nb ): >>>> VALID\n");
    else
        fprintf(log, "\nBasim received Message 5 from Amal with this f( Nb ): >>>> INVALID\n");

    BIO_dump_indent_fp(log, &Nb, sizeof(Nb), 4);

    //*************************************   
    // Final Clean-Up
    //*************************************
end_:
    fprintf( log , "\n\nBasim has terminated normally. Goodbye\n") ;
    fclose( log ) ;  

    return 0 ;
}
